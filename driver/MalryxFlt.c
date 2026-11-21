/*
 * MalryxFlt.sys — pilote noyau de Malryx (minifiltre Filter Manager)
 *
 * Rôle : bloquer un programme malveillant AVANT qu'il ne s'exécute.
 *
 *  1. PsSetCreateProcessNotifyRoutineEx : Windows appelle ProcessNotify() à chaque création de
 *     processus, avant l'exécution de sa première instruction.
 *  2. Le pilote envoie le chemin de l'exécutable et la ligne de commande à Malryx (espace
 *     utilisateur) par un port de communication du Filter Manager (\MalryxPort).
 *  3. Malryx analyse (signatures, YARA, ClamAV, heuristiques, règles anti-exploit) et répond.
 *  4. Si Malryx répond « bloquer », la création est refusée : CreationStatus = STATUS_ACCESS_DENIED.
 *
 * Sécurité de conception :
 *  - « fail-open » : si Malryx ne répond pas en 3 s, ou n'est pas connecté, le processus est autorisé
 *    (le système ne peut jamais rester bloqué à cause de Malryx) ;
 *  - les processus créés par Malryx lui-même ne sont pas soumis (évite les interblocages) ;
 *  - le port n'accepte qu'un client, et seulement SYSTEM / Administrateurs (descripteur par défaut).
 *
 * Compilation : voir build-driver.cmd (WDK requis). Lien obligatoire avec /INTEGRITYCHECK.
 */
#include <fltKernel.h>

#define MALRYX_PORT_NAME  L"\\MalryxPort"
#define MALRYX_TAG        'xrlM'
#define PATH_CHARS        520
#define CMD_CHARS         1024
#define REPLY_TIMEOUT_100NS (-30000000LL)   /* 3 secondes */

typedef struct _MALRYX_REQUEST {
    ULONG ProcessId;
    ULONG ParentId;
    ULONG PathLength;               /* en caractères */
    WCHAR Path[PATH_CHARS];
    ULONG CmdLength;                /* en caractères */
    WCHAR Cmd[CMD_CHARS];
} MALRYX_REQUEST, *PMALRYX_REQUEST;

typedef struct _MALRYX_REPLY {
    ULONG Block;
} MALRYX_REPLY, *PMALRYX_REPLY;

static PFLT_FILTER gFilter = NULL;
static PFLT_PORT   gServerPort = NULL;
static PFLT_PORT   gClientPort = NULL;
static HANDLE      gClientPid = NULL;
static BOOLEAN     gNotifyRegistered = FALSE;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS MalryxUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS MalryxConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                       _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                       _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionCookie);
VOID MalryxDisconnect(_In_opt_ PVOID ConnectionCookie);
NTSTATUS MalryxInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                             _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                      /* Flags */
    NULL,                   /* Contextes */
    gCallbacks,             /* Aucune opération fichier interceptée */
    MalryxUnload,
    MalryxInstanceSetup,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* ------------------------------------------------------------------------- */
static VOID CopyUnicode(_Out_writes_(cap) PWCHAR dst, _In_ ULONG cap, _Out_ PULONG outLen, _In_opt_ PCUNICODE_STRING src)
{
    ULONG n = 0;
    if (src != NULL && src->Buffer != NULL) {
        n = src->Length / sizeof(WCHAR);
        if (n > cap - 1) n = cap - 1;
        RtlCopyMemory(dst, src->Buffer, n * sizeof(WCHAR));
    }
    dst[n] = L'\0';
    *outLen = n;
}

static VOID ProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    PMALRYX_REQUEST req;
    MALRYX_REPLY reply;
    ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout;
    NTSTATUS status;
    PFLT_PORT port;

    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL)                          return;  /* fin de processus */
    port = gClientPort;
    if (port == NULL || gFilter == NULL)             return;  /* Malryx non connecté : autorisé */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)         return;
    if (CreateInfo->CreatingThreadId.UniqueProcess == gClientPid) return;  /* créé par Malryx */
    if (CreateInfo->ImageFileName == NULL)           return;

    req = (PMALRYX_REQUEST)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(MALRYX_REQUEST), MALRYX_TAG);
    if (req == NULL)                                 return;

    req->ProcessId = HandleToULong(ProcessId);
    req->ParentId  = HandleToULong(CreateInfo->ParentProcessId);
    CopyUnicode(req->Path, PATH_CHARS, &req->PathLength, CreateInfo->ImageFileName);
    CopyUnicode(req->Cmd, CMD_CHARS, &req->CmdLength, CreateInfo->CommandLine);

    reply.Block = 0;
    timeout.QuadPart = REPLY_TIMEOUT_100NS;
    status = FltSendMessage(gFilter, &gClientPort, req, sizeof(MALRYX_REQUEST), &reply, &replyLen, &timeout);

    if (status == STATUS_SUCCESS && replyLen >= sizeof(MALRYX_REPLY) && reply.Block != 0) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
    }
    ExFreePoolWithTag(req, MALRYX_TAG);
}

/* ------------------------------------------------------------------------- */
NTSTATUS MalryxConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
                       _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
                       _In_ ULONG SizeOfContext, _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    *ConnectionCookie = NULL;
    gClientPid = PsGetCurrentProcessId();
    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID MalryxDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilter, &gClientPort);   /* met gClientPort à NULL */
    gClientPid = NULL;
}

NTSTATUS MalryxInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                             _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_FLT_DO_NOT_ATTACH;   /* aucune surveillance de volume nécessaire */
}

NTSTATUS MalryxUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gNotifyRegistered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotify, TRUE);
        gNotifyRegistered = FALSE;
    }
    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }
    if (gFilter != NULL) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status)) return status;

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);   /* SYSTEM + Administrateurs */
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&portName, MALRYX_PORT_NAME);
        InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(gFilter, &gServerPort, &oa, NULL,
                                            MalryxConnect, MalryxDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(status)) {
        status = PsSetCreateProcessNotifyRoutineEx(ProcessNotify, FALSE);
        if (NT_SUCCESS(status)) gNotifyRegistered = TRUE;
    }
    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(gFilter);
    }
    if (!NT_SUCCESS(status)) {
        MalryxUnload(0);
    }
    return status;
}
