@echo off
rem ==========================================================================
rem  Compilation de MalryxFlt.sys
rem  Prérequis : Visual Studio 2022 (charge « Développement C++ ») + Windows Driver Kit (WDK)
rem              https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
rem  À lancer depuis « x64 Native Tools Command Prompt for VS 2022 ».
rem ==========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

for /f "tokens=2,*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Kits\Installed Roots" /v KitsRoot10 2^>nul ^| find "KitsRoot10"') do set "KITS=%%b"
if not defined KITS (echo [ERREUR] Windows Kits introuvable : installe le WDK. & exit /b 1)

set "VER="
for /f "delims=" %%v in ('dir /b /ad /o-n "%KITS%Include\10.*"') do (
  if exist "%KITS%Include\%%v\km\fltKernel.h" if not defined VER set "VER=%%v"
)
if not defined VER (echo [ERREUR] En-têtes du WDK ^(km\fltKernel.h^) introuvables. & exit /b 1)
echo WDK %VER%

set "INC=/I"%KITS%Include\%VER%\km" /I"%KITS%Include\%VER%\shared" /I"%KITS%Include\%VER%\km\crt""
set "LIB=%KITS%Lib\%VER%\km\x64"
if not exist x64 mkdir x64

cl /nologo /c /kernel /W4 /WX /O2 /Gz /GS- /Gy /Zi /Zc:wchar_t /std:c17 ^
   /D_AMD64_ /DAMD64 /D_WIN64 /DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DPOOL_NX_OPTIN=1 ^
   %INC% /Fox64\MalryxFlt.obj /Fdx64\MalryxFlt.pdb MalryxFlt.c || exit /b 1

link /nologo /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry /INTEGRITYCHECK /NODEFAULTLIB /MACHINE:X64 ^
   /OPT:REF /OPT:ICF /DEBUG /RELEASE ^
   /OUT:x64\MalryxFlt.sys x64\MalryxFlt.obj "%LIB%\fltMgr.lib" "%LIB%\ntoskrnl.lib" || exit /b 1

copy /y MalryxFlt.inf x64\ >nul
echo.
echo [OK] x64\MalryxFlt.sys compile. Installation (mode test) : install-driver.ps1
