# Pilote noyau MalryxFlt : blocage AVANT l'exécution

## Pourquoi un pilote ?
Sans pilote, Malryx détecte un nouveau programme quelques millisecondes après son démarrage. Il le **suspend** aussitôt, l'analyse, puis le tue ou le relance. C'est très rapide, mais le programme a déjà existé un court instant.

Avec le pilote, c'est Windows lui-même qui demande l'avis de Malryx **avant** de créer le processus. S'il est malveillant, la création est refusée (`STATUS_ACCESS_DENIED`) et pas une seule instruction du malware ne s'exécute. C'est l'architecture des antivirus professionnels.

```
 Explorateur / malware ──CreateProcess──▶ Noyau Windows
                                             │ PsSetCreateProcessNotifyRoutineEx
                                             ▼
                                       MalryxFlt.sys ──FltSendMessage──▶ Malryx.exe (administrateur)
                                             ▲                            signatures · YARA · ClamAV
                                             │◀──────── bloquer / autoriser ── heuristiques · anti-exploit
                                             ▼
                          CreationStatus = STATUS_ACCESS_DENIED  (ou création normale)
```

**Sécurité de conception :** fonctionnement « fail-open » (si Malryx ne répond pas en 3 s, le programme est autorisé : le PC ne peut jamais rester bloqué), aucun interblocage avec les processus de Malryx, et port de communication réservé à SYSTEM et aux Administrateurs.

## 1. Compiler
Prérequis : Visual Studio 2022 (« Développement Desktop en C++ ») + [WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk).
```
x64 Native Tools Command Prompt for VS 2022
> cd driver
> build-driver.cmd           → driver\x64\MalryxFlt.sys
```
Le workflow GitHub essaie aussi de le compiler (étape optionnelle). Ensuite, `build.ps1` l'embarque automatiquement dans `Malryx.exe`.

## 2. Installer (mode test : VM ou PC de démonstration)
Windows n'accepte que les pilotes signés par Microsoft, sauf en **mode test** :
1. Désactive **Secure Boot** (BIOS/UEFI, ou réglages de la VM).
2. PowerShell **administrateur** : `.\install-driver.ps1`. Le script active le mode test ; **redémarre**.
3. Relance `.\install-driver.ps1`. Il crée un certificat de test, signe le pilote, l'installe et le charge.
4. Lance Malryx **en administrateur**. Protection → « Mode : pilote noyau (avant exécution) ».

L'installation se fait aussi depuis Malryx : Réglages → Avancé → « Installer le pilote (mode test) ».
Le filigrane « Mode test » s'affiche en bas à droite de l'écran : c'est normal.

Désinstallation : `.\install-driver.ps1 -Uninstall`, puis `.\install-driver.ps1 -DisableTestMode`.

## 3. Tester
Dans la VM, pilote chargé et Malryx lancé en administrateur :
- copie un exécutable dont tu ajoutes le SHA-256 à Réglages → « Importer des hashes », puis double-clique : Windows affiche « Accès refusé » ;
- `cmd /c "vssadmin delete shadows /all /quiet"` : la commande est refusée avant de s'exécuter.

## Distribution publique (hors projet étudiant)
Un pilote chargé sur n'importe quel PC sans mode test doit être signé par **Microsoft** : certificat **EV** au nom d'une **entreprise**, puis soumission au Partner Center (signature d'attestation). Il faut aussi demander une **altitude** officielle (fsfcomm@microsoft.com). Ce n'est pas accessible à un particulier : le mode test est la voie normale pour une démonstration ou une soutenance.

> ⚠ Code noyau : une erreur provoque un écran bleu. Teste toujours d'abord dans une **VM** avec un instantané (snapshot).
