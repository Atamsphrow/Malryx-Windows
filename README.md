# Malryx – Anti-Malware pour Windows

Malryx est une suite de sécurité et d'optimisation de bureau **100 % hors ligne** qui s'inspire de Malwarebytes et d'AVG : analyse par étapes, protection en temps réel à plusieurs couches, analyse des téléphones Android et des clés USB, quarantaine, bouton « Analyser mon PC », nettoyage, performances et confidentialité. Tout est gratuit.
Tout tient dans **un seul fichier `Malryx.exe`** : aucune installation, aucun logiciel à télécharger à part.

## Fonctionnalités

| Module | Ce qu'il fait |
|---|---|
| **Tableau de bord** | État global (protégé / non protégé / menaces à traiter), cartes Analyse, Protection et Détections, moteurs, score de sécurité, activité récente |
| **Analyse des menaces** | 6 étapes : mise à jour → mémoire (processus) → démarrage (registre Run, dossiers Startup, tâches planifiées) → registre (Winlogon, IFEO, AppInit_DLLs) → fichiers → heuristique |
| **Analyse complète / personnalisée** | Tous les disques, ou des dossiers, fichiers et clés USB choisis. Glisser-déposer et clic droit « Analyser avec Malryx » dans l'Explorateur |
| **Protection à l'exécution** | Chaque programme lancé est vérifié avant de pouvoir agir. Avec le pilote noyau, Windows refuse même sa création (voir `driver/`) |
| **Anti-exploit (comportement)** | Bloque les attaques sans fichier : Office ou PDF qui lance PowerShell, commandes encodées, mshta/regsvr32/certutil détournés, suppression des sauvegardes, désactivation de Defender |
| **Protection contre les malwares** | Tout fichier créé, téléchargé ou renommé est analysé instantanément. Le processus est arrêté et le fichier mis en quarantaine |
| **Anti-ransomware** | Fichiers-appâts cachés et détection des chiffrements en rafale (entropie, extensions). Le programme fautif est **suspendu** et l'utilisateur choisit |
| **Protection Web** | Bloque des milliers de domaines malveillants (URLhaus) via le fichier hosts, avec une liste personnalisable |
| **Protection du démarrage** | Tout nouveau programme ajouté au démarrage est analysé et, s'il est malveillant, retiré |
| **USB** | Surveillance et analyse automatique des clés dès leur branchement |
| **Android (ADB)** | Infos de sécurité (root, correctif, sources inconnues), analyse des applis (permissions dangereuses, accessibilité, origine hors store, code `.dex` avec YARA), analyse du stockage, désinstallation |
| **Analyser mon PC** | Une seule analyse (menaces, sécurité de Windows, fichiers inutiles, traces, télémétrie, logiciels obsolètes, démarrage, applis gourmandes, santé). Elle affiche « X problèmes » par catégorie avec « Tout corriger ». **Seuls les vrais problèmes sont comptés**, sans gonflage commercial |
| **Nettoyage** | Fichiers inutiles (standard et approfondi : Windows.old, journaux, cache de distribution, vidages mémoire, composants obsolètes via DISM), **doublons** (comparaison du contenu, l'original le plus ancien est gardé), **gros fichiers oubliés**, **restes de désinstallation** (sauvegardés avant suppression). Les fichiers vont à la Corbeille |
| **Performances** | **Démarrage** (durée réelle, impact estimé de chaque programme, activer/désactiver), **mode veille** (pause des applications inactives gourmandes, réveil automatique au clic), **mise à jour des logiciels** via winget (priorité aux logiciels vulnérables), **santé** (SMART, température, usure, espace, mémoire vive, batterie, alertes) |
| **Confidentialité** | **Traces de navigation** (Chrome, Edge, Brave, Opera, Firefox ; favoris et mots de passe jamais touchés), **télémétrie et publicités Windows** (11 réglages réversibles), **webcam et micro** (applications ayant accédé, alerte en direct), **destructeur de fichiers** (écrasement aléatoire, avertissement SSD) |
| **Historique** | Quarantaine chiffrée AES-256-GCM (restaurer / supprimer), historique des détections exportable en CSV, rapports d'analyse, liste autorisée |
| **Outils** | Audit de sécurité (Defender, pare-feu, UAC, SMBv1, RDP, mises à jour, BitLocker, hosts…), nettoyage (temporaires, caches des navigateurs, corbeille), gestionnaire de démarrage, gestionnaire de processus, journal |
| **Réglages** | Démarrage avec Windows, zone de notification, analyses planifiées, ClamAV, sensibilité, VirusTotal, import de signatures, règles YARA personnelles |

**Moteurs de détection :**
- **Base de hashes Malryx** (SHA-256 et MD5), embarquée dans l'exe et mise à jour chaque jour : export MalwareBazaar, plus tes listes. Elle fonctionne hors ligne : environ 32 Mo et 4 µs par recherche pour un million de hashes.
- **Règles YARA :** celles de Malryx et le jeu **YARA Forge « core »** (environ 5 000 règles sélectionnées pour leur faible taux de faux positifs). Le `score` de chaque règle est respecté : 75 ou plus = malveillant, en dessous = suspect.
- **ClamAV** (clamd embarqué, plusieurs millions de signatures), **heuristiques** maison et **VirusTotal** en option (seul le hash est envoyé).

## Hors ligne par défaut, en ligne uniquement en Wi-Fi
Tout est **embarqué** : moteur et bases ClamAV, base de hashes, YARA Forge, ADB, liste Web. Au premier lancement, rien n'est téléchargé.

| Mode (Réglages → Connexion et signatures) | Comportement |
|---|---|
| **Automatique : Wi-Fi** (par défaut) | Hors ligne tant qu'aucun Wi-Fi n'est connecté. Dès qu'un Wi-Fi avec accès Internet est détecté (API WLAN de Windows + test réel), Malryx passe en ligne : mise à jour des signatures si elles ont plus de 24 h, VirusTotal, winget, liste Web. Wi-Fi perdu → retour hors ligne immédiat |
| En ligne sur toute connexion | Pareil, Ethernet compris |
| Jamais : 100 % hors ligne | Aucune connexion réseau, jamais. Mises à jour par pack USB uniquement |

- **Hors ligne, Malryx n'ouvre aucune connexion :** un verrou unique (`netfetch.OFFLINE`) bloque toutes les fonctions réseau, et un test de l'application complète vérifie qu'aucune connexion sortante n'est tentée.
- **Connexion limitée** (partage de connexion du téléphone, forfait mobile, réglage Windows « Connexion limitée ») : seules les petites mises à jour incrémentales sont téléchargées, jamais les bases complètes.

### Mise à jour sans Internet : packs de signatures signés
1. Le workflow « Signatures Malryx » publie chaque jour `malryx-signatures-AAAAMMJJ.zip`, ainsi que `malryx-signatures-latest.zip`, dans la release `signatures`.
2. Copie ce fichier à la racine d'une clé USB, ou dans un dossier `Malryx` sur la clé.
3. Branche la clé : Malryx vérifie le pack et propose de l'installer. Sinon : Réglages → « Importer un pack ».
4. Pour transmettre les signatures à un autre PC sans Internet : Réglages → « Exporter un pack pour un autre PC ».

**Vérifications d'un pack :** la signature **Ed25519** du manifeste, le SHA-256 de chaque fichier, puis le contrôle que le pack est plus récent que l'installation. Les bases ClamAV sont en plus vérifiées par clamd (signature Cisco-Talos). Un pack modifié, contrefait ou dont la signature a été retirée est **refusé**.

**À faire une seule fois, la clé de signature :**
```bash
pip install cryptography
python tools/gen_pack_key.py      # écrit malryx/pack_pubkey.txt (à committer) et affiche la clé privée
```
Mets la clé privée dans le secret GitHub `MALRYX_PACK_KEY`. Dès que `pack_pubkey.txt` existe, Malryx exige des packs signés.

**Mises à jour en ligne (Wi-Fi), qui ne dépendent pas d'un seul serveur :**
1. serveurs officiels ClamAV (freshclam, sans requête DNS TXT) ;
2. si ça échoue (DNS qui ne résout pas `database.clamav.net`, limite 403/429 du CDN) : **miroir Malryx sur GitHub Releases**, mis à jour chaque jour par le workflow `signatures.yml` ;
3. si le DNS local ne résout pas non plus `github.com` : bascule automatique en **DNS-over-HTTPS** (1.1.1.1, 8.8.8.8, 9.9.9.9 joints par adresse IP). TLS reste vérifié normalement.

Chaque fichier du miroir est vérifié par SHA-256. Les bases ClamAV portent en plus la signature numérique de Cisco-Talos, que clamd vérifie au chargement.

## Obtenir Malryx.exe

### Option A : GitHub Actions (aucune installation sur ton PC)
1. Ce code vit sur la branche **`opus-qt-3.0.0`** du dépôt **public** `Atamsphrow/Malryx-Windows` (branche d'essai de la réécriture Qt, séparée du `main` Flutter). Le dépôt doit être public pour que l'application télécharge les signatures sans authentification :
   ```bash
   git clone --branch opus-qt-3.0.0 https://github.com/Atamsphrow/Malryx-Windows.git
   ```
   Ne jamais pousser ce code vers `Atamsphrow/Malryx` (dépôt Linux, autre projet).
2. **Clé de signature des packs** : `python tools/gen_pack_key.py`, committe `malryx/pack_pubkey.txt`, puis ajoute le secret `MALRYX_PACK_KEY` (voir plus bas).
3. **Recommandé : clé MalwareBazaar.** Crée un compte gratuit sur [auth.abuse.ch](https://auth.abuse.ch), génère une *Auth-Key*, puis ajoute-la dans GitHub → Settings → Secrets → Actions sous le nom `MB_AUTH_KEY`. Sans elle, la base de hashes ne contient que tes propres listes, et la détection repose alors sur ClamAV et YARA.
4. Onglet **Actions** → « Signatures Malryx » → **Run workflow**. Ce workflow crée la release `signatures` (bases ClamAV, hashes, YARA Forge, URLhaus), puis tourne tout seul chaque jour.
5. Onglet **Actions** → « Compiler Malryx » → **Run workflow**. L'artefact `Malryx` contient :
   - `Malryx-Setup.exe` (**recommandé**, environ 300 Mo) : installateur qui démarre rapidement, déclenche moins de faux positifs et se désinstalle proprement ;
   - `Malryx.exe` (environ 330 Mo) : portable, un seul fichier. Il se décompresse entièrement à chaque lancement : compte quelques secondes de démarrage. Pratique sur une clé USB ;
   - `SHA256SUMS.txt` : les empreintes des deux fichiers.
6. Pour publier une version : `git tag v$(cat VERSION) && git push --tags`. Le tag doit correspondre au fichier `VERSION`, sinon le build échoue volontairement.

Les bases ClamAV (environ 230 Mo) sont **embarquées** : le build échoue s'il ne peut pas les inclure, pour qu'aucune version « hors ligne » incomplète ne soit jamais produite. **Lance donc le workflow « Signatures Malryx » avant le premier build.**

### Option B : sur ton PC Windows
```powershell
# Python 3.12 (python.org, « Add to PATH » coché). Inno Setup est installé automatiquement si besoin.
powershell -ExecutionPolicy Bypass -File build.ps1    # dist\Malryx-Setup.exe + dist\Malryx.exe, tout embarqué
```

### Version
Le numéro de version est défini à **un seul endroit**, le fichier `VERSION`. L'application, les propriétés de l'exe, l'installateur et la vérification du tag le lisent tous.

### Lancer depuis les sources (développement)
```bash
pip install -r requirements.txt
python main.py
```

## Signature et avertissements SmartScreen / Defender
Un exe non signé déclenche l'avertissement SmartScreen (« Windows a protégé votre ordinateur »). Les antivirus se méfient aussi des exe PyInstaller, que beaucoup de malwares utilisent. Malryx réduit le problème à chaque étape :

| Mesure | Effet | Coût |
|---|---|---|
| Bootloader PyInstaller recompilé depuis les sources (automatique dans `build.ps1` si Visual Studio C++ est présent) | Supprime la principale cause de faux positifs | Gratuit |
| Pas de compression UPX, informations de version complètes | Moins de détections heuristiques | Gratuit |
| `sign.ps1 -SelfSigned -TrustOnThisPC` | Exe signé et approuvé **sur ton PC de démo et ceux de l'école** (importe `Malryx-certificat.cer`) | Gratuit |
| [SignPath Foundation](https://signpath.org) : certificat gratuit pour les projets **open source** (dépôt public + licence OSI) | Signature reconnue partout, intégrée au workflow GitHub (section prête dans `build.yml`) | Gratuit, sur dossier |
| Certificat Certum « Open Source Code Signing » (particuliers, dans le monde entier) | Signature à ton nom, réputation SmartScreen | Environ 69 € (set avec carte) |
| [Signaler un faux positif à Microsoft](https://www.microsoft.com/wdsi/filesubmission) (« Software developer ») | Defender retire la détection en quelques jours | Gratuit |

Depuis 2024, **même un certificat EV ne supprime plus immédiatement l'avertissement SmartScreen**. La réputation se construit au fil des téléchargements de chaque version. Signer reste indispensable : l'éditeur affiché devient « Malryx » au lieu de « Éditeur inconnu », et la réputation s'accumule.
Azure Artifact Signing (environ 10 $/mois) n'accepte pour l'instant les particuliers qu'aux États-Unis et au Canada.

**Avec un certificat :** ajoute dans GitHub (Settings → Secrets → Actions) `SIGN_PFX_BASE64` (contenu du .pfx en base64 : `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`) et `SIGN_PFX_PASSWORD`. Chaque build est alors signé automatiquement.

## Premier lancement
- Au premier démarrage, Malryx copie ses moteurs dans `%LOCALAPPDATA%\Malryx`. Le chargement de ClamAV prend ensuite 30 à 60 s.
- **Clic droit → Exécuter en tant qu'administrateur** (ou Réglages → Relancer en administrateur) débloque la protection Web, la réparation du registre et l'analyse des dossiers système.
- Réglages → « Lancer Malryx au démarrage de Windows » : la protection démarre alors avec la session, dans la zone de notification.
- **Premier lancement :** les bases embarquées sont copiées dans `%LOCALAPPDATA%\\Malryx` (environ 230 Mo, quelques secondes). Aucune connexion n'est nécessaire.
- **SmartScreen et Defender** peuvent avertir sur un exe non signé, surtout s'il suspend des processus et modifie le fichier hosts. L'installateur est en général moins signalé que l'exe portable. Voir la section « Signature ».

## Tester sans danger
- **EICAR** (fichier de test standard, inoffensif) : enregistre la ligne ci-dessous sous `test.com` dans Téléchargements. Malryx doit le bloquer immédiatement.
  `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
  Si Defender le bloque avant Malryx, ajoute temporairement une exclusion Defender sur un dossier de test.
- **Double extension** : renomme n'importe quel `.exe` en `facture.pdf.exe` → SUSPECT.
- **Anti-ransomware** : dans une **VM**, lance un script qui chiffre plus de 30 fichiers de Documents en quelques secondes.
- **Android** : active le débogage USB, branche le téléphone, puis va dans Appareils → Analyser le téléphone.
- Les vrais échantillons de malwares se testent uniquement dans une VM isolée, sans réseau.

## Architecture
```
main.py                      point d'entrée (--minimized, --scan <chemin>), instance unique
malryx/
  engine.py                  moteur multi-couches (hash, YARA, ClamAV, VirusTotal, heuristiques)
  clamav.py                  démon clamd local (TCP 127.0.0.1, protocole INSTREAM) + freshclam
  realtime.py                temps réel : watchdog, USB, Android, protection du démarrage
  ransomware.py              fichiers-appâts, détection de rafales, suspension du processus
  execguard.py               protection à l'exécution + anti-exploit (règles de ligne de commande)
  kernel.py                  client du pilote noyau (fltlib : FilterGetMessage / FilterReplyMessage)
  webprotect.py              blocage de domaines via le fichier hosts (URLhaus)
  android.py                 ADB : appareils, applis, permissions, stockage
  winsys.py                  Windows : registre, démarrage, tâches, processus, USB, Explorateur
  audit.py / cleaner.py      audit de sécurité / nettoyage (standard + approfondi)
  pcscan.py                  « Analyser mon PC » : agrégation des problèmes + corrections automatiques
  diskspace.py               doublons, gros fichiers, restes de désinstallation, Corbeille
  performance.py             démarrage, mode veille, mises à jour winget, santé (SMART)
  privacy.py                 traces de navigation, télémétrie, webcam/micro, destructeur
  quarantine.py / history.py quarantaine AES-256-GCM (clé protégée par DPAPI), historique, rapports
  hashdb.py                  base de hashes compacte (mmap + dichotomie)
  netfetch.py / sigupdate.py téléchargements avec repli DNS-over-HTTPS (verrou hors ligne) / mise à jour en ligne
  network.py                 politique réseau : hors ligne par défaut, en ligne seulement en Wi-Fi (API WLAN)
  packs.py                   packs de signatures hors ligne : import (clé USB), export, vérification Ed25519
  settings.py / paths.py     réglages JSON, ressources embarquées, dossier %LOCALAPPDATA%\Malryx
  gui/                       interface PySide6 (Qt) : 11 pages, zone de notification, dialogues
rules/base.yar               règles YARA intégrées
hashes.txt                   signatures SHA-256 intégrées
driver/                      pilote noyau MalryxFlt (C, minifiltre) + compilation + installation en mode test
build.ps1 / Malryx.spec     construction : exe portable + installateur (installer/Malryx.iss)
tools/build_signatures.py    paquet de signatures + pack hors ligne signé (exécuté chaque jour par signatures.yml)
tools/gen_pack_key.py        génère la paire de clés Ed25519 des packs
VERSION                      numéro de version unique
sign.ps1                     signature (vrai certificat ou auto-signé)
.github/workflows/build.yml  compilation automatique sur GitHub
```

## Sécurité des fonctions d'optimisation
- Fichiers temporaires : ceux de moins de 24 h ne sont jamais supprimés (installations ou téléchargements en cours).
- Doublons, gros fichiers, restes : envoyés à la **Corbeille**, donc récupérables. Un exemplaire de chaque doublon est toujours gardé.
- Restes de désinstallation : uniquement les dossiers inutilisés depuis plus de 90 jours, sans programme en cours d'exécution ; les clés de registre sont exportées en `.reg` avant suppression.
- Télémétrie : la valeur d'origine de chaque réglage est sauvegardée, et « Tout restaurer » revient à l'état initial.
- Mode veille : à la fermeture de Malryx, toutes les applications endormies sont réveillées.
- Destructeur : la seule action irréversible ; une double confirmation est demandée.

## Quarantaine
Les fichiers sont chiffrés en **AES-256-GCM**, par blocs de 4 Mo authentifiés : un fichier modifié, tronqué ou dont les blocs sont réordonnés est refusé à la restauration. La clé de 256 bits est propre à chaque installation et protégée par **Windows DPAPI** : elle n'est utilisable que dans la session de l'utilisateur. Les éléments mis en quarantaine par les versions 2.2 et antérieures (format XOR) restent restaurables.

## Limites
- **Pilote noyau :** il ne se charge qu'en **mode test** (Secure Boot désactivé, filigrane à l'écran). Windows exige pour tout pilote une signature Microsoft, obtenue avec un certificat **EV d'entreprise** et la signature d'attestation du Partner Center. Aucun contournement n'est acceptable : charger un pilote non signé sur un PC protégé est exactement ce que font les rootkits.
- **Blocage avant exécution :** complet avec le pilote noyau (mode test). Sans pilote, un programme existe quelques millisecondes avant d'être suspendu, mais un fichier déjà repéré au téléchargement est bloqué dès son lancement (verdict en cache).
- Le pilote ne peut pas être distribué au grand public sans signature Microsoft (certificat EV d'entreprise) : voir `driver/README.md`.
- L'inspection du trafic HTTPS n'est pas couverte (la protection Web bloque par nom de domaine).
- iPhone : impossible, Apple n'autorise pas l'analyse externe des applications.
- Garde Windows Defender actif : Malryx le complète, il ne le remplace pas.

## Composants tiers
- **ClamAV** © Cisco Systems (GPL v2). Sources : https://github.com/Cisco-Talos/clamav
- **Android Platform-Tools / ADB** © Google (Apache 2.0)
- **URLhaus** © abuse.ch (CC0)
- **YARA** © VirusTotal (BSD-3), **Qt / PySide6** (LGPL v3), **watchdog** (Apache 2.0), **psutil** (BSD-3)

Si tu distribues l'exe avec ClamAV embarqué, mentionne la licence GPL de ClamAV et le lien vers ses sources (c'est fait ci-dessus).
