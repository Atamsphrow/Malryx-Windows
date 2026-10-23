# W0 — Rapport de faisabilité (fait par Elri, 2026-10-23)

Demande d'Atamsphrow : « Fais le toi même » — pas de checklist à cocher
à la main. Voici exactement ce qui a été fait, ce qui est prouvé, et la
seule chose qu'Elri ne peut matériellement pas faire.

## Pourquoi pas directement sur ton PC

Vérifié le 2026-10-23 :
- appareils appairés à Muse : **uniquement ton téléphone Android** —
  ton PC Windows n'y figure pas, je n'ai aucune commande dessus ;
- **Tailscale** : démon arrêté sur ma VM, et la dernière clé d'auth
  (octobre) avait été rejetée (HTTP 400, état « Logged out ») — l'accès
  SSH à ta machine Windows décrit dans ton profil Termux passe par
  *ton* téléphone, pas par moi ;
- ma VM est **Linux**, sans Wine : elle ne peut ni compiler du Flutter
  Windows, ni exécuter `clamd.exe`, ni tester `ReadDirectoryChangesW`.

Conclusion honnête : les 4 vérifications « machine réelle » exigent un
Windows qui s'exécute quelque part. Deux voies, §3 — dans les deux cas
le travail est pour moi, pas pour toi.

## 1. Prouvé depuis ma VM (sources officielles, 2026-10-23)

| Check | Résultat | Preuve |
| --- | --- | --- |
| yara-python sous Windows | ✅ **Résolu, risque levé** | PyPI, release **4.5.4** (27 mai 2025) : wheels `win_amd64` publiées pour CPython **3.9 → 3.13**, dont 3.11, 3.12, 3.13. La contrainte Malryx (`yara-python>=4.5,<5.0`) est satisfaite sans compilation. Décision : **figer Python 3.12** pour le backend Windows. |
| ClamAV for Windows | ✅ Existe en officiel | Documentation ClamAV (docs.clamav.net) : builds Windows officiels, au choix **installeur exécutable** ou **ZIP portable** ; `clamd.conf` supporte `TCPSocket 3310` (notre mode retenu, faute d'AF_UNIX). Reste à l'exécuter, pas à le trouver. |
| Flutter Windows | ✅ Exigences confirmées | Il faut **Visual Studio 2022** (ou Build Tools 2022) + workload **« Desktop development with C++ »** — pas VS Code — et Flutter **ne cross-compile pas** le desktop : Windows se build sur Windows. Le runner Malryx `frontend/windows/` est déjà dans le dépôt Linux. |
| Outils de test écrits + testés ici | ✅ | `tools/yara_test.py`, `tools/rdw_test.py`, `tools/clamd_tcp_test.py` : syntaxe Python vérifiée sur la VM ; `rdw_test.py` répond proprement `SKIP` hors Windows, `clamd_tcp_test.py` échoue proprement (connexion refusée) sans démon — ils sont prêts à donner un verdict net sous Windows. |

## 2. Kit prêt (aucune checklist manuelle)

`tools/w0_check.ps1` — **une seule commande** sur un Windows, il fait
tout, tout seul, et écrit `w0_report.json` + `w0_report.txt` :

```
powershell -ExecutionPolicy Bypass -File .\w0_check.ps1
```

Il vérifie : OS 64-bit ; Visual Studio + workload C++ (via `vswhere`) ;
Flutter + `flutter doctor` ; Python → venv jetable → installation
réelle de `yara-python==4.5.4` → test de règle ; prototype
`ReadDirectoryChangesW` (crée un fichier, exige l'événement < 10 s) ;
présence ClamAV et, s'il tourne, `zPING`→`PONG` en TCP 3310 ;
`Get-AuthenticodeSignature` sur `explorer.exe`.
Il n'installe rien en silence et ne modifie rien hors dossiers
temporaires nettoyés. Réserve honnête : le script PowerShell n'a pas
pu être exécuté ici (pas de Windows) — il est écrit défensif
(`Continue`, chaque check isolé) et son premier run fait partie du test.

## 3. Les deux voies pour les 4 verdicts machine

**Voie A — GitHub Actions (recommandée, zéro action pour toi)**
Le workflow `.github/workflows/w0-windows.yml` est écrit et prêt
(déclenchement manuel uniquement). Je crée un dépôt, je pousse le kit,
je lance le workflow : un vrai Windows Server du runner exécute les
checks, je lis les résultats et je te rends le verdict. C'est moi qui
fais tout, du début à la fin. C'est la seule voie où « fais le toi
même » est littéralement vrai à 100 %.
Coût : on utilise GitHub comme machine de build — optionnel au sens
du plan, mais c'est le prix de l'autonomie complète.

**Voie B — Ton PC, une commande**
Je te donne le dossier `tools/` (zip), tu lances la commande du §2
une fois (~2-3 minutes, dont l'installation de yara dans le venv),
tu me renvoies `w0_report.txt`. Une seule action de ta part, zéro
checklist. Limite : ça teste *ta* machine — c'est aussi un avantage :
c'est elle qui servira au développement.

Dans les deux voies, ClamAV demande une installation préalable
(installeur officiel) pour que le test TCP puisse répondre ; le
workflow comme le script le signalent en `ACTION` au lieu de faire
semblant.

## 4. Verdict W0 — CLOS le 2026-10-23 (voie A, GitHub Actions)

- Faisabilité **papier : verte** — aucun bloqueur de conception, le
  risque n°1 du plan (wheel YARA Windows) est levé avec preuve.
- Faisabilité **machine : verte**, les 4 verdicts sont obtenus sur
  runner Windows réel :
  - compile Flutter Windows / Visual Studio : **PASS** (run W0 n°1
    `39986709528`, Flutter 3.47.7, VS Enterprise 2026) ;
  - événement `ReadDirectoryChangesW` réel : **PASS** (run n°1) ;
  - signature Authenticode réelle : **PASS** (run n°1) ;
  - clamd TCP réel : **PASS** (run W1 `39995452363` : PONG, version
    ClamAV 1.5.4/28162). Deux échecs avant ce verdict (runs W0 n°2 et
    W1 n°1 : connexions coupées, WinError 10053) — la recette qui
    marche : **exclusions Windows Defender sur les dossiers ClamAV
    posées avant le démarrage de clamd**, puis PONG en moins d'une
    minute. Le run W0 n°3, bloqué 18 min dans l'étape ClamAV, a été
    annulé : le run W1 rejouait le même test avec le diagnostic.
- W0 et W1 sont clos ; le développement continue en W2 (voir
  docs/DECISIONS.md).
