# Plan complet — Malryx for Windows

Antivirus gratuit pour Windows 10/11 x64, inspiré fonctionnellement
d'AVG AntiVirus Free (recon clean-room : `replica/recon.md` +
`replica/features.csv`), construit sur le moteur de Malryx Linux.
Nom de travail : **Malryx for Windows**. Nom, logo et textes propres —
jamais « AVG ».
Date : 2026-10-23. Statut : plan, aucun code Windows écrit.
Hébergement : local d'abord. GitHub optionnel (build CI / distribution),
jamais obligatoire — décision en W6 seulement.

---

## 1. Principe directeur

On ne réécrit pas un antivirus. On **porte** celui qui existe et qui est
déjà prouvé sous Linux (scan, détections EICAR y compris en archive,
quarantaine restaurée bit-à-bit, progression temps réel), et on concentre
le travail neuf sur ce qui est spécifique à Windows :

1. brancher ClamAV sous Windows,
2. surveiller les fichiers en temps réel en user-mode,
3. scanner les points de persistance Windows,
4. empaqueter en service + installateur propres.

Tout le reste est de l'adaptation, pas de la création.

## 2. Apport des deux outils

**Replica** — a produit la recon (`replica/`) : 16 écrans, 6 flows,
32 lignes de matrice (13 must / 7 should / 4 could / 8 skip).
La suite du pack servira aux jalons correspondants : `replica-architect`
avant W1, `replica-design` en W4, `replica-test` en W5, `replica-diff`
en W6 pour scorer le clone contre la matrice.

**REA** — uniquement sur nos artefacts et les composants ouverts :
- inspection PE de chaque build livré (sections, imports, signature,
  contenu réel de l'installateur) avant de le déclarer prêt ;
- comparaison de versions (diff d'artefacts entre deux jalons) ;
- vérification que l'installateur embarque bien ClamAV/YARA/règles prévus
  et rien d'autre.
REA ne touche jamais un binaire AVG. Limite connue de la VM : pas de
Ghidra/IDA — l'inspection PE reste au niveau layout/imports/preuves
fichier, ce qui suffit pour ce contrôle qualité.

## 3. Architecture cible

```
┌────────────────────────────────────────────────────────────┐
│ UI Flutter Windows (runner déjà présent dans Malryx)       │
│ dashboard · scan · quarantaine · boucliers · réglages       │
│ + tray icon, toasts Windows, entrée clic droit Explorateur │
└───────────────▲──────────────────────┬─────────────────────┘
        WebSocket│ (progression, alertes) │ REST 127.0.0.1:8765
┌───────────────┴──────────────────────▼─────────────────────┐
│ Service Windows « MalryxWin » (backend Python, PyInstaller)│
│ FastAPI locale uniquement — jamais exposée au réseau       │
│                                                            │
│  scan_engine ── moteurs ordonnés, moins cher → plus cher : │
│    1 HashDB locale      4 Heuristiques PE/Windows          │
│    2 ClamAV (clamd TCP) 5 VirusTotal (option, clé user)     │
│    3 YARA               6 Authenticode (nouveau)           │
│                                                            │
│  realtime_win ── ReadDirectoryChangesW (dossiers d'entrée) │
│  persistence ──── Run/RunOnce, Startup, tâches, services   │
│  scheduler ────── Task Scheduler (scans + freshclam)       │
│  quarantine ───── réversible, dossier protégé ACL          │
│  SQLite ───────── historique, menaces, quarantaine         │
└────────────────────────────────────────────────────────────┘
   Données : %LOCALAPPDATA%\malryx\ (config.py le prévoit déjà)
   ClamAV    : clamd.exe en service, TCP 127.0.0.1:3310,
               définitions via freshclam planifié
```

Décisions structurantes (héritées de Malryx Linux, reconduites) :
- backend en **127.0.0.1 uniquement** : un antivirus joignable en réseau
  serait une porte d'entrée ;
- pourcentage **honnête** : énumération d'abord, barre indéterminée tant
  que le total est inconnu ;
- moteurs **du moins cher au plus cher**, VirusTotal seulement si aucun
  moteur local n'a tranché ;
- quarantaine **réversible et vérifiée** : restauration bit-à-bit ou
  rien ;
- **zéro télémétrie, zéro compte** : 100 % local.

## 4. Réutilisation Malryx — vérifié dans le code le 2026-10-23

| Bloc Malryx Linux | Fichier(s) | Sort sous Windows |
| --- | --- | --- |
| Modèles de données | `backend/core/models.py` | Réutilisé — aligné sur le modèle inféré de la recon (Threat, ScanJob, QuarantineEntry) |
| Moteur de scan + archives zip/tar | `backend/core/scan_engine.py` | Réutilisé ; ajouter 7z via outil externe (should) |
| HashDB SHA-256 (+ EICAR) | `backend/engines/hash_checker.py`, `signatures/bundled.hashes` | Réutilisé tel quel |
| YARA | `backend/engines/yara_engine.py`, `rules/malryx_base.yar` | Réutilisé ; wheel Windows de `yara-python` à valider en W0 |
| Heuristiques | `backend/engines/heuristics.py` | Adapté : règles Linux (dropper `curl\|bash`, `ld.so.preload`) remplacées par des règles PE/Windows (double extension, exécutable en dossier temp/utilisateur, script obfusqué, macros) |
| VirusTotal | `engines/` (moteur VT) | Réutilisé, optionnel, clé de l'utilisateur |
| Quarantaine | `backend/core/quarantine.py` | Réutilisé ; ACL Windows au lieu de `chmod 700` (déjà conditionné `IS_WINDOWS` dans config) |
| Base SQLite | `backend/db/local_db.py` | Réutilisée telle quelle |
| Bus d'événements + WebSocket | `backend/core/events.py`, API routes | Réutilisés tels quels |
| Chemins | `backend/core/config.py` | **Déjà Windows-aware** : branche `%LOCALAPPDATA%` écrite ; remplacer `DEFAULT_EXCLUDES` Linux (`/proc`…) par les exclusions Windows (§5) |
| Écrans Flutter (dashboard, scan, quarantaine, réglages) | `frontend/lib/screens/*` | Réutilisés ; écran « Appareils » (Android/USB/SSH Linux) remplacé par « Boucliers » (S07/S08) + « Persistance » |
| Runner Windows | `frontend/windows/` | **Déjà présent** dans le dépôt Malryx — point de départ du build |
| Temps réel | `backend/core/realtime.py` (inotify ctypes) | **Réécrit** : `ReadDirectoryChangesW` ; le repli par scrutation déjà codé sert de filet |
| ClamAV | `backend/engines/clamav_engine.py` (socket Unix `AF_UNIX`) | **Adapté** : `AF_UNIX` n'existe pas sous Windows → client TCP `127.0.0.1:3310`, protocole INSTREAM inchangé |
| Scan processus/paquets, scanners d'appareils Linux | `process_scanner.py`, `package_scanner.py`, `devices/*` | Hors v1 Windows (le `windows_scanner.py` actuel scanne une partition Windows *depuis Linux* — sans objet quand on tourne *sur* Windows) |
| Packaging .deb + systemd | `packaging/` | **Remplacé** : PyInstaller (spec déjà existante à adapter) + service Windows + Inno Setup |

Bilan : moteur et UI ≈ 60-70 % repris. Le neuf se concentre en §5.

## 5. Modules neufs Windows

1. **clamd TCP** — installation/gestion de `clamd.exe` (paquet officiel
   ClamAV for Windows), configuration `clamd.conf` en TCP loopback,
   `freshclam` en tâche planifiée (toutes les 4 h par défaut proposé),
   statut moteur honnête dans l'UI si clamd est absent (repli
   `clamscan.exe`, plus lent, affiché comme tel).
2. **realtime_win** — `ReadDirectoryChangesW` sur : Téléchargements,
   Bureau, Documents, `%TEMP%`, dossiers de démarrage, lecteurs
   amovibles à l'insertion. Fichier fermé en écriture → pipeline moteurs
   → si menace : quarantaine (si réglage auto) + toast Windows (S09).
   C'est une surveillance **user-mode** : elle voit les fichiers, elle
   n'intercepte pas l'exécution au niveau noyau. Écrit noir sur blanc
   dans l'UI et la doc — pas d'équivalence revendiquée avec le File
   Shield kernel d'AVG.
3. **persistence** — inventaire + scan ciblé : clés `Run`/`RunOnce`
   (HKCU/HKLM), dossiers Startup, tâches planifiées non-Microsoft,
   services à démarrage automatique pointant hors `System32`.
   Chaque entrée résolue vers son fichier, scanné par le pipeline.
4. **authenticode** — statut de signature de chaque exécutable scanné
   (`Get-AuthenticodeSignature` via API WinTrust, pas de shell) :
   valide / non signé / signature invalide. Non signé + emplacement
   suspect + heuristiques = signal composé, jamais un verdict seul.
5. **intégration bureau** — icône tray (statut, ouvrir, scan rapide,
   pause des boucliers 10 min/1 h), toasts natifs, entrée Explorateur
   « Analyser avec Malryx » (registre `shell\MalryxScan` en v1 ;
   extension shell native seulement si le besoin se confirme).
6. **service + installateur** — backend en service Windows (démarrage
   automatique, compte LocalSystem, redémarrage en cas d'échec), UI en
   utilisateur normal ; installateur Inno Setup avec élévation UAC,
   désinstalleur propre (service, tâches, clés registre, dossier
   données sur demande). Exclusions par défaut : `C:\Windows\WinSxS`
   en lecture prudente, dossier de quarantaine lui-même, fichiers
   système verrouillés ignorés sans erreur affichée.

**Coexistence Defender** : v1 ne s'enregistre pas au Windows Security
Center et ne désactive pas Defender. Risque connu : double scan et
ralentissements ; mesure d'atténuation : exclusion réciproque
documentée (ajouter le dossier Malryx aux exclusions Defender et
inversement), affichée dans l'aide intégrée. Revendication honnête :
« second avis permanent », pas « remplacement de Defender », tant que
le statut WSC n'est pas obtenu.

## 6. Jalons

| Jalon | Contenu | Critère d'acceptation (vérifiable) |
| --- | --- | --- |
| **W0 — Faisabilité** (2-3 sessions) | Sur PC Windows : Flutter Windows compile (VS Build Tools + workload C++), `yara-python` s'installe, clamd TCP répond, prototype `ReadDirectoryChangesW` | les 4 checks verts sur machine réelle, consignés ; tout rouge = on rescales avant d'écrire du code |
| **W1 — Port moteur** | fork local `malryx-windows` depuis Malryx, config/exclusions Windows, ClamAV TCP, heuristiques PE, CLI fonctionnelle | `malryx scan` sous Windows détecte EICAR (nu, en zip, double extension) ; suite de tests Malryx portée verte |
| **W2 — Service + temps réel** | service Windows, realtime_win, quarantaine auto réglable, toasts | EICAR déposé dans Téléchargements → alerte + quarantaine < 10 s ; service survit à un redémarrage |
| **W3 — Persistance + Authenticode** | module persistence, moteur authenticode, scan « Smart » = zones critiques + persistance | une entrée Run pointant sur EICAR est détectée par le Smart Scan ; un exe non signé en `%TEMP%` lève le signal composé |
| **W4 — UI complète** | écrans S02-S16 de la recon (boucliers, planification via Task Scheduler, exclusions, dossiers protégés), tray, clic droit | `replica-diff` intermédiaire : 13 must présents ; parcours F01-F06 faisables sans CLI |
| **W5 — Durcissement + tests** | `replica-test` : faux positifs (fichiers système, installateurs signés connus), perfs (Deep Scan chronométré), restauration quarantaine, désinstallation propre ; inspection REA de l'artefact | 0 faux positif sur le corpus sain de test ; restauration bit-à-bit ; rapport REA de l'installateur archivé |
| **W6 — Livraison v1.0** | installateur Inno Setup, doc utilisateur honnête (limites §7), choix distribution | installation propre sur un Windows vierge (VM ou machine de test) ; désinstallation sans résidu |

Ordre strict : aucun jalon ne démarre avant le critère du précédent.
Comme pour Musync : **aucun build distribué sans ton « Lancer »**.

Build : sur ton PC Windows (W0 l'équipe). GitHub Actions
(`windows-latest`) reste une option de confort en W6 — pas avant,
pas par défaut.

## 7. Limites assumées de la v1 (à écrire dans la doc livrée)

- Détection = signatures **libres** (ClamAV) + YARA + heuristiques :
  inférieure à AVG/Defender sur les menaces récentes. C'est un antivirus
  réel mais modeste ; le marketing ne dira pas le contraire.
- Temps réel **user-mode** : un malware qui s'exécute plus vite que
  l'écriture disque fermée peut passer. Pas de blocage à l'exécution.
- Pas de protection Web au sens interception HTTPS : seuls les fichiers
  téléchargés sont scannés à l'arrivée.
- Pas de statut antivirus reconnu par Windows (WSC), pas de pilote.
- Installateur **non signé** en v1 → avertissement SmartScreen à
  l'installation. La signature de code (certificat payant) est une
  décision séparée, comme le pilote.

## 8. Risques

| Risque | Probabilité | Parade |
| --- | --- | --- |
| VS Build Tools / compile Flutter Windows pénible sur ton PC | haute | W0 dédié, rien d'autre ne commence avant |
| `yara-python` sans wheel adaptée à ta version Python | moyenne | figer la version Python du backend sur celle testée en W0 ; PyInstaller fige ensuite tout |
| Defender signale le backend PyInstaller (faux positif classique) | moyenne | build reproductible, soumission faux positif à Microsoft, à terme signature de code |
| Double scan avec Defender → PC lent | moyenne | exclusions réciproques documentées, Smart Scan léger par défaut |
| freshclam rate-limited (CDN ClamAV) | basse | miroir par défaut, intervalle raisonnable, statut d'échec visible (S10) |
| Dérive de portée (« fais aussi le pare-feu ») | — | la matrice tranche : premium = skip, toute demande nouvelle passe par `features.csv` |

## 9. Décisions qui t'appartiennent (pas bloquantes avant W4)

1. Nom définitif et icône (Malryx for Windows est un nom de travail).
2. Langue de l'UI v1 : français seul (comme Malryx Linux) ou FR/EN.
3. En W6 : distribution locale seule, ou dépôt + Releases GitHub.
4. Plus tard, si le projet vit : certificat de signature de code, puis
   seulement ensuite réflexion pilote/WSC (XL, autre projet).

## 10. Prochaine action

W0 sur ton PC Windows quand tu veux : je te prépare la checklist exacte
(install VS Build Tools, tests clamd/YARA/Flutter) et on la coche
ensemble, résultat par résultat.
