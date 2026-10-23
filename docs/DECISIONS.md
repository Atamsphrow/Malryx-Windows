# Décisions — Malryx for Windows

Journal des décisions du développement autonome (ordre d'Atamsphrow du
2026-10-23 : aller jusqu'à une version utilisable, similaire à AVG en
fonctions, sans s'arrêter à chaque jalon).

## 2026-10-23 — Cadre
- Cible : Windows 10/11 x64. « Similaire à AVG » = matrice Replica
  (13 must), jamais marque/code/signatures AVG.
- Machine de build et de test : GitHub Actions `windows-latest`
  (voie A choisie par Atamsphrow). Verdicts = logs CI lus en entier,
  étape par étape — un job vert ne suffit pas (leçon du run 2 :
  `continue-on-error` peut masquer un échec réel).
- Dépôt : `Atamsphrow/Malryx-Windows`, privé. Push via l'API Git Data
  (script `~/workspace/scripts/malryx-win-gh.py`, à étendre à chaque
  nouveau fichier : sa liste FILES est explicite).

## 2026-10-23 — W0
- Python backend figé à **3.12** (wheel yara-python 4.5.4 win_amd64
  vérifiée sur PyPI pour 3.9→3.13).
- ClamAV : mode **TCP 127.0.0.1:3310** (pas d'AF_UNIX sous Windows).
  Constat CI : le port s'ouvre avant la fin du chargement des
  signatures ; tout client doit **réessayer zPING jusqu'à PONG**
  (240 s en CI). Ce comportement est une exigence du moteur W1,
  pas seulement du script de test.

## 2026-10-23 — W1 (démarrage)
- Fork local : `backend/` copié de Malryx Linux (320 Ko) ;
  `frontend/` = `pubspec.yaml`, `analysis_options.yaml`, `lib/`,
  `test/`, `windows/` (le runner Linux n'est pas repris).
- Le code Linux reste la référence de comportement (quarantaine
  bit-à-bit, pourcentage honnête, moteurs ordonnés) : on adapte,
  on ne réinvente pas.

## 2026-10-23 (soir) — W0 et W1 clos, recette clamd/Defender
- W0 clos : les 4 verdicts machine sont verts (détail dans W0_RAPPORT.md §4).
- W1 clos : run `39995452363` vert de bout en bout — COMPILE PASS,
  CLAMD_TCP PASS (PONG, ClamAV 1.5.4/28162), DETECTION PASS (EICAR nu,
  zip, double extension ; fichier sain propre ; heuristiques dropper.ps1
  et vssadmin seules).
- Recette clamd sous Windows (apprise après 2 échecs WinError 10053) :
  poser les exclusions Defender (dossier ClamAV + dossier des bases)
  AVANT de démarrer clamd, sinon le chargement des signatures est
  perturbé et le démon coupe les connexions. PONG ensuite en < 1 min.
- Le run W0 n°3 (bloqué dans l'étape ClamAV, aucun journal lisible
  pendant le job) a été annulé ; le run W1 rejouait le même test avec
  journal clamd affiché — méthode à retenir : toujours instrumenter
  l'étape qui peut pendre.
- W2 : temps réel Windows = ReadDirectoryChangesW via ctypes (un thread
  par dossier, scan après stabilisation de la taille) ; service SCM via
  pywin32 ; toasts WinRT via PowerShell (best-effort, session 0 = limite
  v1 connue) ; dossier Démarrage surveillé ; surcharge des dossiers par
  MALRYX_WATCH_DIRS (service + tests).

## 2026-10-23 — Verdicts W3 (1er passage) et W4

- W3 run 39999148019 : PERSISTENCE PASS (687 services, 88 tâches énumérés),
  Authenticode explorer.exe VALID. Échecs : workflow généré sans l'étape
  pip install (CLI sans pydantic) et faux .exe texte classé INVALID —
  TRUST_E_SUBJECT_FORM_UNKNOWN (0x800B0003) désormais classé « non signé »
  (aucune signature vérifiable). Correctifs poussés (fa90e69), re-run en cours.
- W4 run 40001062031 : UI_VERDICT PASS (analyze + tests + build Windows
  release, malryx.exe 91 648 octets) et BACKEND_EXE_VERDICT PASS
  (PyInstaller onefile répond sur /api/health). La paire livrable existe.

## 2026-10-23 — W2 CLOS, triage W3 insuffisant

- W2 run 40005574679 : REALTIME_VERDICT PASS — EICAR détecté par 2 moteurs,
  mis en quarantaine en 0,81 s, fichier sain conservé, arrêt propre. Le
  deadlock CloseHandle (prouvé par faulthandler) est corrigé par le passage
  en I/O overlapped : chaque thread RDW possède et ferme ses handles.
- W3 : le triage Authenticode n'a pas suffi (scan STARTUP toujours > 900 s).
  Hypothèse principale : WinVerifyTrust tente des récupérations réseau
  (AIA) pendant la construction de chaîne. Ajout de
  WTD_CACHE_ONLY_URL_RETRIEVAL ; harnais durci (timeout isolé par scan).

## 2026-10-23 — Triage W3 étendu

- Run 40008984176 : les scans STARTUP/SMART dépassent toujours 600/1200 s.
  Le goulot n'était pas WinVerifyTrust mais les scans complets des
  binaires signés hors dossier Windows (Program Files du runner).
  Triage étendu : dans STARTUP/SMART, tout fichier à signature VALIDE
  est contrôlé par sa signature seule, quel que soit le dossier ; les
  non signés gardent le scan complet. PATH/FULL inchangés.
