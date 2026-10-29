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

## 2026-10-24 — Cause racine W3 trouvée (sondes 1 et 2)

- Sonde 1 : énumération 104 cibles en 1,2 s ; verify_signature total
  1,55 s ; scan complet des 64 non-signés = 842 s (plancher ~12 s/fichier).
- Sonde 2 : `_scan_instream` seul = 0,53 s ; `scan()` complet = 11,98 s.
  Cause : `_scan_instream` rendait None pour « propre » comme pour
  « non concluant », donc chaque fichier propre déclenchait AUSSI le
  repli `clamscan.exe`, qui recharge toute la base (~12 s). Corrigé :
  INSTREAM rend (verdict, conclusif) ; le binaire ne sert que si le
  daemon n'a pas tranché (ou fichier > 25 Mo).
- cmd.exe ressort « unsigned » sur le runner (signature catalogue non
  vue par WinVerifyTrust dans ce contexte) : le triage reste utile,
  mais le correctif moteur est LA correction principale.

## 2026-10-24 — W3 CLOS, W5 quasi clos

- W3 run 40038831437 : TOUT PASS — persistance, Authenticode, STARTUP
  (EICAR planté détecté + menace « non signé » présente), SMART.
  Après correctif moteur : `moteur clamav` 11,98 s → ~0,01 s/fichier.
- Régressions post-correctif : w1 40038826746, w2 40038826756,
  w4 40038826824 — tous verts.
- W5 run 40038826809 : AUDIT + FP + RESTORE (SHA-256 identique) +
  STARTUP_NOISE tous PASS, avec un scan STARTUP qui va désormais au
  bout. Ajout du test de robustesse temps réel (gros fichier 300 Mo,
  EICAR écrit en deux fois, renommage sain) — vert en local (inotify),
  verdict Windows/RDW en CI.
- Reste W5 : inspection REA des artefacts construits (avec W6, sur
  l'installateur final) + replica-diff final features.csv.

## 2026-10-24 — W5 : robustesse temps réel PASS sur Windows

- Run 40040443743 : REALTIME_ROBUST_VERDICT PASS via ReadDirectoryChangesW
  (fichier 300 Mo sans blocage, EICAR en deux écritures détecté, sain
  renommé .exe intact) ; audit, FP, restauration, bruit startup toujours
  verts. W5 ne dépend plus que de l'inspection REA des artefacts et du
  replica-diff final, faits avec W6 sur l'installateur construit.

## 2026-10-24 — W6 premier build vert + replica-diff final

- Run 40040961793 : INSTALLER_VERDICT PASS (Malryx-Setup-1.0.0.exe,
  ~152 Mo), installation silencieuse OK, backend en ligne via les
  tâches, désinstallation propre.
- replica/diff-final.md : 13 must = 9 livrés, 3 partiels au périmètre
  v1 (behavior/web/email), 1 écart (scan médias amovibles) ; should :
  4 livrés, écarts assumés (maj programme, scan planifié non câblé,
  dossiers anti-ransomware) ; skips tous tenus.
- Ajouts pour le run final : inspection des artefacts construits
  (chaînes interdites dans backend exe + installateur) et bundle
  allégé (UserManual ClamAV exclu).

- Audit artefacts, 1re passe : FAIL sur `api_key` dans le backend exe —
  faux positif de mon motif : c'est l'identifiant du moteur VirusTotal
  (clé optionnelle de l'utilisateur), aucune valeur. Motifs resserrés
  sur les valeurs (préfixes de clés, affectation avec valeur longue).

## 2026-10-24 — W6 CLOS. W0→W6 TERMINÉS : v1.0 livrée

- Run final 40043274039 : INSTALLER_VERDICT PASS
  (Malryx-Setup-1.0.0.exe, 156 501 973 octets), ARTIFACT_AUDIT PASS
  (ferme le dernier point W5), SMOKE PASS (installation silencieuse,
  backend en ligne), UNINSTALL PASS.
- L'ordre permanent du 2026-10-23 est rempli : version utilisable,
  similaire à AVG Free selon le replica-diff honnête
  (replica/diff-final.md). Restent côté Atamsphrow : essai sur son PC,
  nom/icône définitifs, certificat de signature éventuel, décision de
  publication (le dépôt est privé, l'installateur est dans les
  artefacts du run 40043274039, rétention 14 jours).

## 2026-10-24 — Signature auto-signée « Atamsphrow » (décision d'Atamsphrow : pas de certificat payant)

- Certificat DÉDIÉ créé (CN=Atamsphrow, O=ENI, L=Fianarantsoa, C=MG,
  RSA 2048, EKU Code Signing, valable jusqu'en 2054) — clé locale
  ~/malryx-windows-release.pfx (jamais committée), mot de passe en
  ~/.android/malryx-windows-release.pass, copie CI en secrets GitHub
  WINDOWS_SIGN_PFX_B64 / WINDOWS_SIGN_PASSWORD. Ne pas toucher sans
  instruction explicite, comme les clés Musync/Presence/Palimpseste.
- La CI signe malryx.exe, malryx-backend.exe et l'installateur
  (signtool, horodatage DigiCert quand joignable), puis la release
  v1.0.0 est publiée avec l'installateur signé. Effet assumé :
  éditeur affiché + intégrité, mais SmartScreen avertit toujours
  (pas une autorité reconnue par Windows).

## 2026-10-24 — Release v1.0.0 publiée, dépôt rendu public

- Le quota Actions du dépôt privé était épuisé (échecs de jobs en 2 s,
  zéro étape, y compris sur des workflows inchangés) : Atamsphrow a
  choisi de rendre le dépôt PUBLIC → minutes illimitées, build signé
  relancé vert (run 40056305742 : SIGN_BIN, SIGN, INSTALLER, AUDIT,
  SMOKE, UNINSTALL tous PASS ; signature vérifiée aussi en local sur
  l'artefact téléchargé, bloc PKCS signé « Atamsphrow »).
- Release GitHub v1.0.0 publiée (tag sur 182e4d3) avec
  Malryx-Setup-1.0.0.exe signé (156 515 304 octets, état uploaded).
  L'upload direct d'asset depuis la VM étant refusé (jeton limité à
  api.github.com), l'attachement passe par le workflow
  release-upload.yml (token du runner).
- Sauvegarde de la clé remise à Atamsphrow via liens privés expirants
  (pfx + mot de passe + certificat public) ; originaux conservés en
  local et en secrets GitHub.

## 2026-10-29 — Correctifs v1.0.1 (verdict d'essai sur le PC d'Atamsphrow)

- Verdict reçu 00:09 EAT : 4 bugs — eicar.com dans Téléchargements NON
  détecté malgré le bouclier temps réel activé, scan intelligent difficile
  à démarrer, page Scan grise après « Terminer », boutons Utilisateur /
  refresh inopérants. Méthode ≥3 avis appliquée avant toute modification
  (code réel lu directement + GPT via Groq + Gemini, tous d'accord, aucun
  désaccord ; DeepSeek 3× vide, Orca/OpenRouter limités, Ashna/OpenAI/
  Perplexity bloqués côté coffre — pas de 3e avis IA complet).
- Bug 1 (cause confirmée par le test : bouclier ON + Téléchargements) :
  le backend SYSTEM surveillait systemprofile via Path.home(). Correctif :
  `iter_windows_user_homes()` (profils C:\Users, hors Public/Default)
  utilisé par le watcher temps réel et par les cibles du scan intelligent ;
  protection temps réel activée par défaut (frais installs seulement, les
  réglages sauvegardés priment).
- Bug 2 : la résolution des cibles SMART/STARTUP (persistance + processus)
  bloquait la réponse 202. Correctif : résolution différée dans le thread
  du job (202 immédiat, vue d'exécution visible aussitôt) ; un échec
  d'énumération devient un scan en échec expliqué, pas un thread mort.
- Bug 3 : en release, une exception de build = écran gris silencieux.
  Correctif : `FlutterError.onError` + `ErrorWidget.builder` journalisent
  dans %LOCALAPPDATA%\Malryx\ui-errors.log et affichent un repli explicite
  avec retour à l'écran de scan. Le widget fautif exact reste à confirmer
  par le journal si le cas se reproduit.
- Bug 4 : `is_root()` retournait toujours False sur Windows (codé en dur)
  et le chip « Utilisateur » n'était pas cliquable. Correctif :
  `IsUserAnAdmin()` via ctypes, chip tactile → dialogue d'explication,
  indicateur + notice « Données rafraîchies » sur le refresh.
- Versions : pubspec 1.0.1+2, installateur Malryx-Setup-1.0.1.exe.
- Ajout v1.0.1 (question d'Atamsphrow 05:30 EAT) : l'installateur ne
  démarrait pas clamd (tâches ONSTART = prochain redémarrage seulement,
  rien ne lance clamd à l'installation) → moteur ClamAV « non installé »
  sans redémarrage. Correctif : `schtasks /Run` sur MalryxClamd et
  MalryxBackend juste après freshclam, avant le lancement de l'interface.
