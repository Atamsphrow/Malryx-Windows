# Malryx for Windows

Antivirus gratuit pour Windows 10/11 x64, construit sur le moteur de
Malryx (Linux/Debian) et inspiré fonctionnellement — en clean-room —
d'AVG AntiVirus Free. Nom et identité propres ; signatures libres
(ClamAV) + YARA + heuristiques ; 100 % local, zéro télémétrie.

État : **W0 — faisabilité**. Aucun code applicatif Windows pour l'instant.

- `PLAN_WINDOWS.md` — plan complet (architecture, jalons W0→W6, limites)
- `replica/recon.md` — cartographie Replica d'AVG Free (sources publiques)
- `replica/features.csv` — matrice des fonctions (must/should/could/skip)
- `W0_RAPPORT.md` — rapport de faisabilité et verdicts W0
- `tools/` — kit de vérification W0 (PowerShell + Python)
- `.github/workflows/w0-windows.yml` — vérifications W0 sur runner Windows
  (déclenchement manuel uniquement)
