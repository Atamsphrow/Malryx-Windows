# W5 — Plan de test (replica-test) et inspection REA

Objectif : prouver que la v1 est *utilisable sans danger* — pas seulement
qu'elle détecte EICAR. Un antivirus qui casse la machine ou mange des
fichiers sains est pire qu'aucun antivirus.

## 1. Faux positifs (le test qui compte le plus)

Corpus sain déposé dans un dossier de test sur le runner, puis scan
complet du dossier + scan des points de démarrage :

- exécutables signés du système (explorer.exe, notepad.exe, svchost.exe) ;
- scripts PowerShell/Batch bénins écrits pour le test (hello world,
  inventaire système en lecture seule, sauvegarde par copie) ;
- archives saines (zip de textes, zip imbriqué) ;
- installeurs courants signés si téléchargeables (sinon, simulés par des
  PE signés du runner).

Critère : **zéro menace de sévérité ≥ MEDIUM** sur le corpus sain.
Toute alerte LOW d'heuristique est listée et jugée une par une.

## 2. Quarantaine : restauration bit-à-bit

- fichier sain-connu + EICAR : mise en quarantaine via l'API, restauration,
  comparaison SHA-256 avant/après — doit être **identique** ;
- restauration vers un emplacement occupé : comportement propre (erreur
  claire, pas d'écrasement silencieux) ;
- suppression définitive : le fichier n'existe plus nulle part.

## 3. Temps réel : robustesse

- dépôt d'un gros fichier (500 Mo de zéros) : pas de scan interminable,
  pas de blocage du watcher ;
- dépôt pendant un scan manuel en cours : pas de crash, pas de doublon
  de quarantaine ;
- renommage d'un fichier sain en `.exe` : pas d'alerte abusive ;
- fichier encore en cours d'écriture au-delà du délai de stabilisation :
  le verdict reste correct (pas de faux négatif silencieux sur EICAR
  écrit lentement, en deux fois).

## 4. Persistance : bruit sur machine « normale »

Sur le runner (Windows quasi stock) : le scan STARTUP ne doit produire
**aucune** menace « non signé » pour les entrées livrées avec Windows /
les runners (services Microsoft signés). Toute entrée signalée est
examinée : si c'est un faux positif de conception, le filtre de dossiers
à risque est resserré avant la v1.

## 5. Inspection REA de l'artefact (nos binaires, jamais AVG)

REA appliqué à ce que NOUS livrons :
- `malryx-backend.exe` (PyInstaller) : inventaire des imports, chaînes,
  URLs embarquées — vérifier qu'aucune clé/secret n'est embarqué, que
  les seules URL sont celles attendues (miroirs ClamAV, VirusTotal) ;
- `Malryx-Setup-1.0.0.exe` : structure de l'installateur, fichiers
  réellement inclus (pas de `.venv`, pas de keystore, pas de sources
  de dev), signature absente assumée ;
- `malryx.exe` (Flutter) : chaînes vérifiées (pas de chemin de dev
  `/home/hatch`, pas d'URL de test).

## 6. replica-diff final

Relecture de `replica/features.csv` : chaque « must » est marqué
fait / partiel / absent avec la preuve (écran, test CI, log). Les
écarts assumés partent dans la doc honnête de W6, pas sous le tapis.
