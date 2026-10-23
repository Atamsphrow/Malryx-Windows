# Recon map: AVG AntiVirus Free (Windows) — clone clean-room

Scope: AVG AntiVirus **Free** pour Windows 10/11 x64, 1 PC, usage personnel.
Tranche clonée : la boucle de protection de base — statut, boucliers temps réel,
scans à la demande, quarantaine, mises à jour des définitions.
Hors tranche : offres premium (Internet Security / Ultimate), compte AVG,
upsell dans l'app.
For: Malryx for Windows — antivirus gratuit d'Atamsphrow, nom propre,
aucune marque, aucun asset et aucun code d'AVG.
Date: 2026-10-23
Méthode: Replica (clean-room). Sources publiques uniquement. Aucune
décompilation, aucun binaire AVG ouvert, aucun trafic capturé.

## Sources

| # | source | URL | notes |
| --- | --- | --- | --- |
| 1 | page produit officielle FR | https://www.avg.com/fr-fr/antivirus-for-windows | promesse Free : bloque virus/spyware/malware, bloque liens, téléchargements et pièces jointes non sécurisés, scanne les problèmes de performance, mises à jour de sécurité en temps réel ; sépare Free du premium (pare-feu amélioré, anti-phishing paiements, support 24/7 = payant) |
| 2 | page téléchargement Free FR | https://www.avg.com/fr-fr/lp-ws-free-antivirus-download | « installation rapide, protection permanente », même liste de 4 bénéfices Free |
| 3 | aide officielle (Getting Started) | https://help.avg.com/en/avg_free/17/index.html | écran principal = statut « You are fully protected » / rouge si problème ; composants : Computer (Resident Shield + Software Analyzer), Web and Email (Online Shield + Email Protection) ; Menu ▸ Settings ▸ Components ; Menu ▸ Settings ▸ Update (définitions + programme, auto par défaut) |
| 4 | revue tierce 2026 | http://antivirus-review.com/avg-antivirus-review | nomme les Core Shields Free : File Shield, Behavior Shield, Web Shield, Email Shield, CyberCapture (cloud), Quarantine, Rescue Disk, Network Inspector ; confirme que Remote Access Shield, Webcam, Sensitive Data, Fake Website, Data Shredder sont premium |
| 5 | fiche Softpedia | https://www.softpedia.com/get/Antivirus/AVG-Free-Edition.shtml | protection temps réel à l'ouverture/ajout de fichier, anti-ransomware par dossiers protégés + exceptions, Web/Email Shield, Network Inspector, mises à jour automatiques définitions + programme |

Note de fiabilité : les sources 1-3 sont officielles. Les noms fins de
boucliers (File/Behavior/Web/Email) viennent de 4-5, recoupés entre eux —
confiance haute sur l'existence, moyenne sur le périmètre exact Free.

## Core loop

L'utilisateur installe, voit en un coup d'œil « protégé », et quand un fichier
arrive ou un scan se termine, toute menace finit en quarantaine d'où il la
restaure ou la supprime — sans jamais avoir à y penser entre-temps.

## Screens

| ID | screen | route / how to reach | purpose | key components | states seen |
| --- | --- | --- | --- | --- | --- |
| S01 | Installation / bienvenue | installateur téléchargé | installer, choix par défaut sûrs | assistant pas-à-pas, barre de progression, cases composants | en cours, terminé, échec (deviné) |
| S02 | Écran principal / statut | lancement app, icône tray | dire en 1 s si le PC est protégé et lancer l'action principale | grand statut (vert « fully protected » / rouge), tuiles Computer et Web & Email, bouton Scan principal, menu ☰ | protégé, problème critique, bouclier désactivé, définitions périmées (inféré) |
| S03 | Menu des scans | bouton Scan ▾ depuis S02 | choisir le type d'analyse | liste : Smart Scan, Deep Scan, File/Folder Scan, Boot-Time Scan, scan USB/externe | — |
| S04 | Scan en cours | depuis S03 ou bouton principal | suivre l'avancement | barre %, fichier courant, compteur fichiers/menaces, Pause / Stop | progression, pause, annulé |
| S05 | Résultats de scan | fin de S04 | décider du sort de chaque menace | liste menaces (nom, chemin, gravité), action par défaut quarantaine, bouton Résoudre | aucune menace (écran « propre »), menaces résolues, échec de résolution → boot-time conseillé |
| S06 | Quarantaine (Virus Vault) | Menu ▸ Quarantine | isoler, restaurer, supprimer | tableau fichiers isolés (origine, date, menace), actions Restaurer / Supprimer / Ajouter une exception | vide, rempli, confirmation restauration (risquée) |
| S07 | Boucliers — Computer | tuile Computer de S02 | activer/régler File + Behavior Shield | interrupteurs par bouclier (vert on / rouge off), durée si désactivation, sensibilité | on, off temporaire, off définitif |
| S08 | Boucliers — Web & Email | tuile Web & Email de S02 | activer/régler Web + Email Shield | mêmes interrupteurs, options pièces jointes / téléchargements | on, off |
| S09 | Notifications / alerte menace | popup temps réel, tray | bloquer et informer sans ouvrir l'app | toast : fichier, menace, action prise (bloqué/mis en quarantaine), bouton Détails | menace bloquée, action requise |
| S10 | Mises à jour | Menu ▸ Settings ▸ Update | définitions + programme à jour | version définitions, dernière vérification, bouton Update, option auto | à jour, en cours, échec réseau, périmé |
| S11 | Planification | Settings ▸ Scans programmés | scan automatique récurrent | fréquence, heure, type de scan, interrupteur | activé, désactivé |
| S12 | Exclusions / exceptions | Settings ▸ Exceptions | ne plus scanner un fichier/dossier approuvé | liste chemins, Ajouter / Retirer, avertissement risque | vide, rempli |
| S13 | Dossiers protégés (ransomware) | section Protection de S02 | empêcher la modification de dossiers sensibles par des apps non approuvées | liste dossiers, apps bloquées/autorisées | vide, rempli |
| S14 | Network Inspector | outil depuis S02/Menu | scanner le réseau local et le routeur | liste appareils connectés, faiblesses détectées | analyse en cours, propre, faiblesse |
| S15 | Réglages généraux | Menu ▸ Settings | langue, notifications, mode silencieux/jeu, démarrage | formulaire de réglages, sections | — |
| S16 | À propos / version | Menu ▸ About | version programme + définitions | texte version, licences | — |

Écrans premium affichés mais verrouillés chez AVG (pare-feu, webcam,
données sensibles…) : **non clonés** — voir Out of scope. Le clone n'affiche
pas de tuiles payantes.

## Flows

```
F01 Première protection
    S01 -> S02 (statut vert) -> définitions mises à jour auto (S10 en fond)
    happy path clicks: ~3 (installer, accepter défauts, ouvrir)
    edge: pas de réseau à l'installation, définitions initiales périmées,
          conflit avec un autre antivirus présent

F02 Scan rapide et résolution
    S02 -> (bouton Scan) S04 -> S05 -> menaces en quarantaine (S06)
    happy path clicks: 2 avant le scan, 1 pour résoudre
    edge: menace non supprimable en session -> proposer Boot-Time Scan,
          faux positif -> restaurer depuis S06 + exception (S12)

F03 Fichier malveillant téléchargé
    (navigateur) -> S09 alerte Web/File Shield -> fichier bloqué/quarantaine
    happy path clicks: 0 (automatique), 1 pour les détails
    edge: fichier rare/inconnu -> analyse approfondie avant verdict
          (équivalent CyberCapture, en local chez nous : heuristique renforcée)

F04 Désactiver temporairement un bouclier
    S02 -> S07/S08 -> interrupteur off -> choix de durée -> réactivation auto
    happy path clicks: 4
    edge: oubli de réactivation -> le choix d'une durée par défaut est le garde-fou

F05 Scan planifié
    S11 (créer : hebdo, Deep Scan) -> à l'heure dite S04 en fond -> S05/S09 si menace
    happy path clicks: 0 après configuration
    edge: PC éteint à l'heure du scan -> rattrapage au prochain démarrage

F06 Dossier ciblé / clé USB
    Explorateur clic droit « Analyser » ou S03 File/Folder -> S04 -> S05
    happy path clicks: 2
    edge: média retiré pendant le scan, fichier verrouillé par un processus
```

## Components

| component | variants | states | used on |
| --- | --- | --- | --- |
| Statut global | protégé (vert), attention (orange), danger (rouge) | — | S02 |
| Tuile bouclier | Computer, Web & Email | on, off, erreur | S02, S07, S08 |
| Interrupteur bouclier | avec durée de désactivation | on, off temporaire, off | S07, S08, S15 |
| Bouton scan | principal, menu déroulant des types | default, disabled pendant scan | S02, S03 |
| Barre de progression scan | déterminée %, indéterminée (énumération) | en cours, pause, terminé | S04 |
| Ligne menace | gravité basse/moyenne/haute/critique | détectée, en quarantaine, résolue, ignorée | S05, S06 |
| Toast d'alerte | info, menace bloquée, action requise | — | S09 |
| Sélecteur de chemin | fichier, dossier, lecteur | — | S03, S12, S13 |
| Badge définitions | à jour, périmé | — | S02, S10 |

## Inferred data model

```
Shield        id, kind (file|behavior|web|email), enabled, disabled_until,
              sensitivity
              evidence: S02 tuiles, S07/S08, aide officielle (composants)
              confidence: high

ScanJob       id, type (smart|deep|file_folder|boot_time|removable|scheduled),
              target_paths, started_at, finished_at, status
              (running|paused|done|cancelled|failed), files_scanned,
              threats_found
              evidence: S03-S05, manuels (4 types de scan prédéfinis)
              confidence: high

Threat        id, scan_job_id, name (signature), path, sha256, severity,
              engine, status (detected|quarantined|deleted|restored|ignored),
              detected_at
              evidence: S05, S06
              confidence: high

QuarantineEntry  id, threat_id, original_path, stored_path, stored_at,
                 size, restorable
                 evidence: S06 (Virus Vault : restaurer/supprimer/exception)
                 confidence: high

DefinitionUpdate  id, version, checked_at, applied_at, source, status
                  evidence: S10, aide officielle (Update auto définitions+programme)
                  confidence: high

Exclusion     id, path, kind (file|folder|pattern), created_at, note
              evidence: S12, aide support (exclusions après faux positif)
              confidence: high

Schedule      id, scan_type, frequency, time, enabled, last_run, next_run
              evidence: S11
              confidence: medium

ProtectedFolder  id, path ; AllowedApp id, folder_id, app_path, allowed
                 evidence: S13 (anti-ransomware par dossiers + apps autorisées)
                 confidence: medium

NetworkDevice id, ip, mac, hostname, kind, weaknesses[]
              evidence: S14
              confidence: medium (périmètre Free exact incertain)
```

Relationships: ScanJob 1-n Threat ; Threat 1-0..1 QuarantineEntry ;
Schedule 1-n ScanJob ; ProtectedFolder 1-n AllowedApp.

Correspondance Malryx (vérifiée dans le code Linux) : Threat, ScanJob et
QuarantineEntry existent déjà presque à l'identique (`core/models.py`,
`db/local_db.py`) — le modèle du clone part de là, pas de zéro.

## Feature matrix

Voir `features.csv`. Must: 13, should: 7, could: 4, skip: 8.

## Out of scope (cannot or should not be cloned)

- **Base de signatures propriétaire AVG + cloud CyberCapture** : c'est leur
  actif. Remplacé par ClamAV (signatures libres) + YARA + heuristiques.
- **Marque, logo, nom « AVG », textes marketing** : jamais réutilisés.
- **Fonctions premium** Internet Security/Ultimate : pare-feu amélioré,
  Webcam Protection, Remote Access Shield, Sensitive Data Shield,
  Fake Website Shield, Data Shredder, VPN, TuneUp — payantes chez AVG,
  hors promesse « gratuit de base », et plusieurs exigent un pilote/une
  infrastructure qu'on n'a pas.
- **Enregistrement auprès du Windows Security Center** comme antivirus
  reconnu (et la désactivation coordonnée de Defender qui va avec) :
  programme partenaire Microsoft, pas accessible à un projet gratuit
  indépendant en v1. Le clone coexiste avec Defender, il ne le remplace pas.
- **Pilote kernel / minifilter** équivalent au File Shield d'AVG :
  certificat EV + attestation Microsoft obligatoires — décision séparée, XL.
- **Rescue Disk** officiel AVG : remplacé plus tard par un scan au démarrage
  planifié (user-mode), pas un média bootable en v1.
- **Support 24/7, compte AVG, télémétrie cloud** : pas d'infrastructure.

## Size

Screens 16, flows 6, entities 9. Hard parts: (1) protection temps réel
crédible sans pilote kernel — surveillance user-mode des dossiers d'entrée ;
(2) ClamAV sous Windows (clamd en TCP, freshclam fiable) ; (3) coexistence
avec Microsoft Defender sans se marcher dessus ; (4) installateur + service
Windows avec élévation propre.
Size: **L** pour la v1 complète de cette tranche (M si on coupe S13/S14).
No promise of a perfect clone: la détection ne vaudra jamais celle d'AVG
tant qu'elle repose sur des signatures libres.

## Résumé (5 lignes)

Core loop: statut vert en un coup d'œil, menace → quarantaine → restaurer ou supprimer.
16 écrans, 6 flows, 9 entités — dont 3 déjà présentes dans Malryx Linux.
Plus durs : temps réel sans kernel, ClamAV/Windows, coexistence Defender.
Hors scope : signatures/cloud AVG, premium, pilote kernel, statut WSC.
Next step: `/replica-architect` — voir `../PLAN_WINDOWS.md` (plan complet).
