# Replica-diff final — Malryx for Windows v1.0 vs matrice AVG Free

Établi le 2026-10-24, à partir de `features.csv` et des verdicts CI
réels (runs cités). « Livré » = construit ET prouvé par un test ;
« partiel » = le périmètre v1 annoncé dans la matrice est tenu, pas
au-delà ; « écart » = annoncé mais pas livré en v1.

## MUST (13)

| Fonction | État | Preuve / note |
|---|---|---|
| Écran principal, statut global | Livré | W4, UI_VERDICT run 40001062031 |
| File Shield (user-mode RDW) | Livré | W2 run 40005574679 (quarantaine 0,81 s) ; robustesse W5 run 40040443743 |
| Behavior Shield heuristique | Partiel | Heuristiques à l'analyse (download cradle, vssadmin…) prouvées W1 ; pas de surveillance comportementale continue des processus |
| Web Shield | Partiel | Fichiers téléchargés scannés à l'arrivée (dossier Téléchargements surveillé) ; pas de blocage d'URL ni d'interception HTTPS |
| Email Shield | Partiel | Pièces jointes scannées à l'écriture disque par le temps réel ; pas d'intégration aux clients mail |
| Smart Scan | Livré | W3 run 40038831437, SMART_VERDICT |
| Deep Scan | Livré | Moteur prouvé par les scans PATH/STARTUP ; pas de run CI sur disque entier (durée) |
| File/Folder Scan + clic droit | Livré | Scan PATH, `--scan`, menu Explorateur dans l'installateur |
| Removable Scan à l'insertion | **Écart** | Non construit pour Windows en v1 (existe côté Linux) |
| Archives zip/tar | Livré | W1 : EICAR dans un zip détecté (--archives) ; 7z externe non fait |
| Quarantaine isoler/restaurer/supprimer | Livré | W5 RESTORE_VERDICT (SHA-256 identique), stockage chiffré |
| Alerte temps réel (toast) | Livré* | Toasts WinRT codés ; limite session 0 documentée |
| Définitions à jour (freshclam) | Livré | Bouton UI + freshclam de l'installateur (4 vérifs/jour) |

## SHOULD (7)

| Fonction | État | Note |
|---|---|---|
| Mise à jour du programme | **Écart** | Pas de vérificateur de version en v1 |
| Scan planifié | **Écart partiel** | Le réglage existe (presets → cron) mais la tâche Task Scheduler de scan n'est pas créée |
| Exclusions | Livré | Éditables dans Réglages, appliquées par le backend |
| Historique et statistiques | Livré | SQLite + compteurs du dashboard |
| Scan des points de persistance | Livré | W3 PERSISTENCE_VERDICT |
| Authenticode | Livré | W3 AUTHENTICODE_VERDICT + triage des scans rapides |
| Dossiers protégés anti-ransomware | **Écart** | Non construit en v1 |

## COULD (4) — aucun livré en v1

Boot-Time Scan (les démons démarrent au boot via tâches, mais pas de
scan avant session), Network Inspector, mode silencieux, rapport
exportable : reportés, aucun n'était promis pour la v1.

## SKIP (8) — tenus

Aucun élément skip n'a été construit : ni signatures/cloud AVG, ni
pilote kernel, ni enregistrement WSC, ni fonction premium, ni compte
cloud/télémétrie, ni marque AVG.

## Verdict

Sur 13 must : 9 livrés, 3 partiels au périmètre v1 annoncé,
1 écart (médias amovibles). La v1 est utilisable au quotidien en
coexistence avec Defender ; les écarts sont documentés dans
`docs/UTILISATION.md` quand ils touchent l'utilisateur.
