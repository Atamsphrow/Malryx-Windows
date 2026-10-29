# Malryx for Windows — guide d'utilisation (v1.0)

Malryx est un antivirus local et gratuit pour Windows, construit sur des
moteurs ouverts : ClamAV (signatures), YARA (règles), une base
d'empreintes locale et des heuristiques. Interface en français, aucune
publicité, aucune télémétrie, aucun compte.

## Installation

1. Lancez `Malryx-Setup-1.0.1.exe` et acceptez l'élévation administrateur.
2. L'installateur est signé par l'auteur (certificat auto-signé
   « Atamsphrow », comme ses applications Android) : l'éditeur
   s'affiche et l'intégrité du fichier est vérifiable, mais
   SmartScreen affichera quand même un avertissement, car ce
   certificat n'est pas délivré par une autorité commerciale
   reconnue par Windows. Cliquez « Informations complémentaires »
   puis « Exécuter quand même » — uniquement si le fichier vient
   bien de l'auteur du projet.
3. L'installateur télécharge les définitions ClamAV (plusieurs minutes
   selon la connexion), pose les exclusions Defender nécessaires à
   ClamAV, et enregistre deux tâches de démarrage : le moteur ClamAV et
   le moteur Malryx.
4. L'icône Malryx apparaît dans le menu Démarrer, sur le Bureau si vous
   l'avez demandé, et la barre d'état système (près de l'horloge).

## Ce que fait Malryx

- **Protection temps réel** : les fichiers créés ou modifiés dans vos
  dossiers utilisateur (Documents, Téléchargements, Bureau, dossier
  Démarrage…) sont analysés automatiquement ; une menace détectée est
  mise en quarantaine si l'option est active.
- **Scan intelligent** : points de démarrage (registre, tâches
  planifiées, services), processus en cours, Téléchargements et
  fichiers temporaires. Les fichiers signés valides sont contrôlés par
  leur signature ; les autres sont scannés en entier.
- **Scan complet / par dossier** : tout le contenu, signatures ou non.
- **Points de démarrage** : liste tout ce qui se lance automatiquement,
  et signale les exécutables non signés placés dans des dossiers à
  risque (Temp, Téléchargements).
- **Quarantaine** : les fichiers isolés sont chiffrés au repos ;
  restauration possible à l'octet près.
- **Mises à jour** : bouton « Mettre à jour maintenant » dans les
  Réglages (freshclam, miroirs officiels ClamAV).
- **Menu contextuel** : clic droit sur un fichier ou un dossier →
  « Analyser avec Malryx » (si l'option a été cochée à l'installation).

## Limites connues (v1, assumées)

- **Pas d'enregistrement au Centre de sécurité Windows** : Malryx
  coexiste avec Microsoft Defender, il ne le remplace pas
  officiellement. Vous pouvez garder les deux actifs.
- **Protection temps réel en mode utilisateur** : un programme lancé
  avec des droits administrateur peut contourner la surveillance des
  dossiers ; il n'y a pas de pilote noyau.
- **Détection** : les moteurs sont ceux de ClamAV/YARA/heuristiques —
  efficaces sur les menaces connues, plus faibles qu'un produit
  commercial sur les attaques zero-day et le phishing, qui reposent
  sur d'énormes infrastructures cloud que Malryx n'a pas.
- **Notifications** : les alertes apparaissent dans l'interface ; le
  toast Windows peut ne pas s'afficher quand l'interface est fermée
  (limite des services Windows en session 0).
- **Signatures des scans rapides** : le scan intelligent fait confiance
  aux signatures Authenticode valides (comme les antivirus réels) ; un
  scan complet reste disponible pour tout vérifier.

## Désinstallation

Panneau de configuration → Applications → Malryx → Désinstaller.
Les tâches de démarrage et le menu contextuel sont retirés ; le dossier
des définitions (`C:\ProgramData\Malryx`) peut être supprimé à la main.
