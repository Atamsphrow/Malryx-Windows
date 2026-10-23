import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/app_state.dart';
import '../theme/app_theme.dart';
import '../widgets/common.dart';

/// Boucliers (S07/S08 de la recon) : les protections permanentes, groupees
/// comme dans les antivirus classiques — Ordinateur d'un cote,
/// Telechargements & scripts de l'autre.
///
/// Chaque interrupteur ecrit directement dans les reglages du backend
/// (PUT /api/settings) : l'etat affiche est toujours l'etat reel. Aucun
/// bouclier fictif : Malryx n'a ni extension navigateur ni filtre mail,
/// le deuxieme groupe couvre ce qui protege reellement les fichiers
/// entrants (archives, scripts, reputation en ligne optionnelle).
class ShieldsScreen extends StatelessWidget {
  const ShieldsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final settings = state.settings;
    final realtime = settings['realtime_protection'] as bool? ?? false;

    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        NoticeBanner(
          message: realtime
              ? 'Protection en temps reel active : les fichiers crees ou '
                  'modifies dans les dossiers sensibles (Telechargements, '
                  'Bureau, Temp, Demarrage) sont analyses immediatement.'
              : 'Protection en temps reel DESACTIVEE : seuls les scans '
                  'lances manuellement analysent les fichiers. '
                  'Reactivation conseillee.',
          icon: realtime ? Icons.verified_user_outlined : Icons.warning_amber,
        ),
        if (state.lastRealtimeThreat != null) ...[
          const SizedBox(height: 12),
          NoticeBanner(
            message: 'Derniere alerte temps reel : ${state.lastRealtimeThreat}',
            icon: Icons.bug_report_outlined,
          ),
        ],
        const SizedBox(height: 16),
        SectionCard(
          title: 'Ordinateur',
          icon: Icons.computer_outlined,
          subtitle: 'Fichiers, comportement et supports amovibles.',
          child: Column(
            children: [
              _ShieldToggle(
                title: 'Bouclier fichiers (temps reel)',
                subtitle: 'Surveillance continue des dossiers sensibles '
                    'et analyse a la creation / modification.',
                value: realtime,
                onChanged: (v) =>
                    state.updateSetting('realtime_protection', v),
              ),
              _ShieldToggle(
                title: 'Quarantaine automatique',
                subtitle: 'Isole immediatement toute menace detectee en '
                    'temps reel, sans attendre une decision.',
                value: settings['auto_quarantine'] as bool? ?? false,
                onChanged: (v) => state.updateSetting('auto_quarantine', v),
              ),
              _ShieldToggle(
                title: 'Analyse des medias amovibles',
                subtitle: 'Lance un scan des qu\'une cle USB est branchee.',
                value: settings['autoscan_removable'] as bool? ?? true,
                onChanged: (v) =>
                    state.updateSetting('autoscan_removable', v),
              ),
              _ShieldToggle(
                title: 'Heuristiques comportementales',
                subtitle: 'Signaux de risque sans signature connue : '
                    'droppers, obfuscation, suppression des clichés '
                    'instantanes (ransomware), double extension.',
                value: settings['heuristics_enabled'] as bool? ?? true,
                onChanged: (v) =>
                    state.updateSetting('heuristics_enabled', v),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SectionCard(
          title: 'Telechargements & scripts',
          icon: Icons.download_outlined,
          subtitle: 'Ce qui entre sur la machine : archives, signatures, '
              'reputation en ligne.',
          child: Column(
            children: [
              _ShieldToggle(
                title: 'Signatures ClamAV',
                subtitle: 'Base de signatures open source, mise a jour '
                    'par freshclam (voir Reglages > Mises a jour).',
                value: settings['clamav_enabled'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('clamav_enabled', v),
              ),
              _ShieldToggle(
                title: 'Regles YARA',
                subtitle: 'Detection par motifs de code, efficace sur '
                    'les familles connues et leurs variantes.',
                value: settings['yara_enabled'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('yara_enabled', v),
              ),
              _ShieldToggle(
                title: 'Fouiller les archives',
                subtitle: 'Analyse le contenu des zip et autres archives '
                    'telechargees au lieu de leur seule enveloppe.',
                value: settings['scan_archives'] as bool? ?? true,
                onChanged: (v) => state.updateSetting('scan_archives', v),
              ),
              _ShieldToggle(
                title: 'Reputation VirusTotal (optionnel)',
                subtitle: 'Interroge le service en ligne sur les '
                    'empreintes inconnues. Desactive par defaut, cle API '
                    'dans Reglages.',
                value: settings['virustotal_enabled'] as bool? ?? false,
                enabled: settings['virustotal_key_set'] as bool? ?? false,
                onChanged: (v) =>
                    state.updateSetting('virustotal_enabled', v),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Row(
              children: [
                Icon(
                  realtime ? Icons.verified_user : Icons.shield_outlined,
                  color:
                      realtime ? SeverityPalette.clean : SeverityPalette.high,
                  size: 28,
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Text(
                    realtime
                        ? 'Tous les boucliers essentiels sont en place.'
                        : 'La protection permanente est incomplete : '
                            'activez le bouclier fichiers pour une '
                            'protection continue.',
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _ShieldToggle extends StatelessWidget {
  const _ShieldToggle({
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
    this.enabled = true,
  });

  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return SwitchListTile(
      value: value,
      onChanged: enabled ? onChanged : null,
      contentPadding: EdgeInsets.zero,
      secondary: Icon(
        value ? Icons.check_circle : Icons.remove_circle_outline,
        color: value
            ? SeverityPalette.clean
            : theme.colorScheme.onSurfaceVariant,
        size: 20,
      ),
      title: Text(title, style: theme.textTheme.bodyLarge),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 2),
        child: Text(
          subtitle,
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
      ),
      isThreeLine: subtitle.length > 70,
    );
  }
}
