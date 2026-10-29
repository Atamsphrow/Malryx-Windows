import 'dart:io';

import 'package:flutter/material.dart';
import 'package:intl/date_symbol_data_local.dart';
import 'package:provider/provider.dart';

import 'models/scan_result.dart';
import 'screens/dashboard_screen.dart';
import 'screens/devices_screen.dart';
import 'screens/local_scan_screen.dart';
import 'screens/quarantine_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/shields_screen.dart';
import 'services/tray_service.dart';
import 'state/app_state.dart';
import 'theme/app_theme.dart';
import 'widgets/common.dart';

/// Point d'entree. `--scan <chemin>` (menu contextuel de l'Explorateur,
/// raccourcis) demande l'analyse immediate de la cible passee.
/// Journalise une erreur d'affichage Flutter dans un fichier local, sans
/// jamais lever (la journalisation ne doit pas aggraver l'erreur).
void _logFlutterError(FlutterErrorDetails details) {
  try {
    final base = Platform.environment['LOCALAPPDATA'] ??
        Platform.environment['APPDATA'];
    if (base == null) return;
    final dir = Directory('$base/Malryx');
    dir.createSync(recursive: true);
    final file = File('${dir.path}/ui-errors.log');
    file.writeAsStringSync(
      '[${DateTime.now().toIso8601String()}] ${details.exceptionAsString()}\n'
      '${details.stack ?? ''}\n',
      mode: FileMode.append,
    );
  } catch (_) {}
}

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  // v1.0.2 : les DateFormat('fr_FR') de formatters.dart exigent les symboles
  // de dates intl, sinon LocaleDataException au premier rendu d'une menace
  // ou d'un element de quarantaine (constate en essai v1.0.1).
  await initializeDateFormatting('fr_FR');
  // v1.0.1 : en build release, une exception pendant le build affiche un
  // ecran gris silencieux. On journalise l'erreur et on affiche un repli
  // explicite avec un bouton de retour, au lieu du gris.
  FlutterError.onError = (details) {
    _logFlutterError(details);
    FlutterError.dumpErrorToConsole(details);
  };
  ErrorWidget.builder = (details) {
    _logFlutterError(details);
    return const _DisplayErrorFallback();
  };
  String? scanTarget;
  final index = args.indexOf('--scan');
  if (index != -1 && index + 1 < args.length) {
    scanTarget = args[index + 1];
  }
  runApp(MalryxApp(pendingScanTarget: scanTarget));
}

class MalryxApp extends StatelessWidget {
  const MalryxApp({super.key, this.pendingScanTarget});

  final String? pendingScanTarget;

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) =>
          AppState(pendingScanTarget: pendingScanTarget)..initialize(),
      child: Consumer<AppState>(
        builder: (context, state, _) {
          return MaterialApp(
            title: 'Malryx',
            debugShowCheckedModeBanner: false,
            // Mode sombre forcé : aucun ThemeMode.system, aucun thème clair.
            // C'est un choix de conception, pas un oubli.
            theme: MalryxTheme.dark(_seedFrom(state)),
            home: const _AppShell(),
          );
        },
      ),
    );
  }

  /// Couleur d'accent issue des réglages du backend, avec repli sur le cyan.
  Color _seedFrom(AppState state) {
    final raw = state.settings['accent_color'];
    if (raw is String) {
      final hex = raw.replaceAll('#', '');
      final value = int.tryParse(hex, radix: 16);
      if (value != null) {
        // Format attendu : AARRGGBB. Si seul RRGGBB est fourni, on force
        // l'opacité complète.
        return Color(hex.length == 6 ? 0xFF000000 | value : value);
      }
    }
    return MalryxTheme.defaultSeed;
  }
}

/// Coquille de l'application : rail de navigation à gauche, écran à droite.
class _AppShell extends StatefulWidget {
  const _AppShell();

  @override
  State<_AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<_AppShell> {
  int _index = 0;

  static const List<({String label, IconData icon, IconData selectedIcon})>
      _destinations = [
    (
      label: 'Tableau de bord',
      icon: Icons.dashboard_outlined,
      selectedIcon: Icons.dashboard
    ),
    (label: 'Scan', icon: Icons.radar_outlined, selectedIcon: Icons.radar),
    (
      label: 'Boucliers',
      icon: Icons.shield_outlined,
      selectedIcon: Icons.shield
    ),
    (
      label: 'Appareils',
      icon: Icons.devices_outlined,
      selectedIcon: Icons.devices
    ),
    (
      label: 'Quarantaine',
      icon: Icons.lock_outline,
      selectedIcon: Icons.lock
    ),
    (
      label: 'Réglages',
      icon: Icons.settings_outlined,
      selectedIcon: Icons.settings
    ),
  ];

  void _navigate(int index) => setState(() => _index = index);

  TrayService? _tray;
  bool _scanTargetConsumed = false;

  @override
  void initState() {
    super.initState();
    _tray = TrayService(
      onOpen: () {},
      onSmartScan: () => _startTrayScan(ScanTypes.smart),
      onStartupScan: () => _startTrayScan(ScanTypes.startup),
      onQuit: () => exit(0),
    );
    _tray!.initialize();
  }

  @override
  void dispose() {
    _tray?.dispose();
    super.dispose();
  }

  void _startTrayScan(String type) {
    final state = context.read<AppState>();
    if (state.phase != BackendPhase.ready) return;
    state.startScan(type: type).then((started) {
      if (started && mounted) _navigate(1);
    });
  }

  /// Une cible passee en ligne de commande ouvre l'ecran d'analyse des
  /// que le backend est pret (une seule fois).
  void _consumeScanTarget(AppState state) {
    if (_scanTargetConsumed || state.phase != BackendPhase.ready) return;
    if (state.pendingScanTarget == null) return;
    _scanTargetConsumed = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _navigate(1);
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();

    if (state.phase == BackendPhase.starting) {
      return const _StartupScreen();
    }
    if (state.phase == BackendPhase.failed) {
      return _StartupFailedScreen(message: state.startupError ?? 'Erreur inconnue');
    }
    _consumeScanTarget(state);

    return Scaffold(
      body: Row(
        children: [
          _NavigationSidebar(
            index: _index,
            destinations: _destinations,
            onSelect: _navigate,
          ),
          const VerticalDivider(width: 1),
          Expanded(
            child: Column(
              children: [
                _TopBar(title: _destinations[_index].label),
                if (state.notice != null)
                  Padding(
                    padding: const EdgeInsets.fromLTRB(24, 0, 24, 0),
                    child: NoticeBanner(
                      message: state.notice!,
                      isError: state.noticeIsError,
                      onDismiss: state.clearNotice,
                    ),
                  ),
                Expanded(child: _screenFor(_index)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _screenFor(int index) => switch (index) {
        0 => DashboardScreen(onNavigate: _navigate),
        1 => const LocalScanScreen(),
        2 => const ShieldsScreen(),
        3 => DevicesScreen(onNavigate: _navigate),
        4 => const QuarantineScreen(),
        _ => const SettingsScreen(),
      };
}

class _NavigationSidebar extends StatelessWidget {
  const _NavigationSidebar({
    required this.index,
    required this.destinations,
    required this.onSelect,
  });

  final int index;
  final List<({String label, IconData icon, IconData selectedIcon})>
      destinations;
  final ValueChanged<int> onSelect;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final state = context.watch<AppState>();

    return NavigationRail(
      selectedIndex: index,
      onDestinationSelected: onSelect,
      labelType: NavigationRailLabelType.all,
      minWidth: 96,
      leading: Padding(
        padding: const EdgeInsets.only(top: 20, bottom: 24),
        child: Column(
          children: [
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    theme.colorScheme.primary,
                    theme.colorScheme.tertiary,
                  ],
                ),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(Icons.shield_outlined,
                  color: theme.colorScheme.onPrimary, size: 24),
            ),
            const SizedBox(height: 8),
            Text(
              'Malryx',
              style: theme.textTheme.labelLarge?.copyWith(
                fontWeight: FontWeight.w700,
                letterSpacing: 0.5,
              ),
            ),
          ],
        ),
      ),
      trailing: Expanded(
        child: Align(
          alignment: Alignment.bottomCenter,
          child: Padding(
            padding: const EdgeInsets.only(bottom: 20),
            child: Tooltip(
              message: state.wsConnected
                  ? 'Flux temps réel connecté'
                  : 'Flux temps réel interrompu, reconnexion en cours',
              child: Icon(
                state.wsConnected ? Icons.sensors : Icons.sensors_off,
                size: 18,
                color: state.wsConnected
                    ? SeverityPalette.clean
                    : SeverityPalette.medium,
              ),
            ),
          ),
        ),
      ),
      destinations: [
        for (final destination in destinations)
          NavigationRailDestination(
            icon: _DestinationIcon(
              icon: destination.icon,
              label: destination.label,
            ),
            selectedIcon: _DestinationIcon(
              icon: destination.selectedIcon,
              label: destination.label,
            ),
            label: Text(destination.label),
          ),
      ],
    );
  }
}

/// Icône de navigation, avec un badge sur les entrées qui demandent attention.
class _DestinationIcon extends StatelessWidget {
  const _DestinationIcon({required this.icon, required this.label});

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final count = switch (label) {
      'Quarantaine' => state.stats.quarantineActive,
      'Appareils' => state.devices.where((d) => d.kind != 'local_host').length,
      _ => 0,
    };
    final scanning = label == 'Scan' && (state.activeScan?.isActive ?? false);

    if (scanning) {
      return const SizedBox(
        width: 24,
        height: 24,
        child: CircularProgressIndicator(strokeWidth: 2.5),
      );
    }
    if (count == 0) return Icon(icon);
    return Badge(
      label: Text('$count'),
      child: Icon(icon),
    );
  }
}

class _TopBar extends StatelessWidget {
  const _TopBar({required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<AppState>();
    final theme = Theme.of(context);

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 18),
      child: Row(
        children: [
          Text(title, style: theme.textTheme.headlineSmall),
          const Spacer(),
          if (state.health != null && !state.health!.root)
            Padding(
              padding: const EdgeInsets.only(right: 12),
              child: Tooltip(
                message: 'Le moteur tourne sans privilèges administrateur. '
                    'Appuyez pour en savoir plus.',
                child: ActionChip(
                  avatar: const Icon(Icons.person_outline, size: 16),
                  label: const Text('Utilisateur'),
                  visualDensity: VisualDensity.compact,
                  onPressed: () => _showElevationDialog(context),
                ),
              ),
            ),
          if (state.refreshing)
            const Padding(
              padding: EdgeInsets.only(right: 12),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2.5),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.refresh),
              tooltip: 'Tout rafraîchir',
              onPressed: () => state.refreshAll(announce: true),
            ),
        ],
      ),
    );
  }
}

/// Dialogue d'explication du statut d'elevation du moteur (v1.0.1 : le
/// chip « Utilisateur » etait informatif mais non cliquable, et le texte
/// parlait de sudo sur une machine Windows).
void _showElevationDialog(BuildContext context) {
  showDialog<void>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Privilèges du moteur'),
      content: const Text(
        "Le moteur d'analyse tourne sans privilèges administrateur : "
        "certains fichiers système protégés ne pourront pas être lus. "
        "Normalement, l'installateur lance le moteur comme service SYSTEM "
        "au démarrage ; redémarrez l'ordinateur pour revenir à ce mode. "
        "Un scan reste possible, avec des erreurs d'accès sur les fichiers "
        "protégés.",
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Compris'),
        ),
      ],
    ),
  );
}

/// Repli affiché à la place d'un sous-arbre en échec de build : message
/// explicite + retour à l'écran de lancement, au lieu de l'écran gris
/// silencieux de Flutter en release (v1.0.1).
class _DisplayErrorFallback extends StatelessWidget {
  const _DisplayErrorFallback();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline,
                size: 40, color: SeverityPalette.medium),
            const SizedBox(height: 16),
            Text(
              "Cette page n'a pas pu s'afficher.",
              style: theme.textTheme.titleMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              "L'erreur a été consignée dans le journal de l'application. "
              "Revenez à l'écran de lancement et réessayez.",
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 20),
            FilledButton.icon(
              onPressed: () {
                final state = context.read<AppState>();
                state.clearActiveScan();
                state.clearSelectedScan();
              },
              icon: const Icon(Icons.arrow_back, size: 18),
              label: const Text("Retour à l'écran de scan"),
            ),
          ],
        ),
      ),
    );
  }
}

class _StartupScreen extends StatelessWidget {
  const _StartupScreen();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [
                    theme.colorScheme.primary,
                    theme.colorScheme.tertiary,
                  ],
                ),
                borderRadius: BorderRadius.circular(18),
              ),
              child: Icon(Icons.shield_outlined,
                  size: 38, color: theme.colorScheme.onPrimary),
            ),
            const SizedBox(height: 24),
            Text('Malryx', style: theme.textTheme.headlineMedium),
            const SizedBox(height: 8),
            Text(
              'Démarrage du moteur d\'analyse…',
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 28),
            const SizedBox(
              width: 200,
              child: LinearProgressIndicator(),
            ),
          ],
        ),
      ),
    );
  }
}

class _StartupFailedScreen extends StatelessWidget {
  const _StartupFailedScreen({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final state = context.read<AppState>();
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 620),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.error_outline,
                    size: 48, color: SeverityPalette.critical),
                const SizedBox(height: 20),
                Text(
                  'Le moteur d\'analyse n\'a pas démarré',
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceContainerHighest,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: SelectableText(
                    message,
                    style: const TextStyle(
                        fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: state.initialize,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Réessayer'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
