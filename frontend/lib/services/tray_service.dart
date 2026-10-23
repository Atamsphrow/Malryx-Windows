import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:tray_manager/tray_manager.dart';

/// Icone de la zone de notification Windows (tray) et son menu.
///
/// Volontairement simple : Ouvrir, deux scans rapides, l'etat de la
/// quarantaine n'y est pas duplique (l'application le montre mieux).
/// Les actions sont branchees par l'ecran principal via des callbacks,
/// ce service ne connait rien de l'etat de l'application.
///
/// Windows uniquement ; tout echec est silencieux (le tray est un
/// confort, pas une fonction de protection).
class TrayService with TrayListener {
  TrayService({
    required this.onOpen,
    required this.onSmartScan,
    required this.onStartupScan,
    required this.onQuit,
  });

  final VoidCallback onOpen;
  final VoidCallback onSmartScan;
  final VoidCallback onStartupScan;
  final VoidCallback onQuit;

  bool _initialized = false;

  Future<void> initialize() async {
    if (_initialized || !Platform.isWindows) return;
    try {
      await trayManager.setIcon('windows/runner/resources/app_icon.ico');
      await trayManager.setToolTip('Malryx — protection antivirus');
      await trayManager.setContextMenu(
        Menu(
          items: [
            MenuItem(key: 'open', label: 'Ouvrir Malryx'),
            MenuItem.separator(),
            MenuItem(key: 'smart', label: 'Scan intelligent'),
            MenuItem(key: 'startup', label: 'Points de demarrage'),
            MenuItem.separator(),
            MenuItem(key: 'quit', label: 'Quitter'),
          ],
        ),
      );
      trayManager.addListener(this);
      _initialized = true;
    } catch (_) {
      // Tray indisponible (session distante, Politique...) : on continue
      // sans lui, l'application reste pleinement utilisable.
    }
  }

  @override
  void onTrayIconMouseDown() {
    onOpen();
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
        onOpen();
      case 'smart':
        onSmartScan();
      case 'startup':
        onStartupScan();
      case 'quit':
        onQuit();
    }
  }

  Future<void> dispose() async {
    if (!_initialized) return;
    try {
      trayManager.removeListener(this);
      await trayManager.destroy();
    } catch (_) {}
    _initialized = false;
  }
}
