import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';
import 'engine_controller.dart';

class TrayService with TrayListener {
  final EngineController engine;
  String? _activeIconPath;
  String? _pausedIconPath;

  TrayService(this.engine);

  Future<void> init() async {
    trayManager.addListener(this);
    await _prepareIcons();
    _syncTray();
    engine.addListener(_syncTray);
  }

  Future<void> _prepareIcons() async {
    _activeIconPath = 'assets/icons/tray_active.png';
    _pausedIconPath = 'assets/icons/tray_paused.png';
  }

  void _syncTray() {
    final iconPath = engine.isRunning ? _activeIconPath : _pausedIconPath;
    final tooltip = switch (engine.phase) {
      EnginePhase.running => 'Witnessd: Running',
      EnginePhase.paused => 'Witnessd: Paused',
      EnginePhase.needsPermission => 'Witnessd: Needs Accessibility',
      EnginePhase.error => 'Witnessd: Error',
      EnginePhase.starting => 'Witnessd: Starting',
    };
    if (iconPath != null) {
      trayManager.setIcon(iconPath).catchError((_) {});
    }
    trayManager.setToolTip(tooltip);
    trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(key: 'open', label: 'Open Witnessd'),
          MenuItem(key: 'toggle', label: engine.isRunning ? 'Pause' : 'Resume'),
          MenuItem.separator(),
          MenuItem(key: 'quit', label: 'Quit'),
        ],
      ),
    );
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    switch (menuItem.key) {
      case 'open':
        await windowManager.show();
        await windowManager.focus();
        break;
      case 'toggle':
        await engine.toggle();
        break;
      case 'quit':
        await engine.stop();
        await windowManager.destroy();
        break;
    }
  }

  @override
  void onTrayIconMouseDown() async {
    await windowManager.show();
    await windowManager.focus();
  }
}
