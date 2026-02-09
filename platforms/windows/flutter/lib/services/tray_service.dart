import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:system_tray/system_tray.dart';
import 'package:window_manager/window_manager.dart';
import 'package:path/path.dart' as path;

import 'witnessd_service.dart';

/// System tray service provider
final trayServiceProvider =
    StateNotifierProvider<TrayServiceNotifier, TrayState>((ref) {
  return TrayServiceNotifier(ref);
});

/// State for the tray service
class TrayState {
  final bool isInitialized;
  final bool isVisible;
  final String tooltip;

  const TrayState({
    this.isInitialized = false,
    this.isVisible = false,
    this.tooltip = 'Witnessd',
  });

  TrayState copyWith({
    bool? isInitialized,
    bool? isVisible,
    String? tooltip,
  }) {
    return TrayState(
      isInitialized: isInitialized ?? this.isInitialized,
      isVisible: isVisible ?? this.isVisible,
      tooltip: tooltip ?? this.tooltip,
    );
  }
}

/// Manages the system tray icon and menu
class TrayServiceNotifier extends StateNotifier<TrayState> {
  final Ref _ref;
  final SystemTray _systemTray = SystemTray();
  Timer? _updateTimer;

  TrayServiceNotifier(this._ref) : super(const TrayState());

  /// Initialize the system tray
  Future<void> initialize() async {
    // Find the icon path
    final iconPath = await _getIconPath();

    // Initialize the system tray
    await _systemTray.initSystemTray(
      title: 'Witnessd',
      iconPath: iconPath,
      toolTip: 'Witnessd: Initializing...',
    );

    // Build the context menu
    await _buildContextMenu();

    // Register click handler
    _systemTray.registerSystemTrayEventHandler((eventName) {
      if (eventName == kSystemTrayEventClick) {
        _showWindow();
      } else if (eventName == kSystemTrayEventRightClick) {
        _systemTray.popUpContextMenu();
      }
    });

    state = state.copyWith(isInitialized: true);

    // Start periodic status updates
    _startUpdateTimer();
  }

  Future<String> _getIconPath() async {
    // Try to find icon relative to executable
    final execPath = Platform.resolvedExecutable;
    final execDir = path.dirname(execPath);

    // Check for icon in various locations
    final possiblePaths = [
      path.join(execDir, 'data', 'flutter_assets', 'assets', 'icons', 'witnessd.ico'),
      path.join(execDir, 'assets', 'icons', 'witnessd.ico'),
      path.join(execDir, 'witnessd.ico'),
    ];

    for (final iconPath in possiblePaths) {
      if (File(iconPath).existsSync()) {
        return iconPath;
      }
    }

    // Fallback - return the first path even if it doesn't exist
    // The system_tray package will handle missing icons gracefully
    return possiblePaths.first;
  }

  /// Build the tray context menu
  Future<void> _buildContextMenu() async {
    final witnessdState = _ref.read(witnessdServiceProvider);

    final menu = Menu();

    // Status header (disabled)
    String statusText;
    if (witnessdState.sentinelStatus.isRunning) {
      final docCount = witnessdState.sentinelStatus.trackedDocuments;
      statusText = 'Sentinel Active - $docCount document${docCount == 1 ? '' : 's'}';
    } else if (witnessdState.status.isInitialized) {
      statusText = 'Sentinel Stopped';
    } else {
      statusText = 'Not Initialized';
    }

    await menu.buildFrom([
      MenuItemLabel(
        label: statusText,
        enabled: false,
      ),
      MenuSeparator(),

      // Start/Stop Sentinel
      if (witnessdState.sentinelStatus.isRunning)
        MenuItemLabel(
          label: 'Stop Sentinel',
          onClicked: (item) => _stopSentinel(),
        )
      else if (witnessdState.status.isInitialized)
        MenuItemLabel(
          label: 'Start Sentinel',
          onClicked: (item) => _startSentinel(),
        ),

      MenuSeparator(),

      // Show window
      MenuItemLabel(
        label: 'Open Witnessd',
        onClicked: (item) => _showWindow(),
      ),

      // Settings
      MenuItemLabel(
        label: 'Settings...',
        onClicked: (item) => _openSettings(),
      ),

      MenuSeparator(),

      // Exit
      MenuItemLabel(
        label: 'Exit',
        onClicked: (item) => _exit(),
      ),
    ]);

    await _systemTray.setContextMenu(menu);
  }

  /// Update tray tooltip based on current status
  void _updateTooltip() {
    final witnessdState = _ref.read(witnessdServiceProvider);

    String tooltip;
    if (witnessdState.sentinelStatus.isRunning) {
      final docCount = witnessdState.sentinelStatus.trackedDocuments;
      tooltip = 'Witnessd: Active ($docCount doc${docCount == 1 ? '' : 's'})';
    } else if (witnessdState.status.isInitialized) {
      tooltip = 'Witnessd: Ready';
    } else {
      tooltip = 'Witnessd: Not Initialized';
    }

    if (tooltip != state.tooltip) {
      _systemTray.setToolTip(tooltip);
      state = state.copyWith(tooltip: tooltip);
    }
  }

  void _startUpdateTimer() {
    _updateTimer?.cancel();
    _updateTimer = Timer.periodic(const Duration(seconds: 3), (_) {
      _updateTooltip();
      _buildContextMenu(); // Rebuild menu to reflect current state
    });
  }

  Future<void> _showWindow() async {
    await windowManager.show();
    await windowManager.focus();
    state = state.copyWith(isVisible: true);
  }

  Future<void> _hideWindow() async {
    await windowManager.hide();
    state = state.copyWith(isVisible: false);
  }

  Future<void> _startSentinel() async {
    await _ref.read(witnessdServiceProvider.notifier).startSentinel();
    await _buildContextMenu();
    _updateTooltip();
  }

  Future<void> _stopSentinel() async {
    await _ref.read(witnessdServiceProvider.notifier).stopSentinel();
    await _buildContextMenu();
    _updateTooltip();
  }

  Future<void> _openSettings() async {
    await _showWindow();
    // Navigation to settings will be handled by the UI
  }

  Future<void> _exit() async {
    _updateTimer?.cancel();
    await _systemTray.destroy();
    exit(0);
  }

  @override
  void dispose() {
    _updateTimer?.cancel();
    _systemTray.destroy();
    super.dispose();
  }
}
