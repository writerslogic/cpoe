import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:fluent_ui/fluent_ui.dart' as fluent;
import 'package:window_manager/window_manager.dart';
import 'package:system_tray/system_tray.dart';

import 'app/app.dart';
import 'services/tray_service.dart';
import 'services/witnessd_service.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize window manager for Windows-specific behavior
  await windowManager.ensureInitialized();

  // Configure window options
  WindowOptions windowOptions = const WindowOptions(
    size: Size(400, 520),
    minimumSize: Size(380, 480),
    center: true,
    backgroundColor: Colors.transparent,
    skipTaskbar: true, // Hide from taskbar (tray app)
    titleBarStyle: TitleBarStyle.hidden,
    windowButtonVisibility: false,
  );

  await windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.hide(); // Start hidden, show from tray
  });

  runApp(
    const ProviderScope(
      child: WitnessdApp(),
    ),
  );
}
