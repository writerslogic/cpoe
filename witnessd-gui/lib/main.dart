import 'dart:io';
import 'package:flutter/material.dart';
import 'ui/theme.dart';
import 'ui/screens/permission_gate.dart';
import 'frb_generated.dart';
import 'core/app_state.dart';
import 'core/tray_service.dart';
import 'core/startup_manager.dart';
import 'core/window_handler.dart';
import 'core/rust_loader.dart';
import 'package:window_manager/window_manager.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  String? initError;
  try {
    final lib = tryLoadRustLibrary();
    if (lib == null) {
      initError = 'Failed to load Rust library - no library found';
    } else {
      await RustLib.init(externalLibrary: lib);
    }
  } catch (e) {
    initError = 'Failed to initialize Rust library: $e';
  }

  await windowManager.ensureInitialized();

  if (initError == null) {
    try {
      await AppState.engine.init();
    } catch (e) {
      initError = 'Failed to initialize engine: $e';
    }
  }

  AppState.windowHandler = WindowHandler();
  await AppState.windowHandler.init(startHidden: true);
  AppState.tray = TrayService(AppState.engine);
  await AppState.tray.init();
  final initialTab = _resolveInitialTab(Platform.executableArguments);
  runApp(WitnessdApp(initialTab: initialTab, initError: initError));
  WidgetsBinding.instance.addPostFrameCallback((_) async {
    await StartupManager.init();
  });
}

class WitnessdApp extends StatelessWidget {
  const WitnessdApp({super.key, this.initialTab, this.initError});

  final int? initialTab;
  final String? initError;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Witnessd',
      debugShowCheckedModeBanner: false,
      navigatorKey: AppState.navigatorKey,
      theme: WitnessdTheme.dark,
      home: initError != null
          ? _ErrorScreen(error: initError!)
          : PermissionGate(initialTab: initialTab),
    );
  }
}

class _ErrorScreen extends StatelessWidget {
  const _ErrorScreen({required this.error});
  final String error;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: WitnessdTheme.darkBackground,
      body: Center(
        child: Container(
          width: 500,
          padding: const EdgeInsets.all(32),
          decoration: BoxDecoration(
            color: WitnessdTheme.surface,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: WitnessdTheme.warningRed.withOpacity(0.3),
            ),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(
                Icons.error_outline,
                size: 48,
                color: WitnessdTheme.warningRed,
              ),
              const SizedBox(height: 16),
              const Text(
                'Initialization Error',
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: WitnessdTheme.strongText,
                ),
              ),
              const SizedBox(height: 12),
              Text(
                error,
                textAlign: TextAlign.center,
                style: const TextStyle(color: WitnessdTheme.mutedText),
              ),
              const SizedBox(height: 24),
              ElevatedButton(
                onPressed: () => exit(1),
                child: const Text('Quit'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

int? _resolveInitialTab(List<String> args) {
  for (final arg in args) {
    if (arg.startsWith('--route=')) {
      final route = arg.substring('--route='.length).toLowerCase();
      switch (route) {
        case 'reports':
        case 'document_log':
        case 'documents':
          return 1;
        case 'forensics':
          return 2;
        case 'preferences':
        case 'settings':
          return 3;
        case 'dashboard':
        default:
          return 0;
      }
    }
  }
  return null;
}
