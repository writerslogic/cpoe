import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

import '../services/tray_service.dart';
import '../services/witnessd_service.dart';
import '../screens/main_screen.dart';
import '../theme/windows_theme.dart';

class WitnessdApp extends ConsumerStatefulWidget {
  const WitnessdApp({super.key});

  @override
  ConsumerState<WitnessdApp> createState() => _WitnessdAppState();
}

class _WitnessdAppState extends ConsumerState<WitnessdApp> with WindowListener {
  @override
  void initState() {
    super.initState();
    windowManager.addListener(this);
    _initializeServices();
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  Future<void> _initializeServices() async {
    // Initialize the tray service
    await ref.read(trayServiceProvider.notifier).initialize();

    // Initialize witnessd service and get initial status
    await ref.read(witnessdServiceProvider.notifier).initialize();
  }

  @override
  void onWindowClose() async {
    // Hide to tray instead of closing
    await windowManager.hide();
  }

  @override
  void onWindowFocus() {
    // Refresh status when window gains focus
    ref.read(witnessdServiceProvider.notifier).refreshStatus();
  }

  @override
  Widget build(BuildContext context) {
    return FluentApp(
      title: 'Witnessd',
      debugShowCheckedModeBanner: false,
      theme: WindowsTheme.lightTheme,
      darkTheme: WindowsTheme.darkTheme,
      themeMode: ThemeMode.system,
      home: const MainScreen(),
    );
  }
}
