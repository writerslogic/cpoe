import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';
import 'app_state.dart';
import 'startup_manager.dart';

class WindowHandler with WindowListener {
  Future<void> init({bool startHidden = true}) async {
    await windowManager.setPreventClose(true);
    await windowManager.setMinimumSize(const Size(320, 340));
    await windowManager.setSize(const Size(340, 380));
    await windowManager.center();
    windowManager.addListener(this);
    if (startHidden) {
      await windowManager.hide();
    }
  }

  @override
  void onWindowClose() async {
    final context = AppState.navigatorKey.currentContext;
    if (context == null) {
      await windowManager.hide();
      return;
    }

    bool startAtLogin = await StartupManager.isEnabled();
    final result = await showDialog<bool>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text('Keep Witnessd Running?'),
          content: StatefulBuilder(
            builder: (ctx, setState) {
              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text(
                    'Witnessd runs in the menu bar to preserve your proof-of-process timeline. You can pause it anytime from the tray icon.',
                  ),
                  const SizedBox(height: 16),
                  CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    value: startAtLogin,
                    onChanged: (value) {
                      setState(() => startAtLogin = value ?? true);
                    },
                    title: const Text('Reopen at login'),
                  ),
                ],
              );
            },
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(false),
              child: const Text('Quit'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              child: const Text('Keep Running'),
            ),
          ],
        );
      },
    );

    if (startAtLogin) {
      await StartupManager.enable();
    } else {
      await StartupManager.disable();
    }

    if (result == true) {
      await windowManager.hide();
    } else {
      await windowManager.destroy();
    }
  }
}
