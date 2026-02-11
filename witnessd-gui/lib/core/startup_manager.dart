import 'dart:io';
import 'package:launch_at_startup/launch_at_startup.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/services.dart';

class StartupManager {
  static const _prefsKey = 'start_at_login';
  static bool _supported = true;

  static Future<void> init() async {
    try {
      launchAtStartup.setup(
        appName: 'Witnessd',
        appPath: Platform.resolvedExecutable,
      );
    } catch (_) {
      _supported = false;
    }

    final prefs = await SharedPreferences.getInstance();
    final enabled = prefs.getBool(_prefsKey) ?? true;
    if (enabled) {
      await enable();
    }
  }

  static Future<bool> isEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_prefsKey) ?? true;
  }

  static Future<void> enable() async {
    try {
      await launchAtStartup.enable();
    } on MissingPluginException {
      _supported = false;
    }
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_prefsKey, true);
  }

  static Future<void> disable() async {
    try {
      await launchAtStartup.disable();
    } on MissingPluginException {
      _supported = false;
    }
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_prefsKey, false);
  }

  static bool get isSupported => _supported;
}
