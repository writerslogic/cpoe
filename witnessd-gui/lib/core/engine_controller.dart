import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../bridge.dart';

enum EnginePhase { starting, running, paused, needsPermission, error }

class EngineController extends ChangeNotifier {
  static const _pausePrefsKey = 'engine_paused';
  EnginePhase _phase = EnginePhase.needsPermission;
  String? _lastError;

  EnginePhase get phase => _phase;
  String? get lastError => _lastError;
  bool get isRunning => _phase == EnginePhase.running;

  Future<void> init() async {
    final prefs = await SharedPreferences.getInstance();
    final paused = prefs.getBool(_pausePrefsKey) ?? false;
    if (paused) {
      _phase = EnginePhase.paused;
      notifyListeners();
    }
  }

  Future<void> start() async {
    if (_phase == EnginePhase.running || _phase == EnginePhase.starting) {
      return;
    }
    _phase = EnginePhase.starting;
    _lastError = null;
    notifyListeners();
    try {
      await startEngine();
      _phase = EnginePhase.running;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(_pausePrefsKey, false);
    } catch (err) {
      final message = err.toString();
      if (message.toLowerCase().contains('accessibility')) {
        _phase = EnginePhase.needsPermission;
        _lastError = null;
      } else {
        _phase = EnginePhase.error;
        _lastError = message;
      }
    }
    notifyListeners();
  }

  Future<void> stop() async {
    try {
      await stopEngine();
      _phase = EnginePhase.paused;
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool(_pausePrefsKey, true);
    } catch (err) {
      _phase = EnginePhase.error;
      _lastError = err.toString();
    }
    notifyListeners();
  }

  Future<bool> checkPermission() async {
    final trusted = await accessibilityTrusted();
    final inputTrusted = await inputMonitoringTrusted();
    if ((!trusted || !inputTrusted) && _phase != EnginePhase.paused) {
      _phase = EnginePhase.needsPermission;
      notifyListeners();
    }
    return trusted && inputTrusted;
  }

  Future<bool> refreshPermission({bool prompt = false}) async {
    if (prompt) {
      await requestAccessibilityPermissions();
      await requestInputMonitoringPermissions();
      await Future.delayed(const Duration(milliseconds: 600));
      for (var i = 0; i < 10; i++) {
        final trusted = await accessibilityTrusted();
        final inputTrusted = await inputMonitoringTrusted();
        if (trusted && inputTrusted) break;
        await Future.delayed(const Duration(milliseconds: 400));
      }
    }
    final trusted = await accessibilityTrusted();
    final inputTrusted = await inputMonitoringTrusted();
    if (trusted && inputTrusted && _phase == EnginePhase.needsPermission) {
      final prefs = await SharedPreferences.getInstance();
      final paused = prefs.getBool(_pausePrefsKey) ?? false;
      if (paused) {
        _phase = EnginePhase.paused;
        notifyListeners();
      } else {
        await start();
      }
    }
    if ((!trusted || !inputTrusted) && _phase != EnginePhase.paused) {
      _phase = EnginePhase.needsPermission;
      notifyListeners();
    }
    return trusted && inputTrusted;
  }

  Future<void> toggle() async {
    if (isRunning) {
      await stop();
    } else {
      await refreshPermission(prompt: false);
      if (_phase == EnginePhase.needsPermission) return;
      await start();
    }
  }
}
