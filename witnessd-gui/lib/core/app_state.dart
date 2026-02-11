import 'package:flutter/material.dart';
import 'engine_controller.dart';
import 'tray_service.dart';
import 'window_handler.dart';

class AppState {
  static final navigatorKey = GlobalKey<NavigatorState>();
  static final engine = EngineController();
  static late final TrayService tray;
  static late final WindowHandler windowHandler;
}
