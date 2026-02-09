import 'package:shared_preferences/shared_preferences.dart';

/// Application settings stored in shared preferences
class WitnessdSettings {
  final SharedPreferences _prefs;

  WitnessdSettings(this._prefs);

  // Watch paths
  List<String> get watchPaths =>
      _prefs.getStringList('watchPaths') ?? [];

  Future<void> setWatchPaths(List<String> paths) =>
      _prefs.setStringList('watchPaths', paths);

  Future<void> addWatchPath(String path) async {
    final paths = watchPaths;
    if (!paths.contains(path)) {
      paths.add(path);
      await setWatchPaths(paths);
    }
  }

  Future<void> removeWatchPath(String path) async {
    final paths = watchPaths;
    paths.remove(path);
    await setWatchPaths(paths);
  }

  // Include patterns
  List<String> get includePatterns =>
      _prefs.getStringList('includePatterns') ??
      ['.txt', '.md', '.rtf', '.doc', '.docx'];

  Future<void> setIncludePatterns(List<String> patterns) =>
      _prefs.setStringList('includePatterns', patterns);

  Future<void> addIncludePattern(String pattern) async {
    final normalized = pattern.startsWith('.') ? pattern : '.$pattern';
    final patterns = includePatterns;
    if (!patterns.contains(normalized)) {
      patterns.add(normalized);
      await setIncludePatterns(patterns);
    }
  }

  Future<void> removeIncludePattern(String pattern) async {
    final patterns = includePatterns;
    patterns.remove(pattern);
    await setIncludePatterns(patterns);
  }

  // Debounce interval
  int get debounceIntervalMs => _prefs.getInt('debounceIntervalMs') ?? 500;
  Future<void> setDebounceIntervalMs(int ms) =>
      _prefs.setInt('debounceIntervalMs', ms);

  // Signing key path
  String get signingKeyPath => _prefs.getString('signingKeyPath') ?? '';
  Future<void> setSigningKeyPath(String path) =>
      _prefs.setString('signingKeyPath', path);

  // TPM attestation
  bool get tpmAttestationEnabled =>
      _prefs.getBool('tpmAttestationEnabled') ?? false;
  Future<void> setTpmAttestationEnabled(bool enabled) =>
      _prefs.setBool('tpmAttestationEnabled', enabled);

  // Auto-checkpoint
  bool get autoCheckpoint => _prefs.getBool('autoCheckpoint') ?? false;
  Future<void> setAutoCheckpoint(bool enabled) =>
      _prefs.setBool('autoCheckpoint', enabled);

  int get checkpointIntervalMinutes =>
      _prefs.getInt('checkpointIntervalMinutes') ?? 30;
  Future<void> setCheckpointIntervalMinutes(int minutes) =>
      _prefs.setInt('checkpointIntervalMinutes', minutes);

  // Export defaults
  String get defaultExportFormat =>
      _prefs.getString('defaultExportFormat') ?? 'json';
  Future<void> setDefaultExportFormat(String format) =>
      _prefs.setString('defaultExportFormat', format);

  String get defaultExportTier =>
      _prefs.getString('defaultExportTier') ?? 'standard';
  Future<void> setDefaultExportTier(String tier) =>
      _prefs.setString('defaultExportTier', tier);

  // Launch at login
  bool get openAtLogin => _prefs.getBool('openAtLogin') ?? false;
  Future<void> setOpenAtLogin(bool enabled) =>
      _prefs.setBool('openAtLogin', enabled);

  // Notifications
  bool get showNotifications => _prefs.getBool('showNotifications') ?? true;
  Future<void> setShowNotifications(bool enabled) =>
      _prefs.setBool('showNotifications', enabled);

  // First launch
  bool get hasLaunchedBefore => _prefs.getBool('hasLaunchedBefore') ?? false;
  Future<void> setHasLaunchedBefore(bool launched) =>
      _prefs.setBool('hasLaunchedBefore', launched);
}

/// Provider for settings
class SettingsProvider {
  static WitnessdSettings? _instance;

  static Future<WitnessdSettings> getInstance() async {
    if (_instance == null) {
      final prefs = await SharedPreferences.getInstance();
      _instance = WitnessdSettings(prefs);
    }
    return _instance!;
  }
}
