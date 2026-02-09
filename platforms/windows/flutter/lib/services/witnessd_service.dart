import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/witness_status.dart';
import '../models/settings.dart';
import 'witnessd_bridge.dart';

/// Main witnessd service provider
final witnessdServiceProvider =
    StateNotifierProvider<WitnessdServiceNotifier, WitnessdState>((ref) {
  return WitnessdServiceNotifier();
});

/// Overall application state
class WitnessdState {
  final WitnessStatus status;
  final SentinelStatus sentinelStatus;
  final bool isLoading;
  final String loadingMessage;
  final String? lastError;
  final List<TrackedFile> trackedFiles;

  const WitnessdState({
    this.status = const WitnessStatus(),
    this.sentinelStatus = const SentinelStatus(),
    this.isLoading = false,
    this.loadingMessage = '',
    this.lastError,
    this.trackedFiles = const [],
  });

  WitnessdState copyWith({
    WitnessStatus? status,
    SentinelStatus? sentinelStatus,
    bool? isLoading,
    String? loadingMessage,
    String? lastError,
    List<TrackedFile>? trackedFiles,
  }) {
    return WitnessdState(
      status: status ?? this.status,
      sentinelStatus: sentinelStatus ?? this.sentinelStatus,
      isLoading: isLoading ?? this.isLoading,
      loadingMessage: loadingMessage ?? this.loadingMessage,
      lastError: lastError,
      trackedFiles: trackedFiles ?? this.trackedFiles,
    );
  }
}

/// Manages all witnessd operations
class WitnessdServiceNotifier extends StateNotifier<WitnessdState> {
  final WitnessdBridge _bridge = WitnessdBridge();
  Timer? _statusTimer;
  WitnessdSettings? _settings;

  WitnessdServiceNotifier() : super(const WitnessdState());

  /// Initialize the service
  Future<void> initialize() async {
    _settings = await SettingsProvider.getInstance();
    await refreshStatus();
    _startStatusPolling();
  }

  void _startStatusPolling() {
    _statusTimer?.cancel();
    _statusTimer = Timer.periodic(const Duration(seconds: 3), (_) {
      refreshStatus();
    });
  }

  /// Refresh all status information
  Future<void> refreshStatus() async {
    final status = await _bridge.getStatus();
    final sentinelStatus = await _bridge.getSentinelStatus();

    state = state.copyWith(
      status: status,
      sentinelStatus: sentinelStatus,
    );
  }

  /// Initialize witnessd
  Future<CommandResult> initializeWitnessd() async {
    _setLoading(true, 'Creating keys...');

    final result = await _bridge.initialize();

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Calibrate VDF
  Future<CommandResult> calibrate() async {
    _setLoading(true, 'Calibrating VDF...');

    final result = await _bridge.calibrate();

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Start the sentinel
  Future<CommandResult> startSentinel() async {
    _setLoading(true, 'Starting sentinel...');

    final result = await _bridge.sentinelStart();

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Stop the sentinel
  Future<CommandResult> stopSentinel() async {
    _setLoading(true, 'Stopping sentinel...');

    final result = await _bridge.sentinelStop();

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Start tracking a document
  Future<CommandResult> startTracking(String documentPath) async {
    _setLoading(true, 'Starting tracking...');

    final result = await _bridge.startTracking(documentPath);

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Stop tracking
  Future<CommandResult> stopTracking() async {
    _setLoading(true, 'Stopping tracking...');

    // Create final checkpoint if tracking
    if (state.status.trackingDocument != null) {
      await _bridge.commit(
        state.status.trackingDocument!,
        message: 'Session ended',
      );
    }

    final result = await _bridge.stopTracking();

    _setLoading(false);

    if (result.success) {
      await refreshStatus();
    } else {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Create a checkpoint
  Future<CommandResult> createCheckpoint({String message = ''}) async {
    final trackingDoc = state.status.trackingDocument;
    if (trackingDoc == null) {
      return CommandResult.failure('No active tracking session');
    }

    _setLoading(true, 'Creating checkpoint...');

    final result = await _bridge.commit(trackingDoc, message: message);

    _setLoading(false);

    if (!result.success) {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Export evidence
  Future<CommandResult> export({
    required String filePath,
    required String tier,
    required String outputPath,
  }) async {
    _setLoading(true, 'Exporting evidence...');

    final result = await _bridge.export(
      filePath,
      tier: tier,
      outputPath: outputPath,
    );

    _setLoading(false);

    if (!result.success) {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Verify evidence
  Future<CommandResult> verify(String filePath) async {
    _setLoading(true, 'Verifying evidence...');

    final result = await _bridge.verify(filePath);

    _setLoading(false);

    if (!result.success) {
      state = state.copyWith(lastError: result.message);
    }

    return result;
  }

  /// Get log for a file
  Future<CommandResult> getLog(String filePath) async {
    return _bridge.log(filePath);
  }

  /// Load tracked files
  Future<void> loadTrackedFiles() async {
    final files = await _bridge.listTrackedFiles();
    state = state.copyWith(trackedFiles: files);
  }

  /// Clear error
  void clearError() {
    state = state.copyWith(lastError: null);
  }

  /// Get the data directory path
  String get dataDirectoryPath => _bridge.dataDirectoryPath;

  /// Get settings
  WitnessdSettings? get settings => _settings;

  void _setLoading(bool loading, [String message = '']) {
    state = state.copyWith(
      isLoading: loading,
      loadingMessage: loading ? message : '',
      lastError: loading ? null : state.lastError,
    );
  }

  @override
  void dispose() {
    _statusTimer?.cancel();
    super.dispose();
  }
}
