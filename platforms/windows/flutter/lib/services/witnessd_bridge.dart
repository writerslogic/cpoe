import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as path;

import '../models/witness_status.dart';

/// Bridge to communicate with the witnessd CLI executable
class WitnessdBridge {
  late final String _witnessdPath;
  late final String _dataDirectory;

  WitnessdBridge() {
    _initializePaths();
  }

  void _initializePaths() {
    // Find witnessd executable
    _witnessdPath = _findWitnessdPath();

    // Determine data directory
    final appData = Platform.environment['APPDATA'] ?? '';
    if (appData.isNotEmpty) {
      _dataDirectory = path.join(appData, 'Witnessd');
    } else {
      _dataDirectory = path.join(
        Platform.environment['USERPROFILE'] ?? 'C:\\Users\\Default',
        '.witnessd',
      );
    }

    // Ensure directory exists
    final dir = Directory(_dataDirectory);
    if (!dir.existsSync()) {
      dir.createSync(recursive: true);
    }
  }

  String _findWitnessdPath() {
    // Try various locations for the witnessd executable
    final execPath = Platform.resolvedExecutable;
    final execDir = path.dirname(execPath);

    final possiblePaths = [
      path.join(execDir, 'witnessd.exe'),
      path.join(execDir, '..', 'witnessd.exe'),
      'witnessd.exe', // PATH lookup
      path.join(Platform.environment['PROGRAMFILES'] ?? '', 'Witnessd', 'witnessd.exe'),
      path.join(Platform.environment['LOCALAPPDATA'] ?? '', 'Witnessd', 'witnessd.exe'),
    ];

    for (final p in possiblePaths) {
      if (File(p).existsSync()) {
        return p;
      }
    }

    // Default to expecting it in PATH
    return 'witnessd.exe';
  }

  /// Get the data directory path
  String get dataDirectoryPath => _dataDirectory;

  // MARK: - Commands

  /// Initialize witnessd
  Future<CommandResult> initialize() async {
    return _runCommand(['init']);
  }

  /// Calibrate VDF
  Future<CommandResult> calibrate() async {
    return _runCommand(['calibrate']);
  }

  /// Commit a checkpoint
  Future<CommandResult> commit(String filePath, {String message = ''}) async {
    final args = ['commit', filePath];
    if (message.isNotEmpty) {
      args.addAll(['-m', message]);
    }
    return _runCommand(args);
  }

  /// Get log for a file
  Future<CommandResult> log(String filePath) async {
    return _runCommand(['log', filePath]);
  }

  /// Export evidence
  Future<CommandResult> export(
    String filePath, {
    required String tier,
    required String outputPath,
  }) async {
    return _runCommand(['export', filePath, '-tier', tier, '-o', outputPath]);
  }

  /// Verify evidence file
  Future<CommandResult> verify(String filePath) async {
    return _runCommand(['verify', filePath]);
  }

  /// List tracked files
  Future<CommandResult> list() async {
    return _runCommand(['list']);
  }

  // MARK: - Sentinel Commands

  /// Start the sentinel
  Future<CommandResult> sentinelStart() async {
    return _runCommand(['sentinel', 'start']);
  }

  /// Stop the sentinel
  Future<CommandResult> sentinelStop() async {
    return _runCommand(['sentinel', 'stop']);
  }

  /// Get sentinel status
  Future<SentinelStatus> getSentinelStatus() async {
    var status = const SentinelStatus();

    final result = await _runCommand(['sentinel', 'status']);
    if (result.success) {
      final output = result.message;

      // Check if running
      if (output.contains('RUNNING')) {
        status = status.copyWith(isRunning: true);

        // Parse PID
        final pidMatch = RegExp(r'PID (\d+)').firstMatch(output);
        if (pidMatch != null) {
          status = status.copyWith(pid: int.tryParse(pidMatch.group(1) ?? '0') ?? 0);
        }

        // Parse uptime
        final uptimeMatch = RegExp(r'Uptime: (.+)').firstMatch(output);
        if (uptimeMatch != null) {
          status = status.copyWith(uptime: uptimeMatch.group(1)?.trim() ?? '');
        }
      }
    }

    // Get database stats for tracked documents count
    final statusResult = await _runCommand(['status']);
    if (statusResult.success) {
      final match = RegExp(r'Files tracked: (\d+)').firstMatch(statusResult.message);
      if (match != null) {
        status = status.copyWith(
          trackedDocuments: int.tryParse(match.group(1) ?? '0') ?? 0,
        );
      }
    }

    return status;
  }

  /// Start tracking a document
  Future<CommandResult> startTracking(String documentPath) async {
    return _runCommand(['track', 'start', documentPath]);
  }

  /// Stop tracking
  Future<CommandResult> stopTracking() async {
    return _runCommand(['track', 'stop']);
  }

  /// Get overall status
  Future<WitnessStatus> getStatus() async {
    var status = const WitnessStatus();

    // Check if initialized by running status command
    final result = await _runCommand(['status']);

    if (result.success) {
      final output = result.message;

      // Parse the output to extract status information
      status = status.copyWith(
        isInitialized: output.contains('Data directory:'),
      );

      // Check VDF calibration
      final vdfMatch = RegExp(r'VDF iterations/sec: (\d+)').firstMatch(output);
      if (vdfMatch != null) {
        status = status.copyWith(
          vdfIterPerSec: vdfMatch.group(1) ?? '',
          vdfCalibrated: true,
        );
      }

      // Check TPM
      if (output.contains('TPM: available')) {
        status = status.copyWith(tpmAvailable: true);
        final tpmMatch = RegExp(r'TPM: available \(([^)]+)\)').firstMatch(output);
        if (tpmMatch != null) {
          status = status.copyWith(tpmInfo: tpmMatch.group(1) ?? '');
        }
      }

      // Check database stats
      final eventsMatch = RegExp(r'Events: (\d+)').firstMatch(output);
      if (eventsMatch != null) {
        status = status.copyWith(
          databaseEvents: int.tryParse(eventsMatch.group(1) ?? '0') ?? 0,
        );
      }

      final filesMatch = RegExp(r'Files tracked: (\d+)').firstMatch(output);
      if (filesMatch != null) {
        status = status.copyWith(
          databaseFiles: int.tryParse(filesMatch.group(1) ?? '0') ?? 0,
        );
      }
    }

    // Check tracking status separately
    final trackResult = await _runCommand(['track', 'status']);
    if (trackResult.success && trackResult.message.contains('Active Tracking Session')) {
      status = status.copyWith(isTracking: true);

      // Parse tracking info
      final docMatch = RegExp(r'Document: (.+)').firstMatch(trackResult.message);
      if (docMatch != null) {
        status = status.copyWith(trackingDocument: docMatch.group(1)?.trim());
      }

      final keystrokesMatch = RegExp(r'Keystrokes: (\d+)').firstMatch(trackResult.message);
      if (keystrokesMatch != null) {
        status = status.copyWith(
          keystrokeCount: int.tryParse(keystrokesMatch.group(1) ?? '0') ?? 0,
        );
      }

      final durationMatch = RegExp(r'Duration: (.+)').firstMatch(trackResult.message);
      if (durationMatch != null) {
        status = status.copyWith(trackingDuration: durationMatch.group(1)?.trim() ?? '');
      }
    }

    return status;
  }

  /// List tracked files with details
  Future<List<TrackedFile>> listTrackedFiles() async {
    final result = await _runCommand(['list', '--json']);
    if (!result.success) {
      return [];
    }

    try {
      final List<dynamic> files = jsonDecode(result.message);
      return files.map((f) => TrackedFile.fromJson(f as Map<String, dynamic>)).toList();
    } catch (e) {
      // If JSON parsing fails, try parsing the text output
      return _parseTrackedFilesFromText(result.message);
    }
  }

  List<TrackedFile> _parseTrackedFilesFromText(String output) {
    final files = <TrackedFile>[];
    final lines = output.split('\n').where((l) => l.trim().isNotEmpty);

    for (final line in lines) {
      // Try to parse lines like "  path/to/file.txt (42 events)"
      final match = RegExp(r'^\s*(.+?)\s+\((\d+)\s+events?\)').firstMatch(line);
      if (match != null) {
        final filePath = match.group(1)?.trim() ?? '';
        final events = int.tryParse(match.group(2) ?? '0') ?? 0;

        files.add(TrackedFile(
          id: filePath.hashCode.toString(),
          name: path.basename(filePath),
          path: filePath,
          events: events,
        ));
      }
    }

    return files;
  }

  // MARK: - Private

  /// Strip ANSI escape codes from output
  String _stripAnsiCodes(String input) {
    return input.replaceAll(RegExp(r'\x1B\[[0-9;]*[a-zA-Z]'), '');
  }

  /// Run a witnessd command
  Future<CommandResult> _runCommand(List<String> arguments) async {
    try {
      final process = await Process.start(
        _witnessdPath,
        arguments,
        environment: {
          ...Platform.environment,
          'WITNESSD_DATA_DIR': _dataDirectory,
        },
        runInShell: false,
      );

      final stdout = await process.stdout.transform(utf8.decoder).join();
      final stderr = await process.stderr.transform(utf8.decoder).join();
      final exitCode = await process.exitCode;

      final success = exitCode == 0;
      var message = stdout;
      if (!success && stderr.isNotEmpty) {
        message = stderr;
      }

      // Clean up ANSI codes
      message = _stripAnsiCodes(message).trim();

      return CommandResult(
        success: success,
        message: message,
        exitCode: exitCode,
      );
    } catch (e) {
      return CommandResult(
        success: false,
        message: 'Failed to run witnessd: $e',
        exitCode: -1,
      );
    }
  }
}
