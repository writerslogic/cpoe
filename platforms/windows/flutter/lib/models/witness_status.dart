import 'package:json_annotation/json_annotation.dart';

part 'witness_status.g.dart';

/// Status information from witnessd CLI
@JsonSerializable()
class WitnessStatus {
  final bool isInitialized;
  final bool isTracking;
  final String? trackingDocument;
  final int keystrokeCount;
  final String trackingDuration;
  final bool vdfCalibrated;
  final String vdfIterPerSec;
  final bool tpmAvailable;
  final String tpmInfo;
  final int databaseEvents;
  final int databaseFiles;

  const WitnessStatus({
    this.isInitialized = false,
    this.isTracking = false,
    this.trackingDocument,
    this.keystrokeCount = 0,
    this.trackingDuration = '',
    this.vdfCalibrated = false,
    this.vdfIterPerSec = '',
    this.tpmAvailable = false,
    this.tpmInfo = '',
    this.databaseEvents = 0,
    this.databaseFiles = 0,
  });

  factory WitnessStatus.fromJson(Map<String, dynamic> json) =>
      _$WitnessStatusFromJson(json);

  Map<String, dynamic> toJson() => _$WitnessStatusToJson(this);

  WitnessStatus copyWith({
    bool? isInitialized,
    bool? isTracking,
    String? trackingDocument,
    int? keystrokeCount,
    String? trackingDuration,
    bool? vdfCalibrated,
    String? vdfIterPerSec,
    bool? tpmAvailable,
    String? tpmInfo,
    int? databaseEvents,
    int? databaseFiles,
  }) {
    return WitnessStatus(
      isInitialized: isInitialized ?? this.isInitialized,
      isTracking: isTracking ?? this.isTracking,
      trackingDocument: trackingDocument ?? this.trackingDocument,
      keystrokeCount: keystrokeCount ?? this.keystrokeCount,
      trackingDuration: trackingDuration ?? this.trackingDuration,
      vdfCalibrated: vdfCalibrated ?? this.vdfCalibrated,
      vdfIterPerSec: vdfIterPerSec ?? this.vdfIterPerSec,
      tpmAvailable: tpmAvailable ?? this.tpmAvailable,
      tpmInfo: tpmInfo ?? this.tpmInfo,
      databaseEvents: databaseEvents ?? this.databaseEvents,
      databaseFiles: databaseFiles ?? this.databaseFiles,
    );
  }
}

/// Sentinel status information
@JsonSerializable()
class SentinelStatus {
  final bool isRunning;
  final int pid;
  final String uptime;
  final int trackedDocuments;

  const SentinelStatus({
    this.isRunning = false,
    this.pid = 0,
    this.uptime = '',
    this.trackedDocuments = 0,
  });

  factory SentinelStatus.fromJson(Map<String, dynamic> json) =>
      _$SentinelStatusFromJson(json);

  Map<String, dynamic> toJson() => _$SentinelStatusToJson(this);

  SentinelStatus copyWith({
    bool? isRunning,
    int? pid,
    String? uptime,
    int? trackedDocuments,
  }) {
    return SentinelStatus(
      isRunning: isRunning ?? this.isRunning,
      pid: pid ?? this.pid,
      uptime: uptime ?? this.uptime,
      trackedDocuments: trackedDocuments ?? this.trackedDocuments,
    );
  }
}

/// Result from a witnessd command
class CommandResult {
  final bool success;
  final String message;
  final int exitCode;

  const CommandResult({
    required this.success,
    required this.message,
    required this.exitCode,
  });

  factory CommandResult.failure(String message) {
    return CommandResult(
      success: false,
      message: message,
      exitCode: 1,
    );
  }

  factory CommandResult.success(String message) {
    return CommandResult(
      success: true,
      message: message,
      exitCode: 0,
    );
  }
}

/// Tracked file entry
@JsonSerializable()
class TrackedFile {
  final String id;
  final String name;
  final String path;
  final int events;
  final DateTime? lastModified;

  const TrackedFile({
    required this.id,
    required this.name,
    required this.path,
    required this.events,
    this.lastModified,
  });

  factory TrackedFile.fromJson(Map<String, dynamic> json) =>
      _$TrackedFileFromJson(json);

  Map<String, dynamic> toJson() => _$TrackedFileToJson(this);
}

/// Export tier levels
enum ExportTier {
  basic('basic', 'Basic', 'Checkpoint chain + VDF proofs only'),
  standard('standard', 'Standard', 'Includes keystroke evidence'),
  enhanced('enhanced', 'Enhanced', 'Adds TPM attestation'),
  maximum('maximum', 'Maximum', 'All available evidence');

  final String value;
  final String displayName;
  final String description;

  const ExportTier(this.value, this.displayName, this.description);
}
