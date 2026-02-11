import 'dart:convert';
import '../frb_generated.dart';

class EngineStatus {
  final bool running;
  final bool accessibilityTrusted;
  final List<String> watchDirs;
  final int eventsWritten;
  final int jitterSamples;
  final int? lastEventTimestampNs;

  EngineStatus({
    required this.running,
    required this.accessibilityTrusted,
    required this.watchDirs,
    required this.eventsWritten,
    required this.jitterSamples,
    required this.lastEventTimestampNs,
  });

  factory EngineStatus.fromFrb(FrbEngineStatus frb) {
    return EngineStatus(
      running: frb.running,
      accessibilityTrusted: frb.accessibilityTrusted,
      watchDirs: frb.watchDirs,
      eventsWritten: frb.eventsWritten.toInt(),
      jitterSamples: frb.jitterSamples.toInt(),
      lastEventTimestampNs: frb.lastEventTimestampNs?.toInt(),
    );
  }

  static EngineStatus? fromJsonString(String? raw) {
    if (raw == null) return null;
    final map = jsonDecode(raw) as Map<String, dynamic>;
    return EngineStatus(
      running: map['running'] as bool? ?? false,
      accessibilityTrusted: map['accessibility_trusted'] as bool? ?? false,
      watchDirs: (map['watch_dirs'] as List<dynamic>? ?? [])
          .map((e) => e.toString())
          .toList(),
      eventsWritten: map['events_written'] as int? ?? 0,
      jitterSamples: map['jitter_samples'] as int? ?? 0,
      lastEventTimestampNs: map['last_event_timestamp_ns'] as int?,
    );
  }
}
