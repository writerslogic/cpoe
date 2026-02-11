import 'dart:convert';
import '../frb_generated.dart';

class EngineConfig {
  final String dataDir;
  final List<String> watchDirs;
  final int retentionDays;

  EngineConfig({
    required this.dataDir,
    required this.watchDirs,
    required this.retentionDays,
  });

  factory EngineConfig.fromFrb(FrbEngineConfig frb) {
    return EngineConfig(
      dataDir: frb.dataDir,
      watchDirs: frb.watchDirs,
      retentionDays: frb.retentionDays.toInt(),
    );
  }

  FrbEngineConfig toFrb() {
    return FrbEngineConfig(
      dataDir: dataDir,
      watchDirs: watchDirs,
      retentionDays: retentionDays,
    );
  }

  factory EngineConfig.fromJson(String raw) {
    final map = jsonDecode(raw) as Map<String, dynamic>;
    return EngineConfig(
      dataDir: map['data_dir'] as String? ?? '',
      watchDirs: (map['watch_dirs'] as List<dynamic>? ?? [])
          .map((e) => e.toString())
          .toList(),
      retentionDays: map['retention_days'] as int? ?? 30,
    );
  }

  String toJson() {
    return jsonEncode({
      'data_dir': dataDir,
      'watch_dirs': watchDirs,
      'retention_days': retentionDays,
    });
  }
}
