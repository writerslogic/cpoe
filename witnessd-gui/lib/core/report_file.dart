import 'dart:convert';
import '../frb_generated.dart';

class ReportFile {
  final String filePath;
  final int lastEventTimestampNs;
  final int eventCount;

  ReportFile({
    required this.filePath,
    required this.lastEventTimestampNs,
    required this.eventCount,
  });

  factory ReportFile.fromFrb(FrbReportFile frb) {
    return ReportFile(
      filePath: frb.filePath,
      lastEventTimestampNs: frb.lastEventTimestampNs.toInt(),
      eventCount: frb.eventCount.toInt(),
    );
  }

  Map<String, dynamic> toJson() => {
    'file_path': filePath,
    'last_event_timestamp_ns': lastEventTimestampNs,
    'event_count': eventCount,
  };

  static List<ReportFile> listFromJson(String raw) {
    final data = jsonDecode(raw) as List<dynamic>;
    return data
        .map((e) => e as Map<String, dynamic>)
        .map(
          (e) => ReportFile(
            filePath: e['file_path'] as String? ?? '',
            lastEventTimestampNs: e['last_event_timestamp_ns'] as int? ?? 0,
            eventCount: e['event_count'] as int? ?? 0,
          ),
        )
        .toList();
  }
}
