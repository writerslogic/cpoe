// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'witness_status.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

WitnessStatus _$WitnessStatusFromJson(Map<String, dynamic> json) =>
    WitnessStatus(
      isInitialized: json['isInitialized'] as bool? ?? false,
      isTracking: json['isTracking'] as bool? ?? false,
      trackingDocument: json['trackingDocument'] as String?,
      keystrokeCount: json['keystrokeCount'] as int? ?? 0,
      trackingDuration: json['trackingDuration'] as String? ?? '',
      vdfCalibrated: json['vdfCalibrated'] as bool? ?? false,
      vdfIterPerSec: json['vdfIterPerSec'] as String? ?? '',
      tpmAvailable: json['tpmAvailable'] as bool? ?? false,
      tpmInfo: json['tpmInfo'] as String? ?? '',
      databaseEvents: json['databaseEvents'] as int? ?? 0,
      databaseFiles: json['databaseFiles'] as int? ?? 0,
    );

Map<String, dynamic> _$WitnessStatusToJson(WitnessStatus instance) =>
    <String, dynamic>{
      'isInitialized': instance.isInitialized,
      'isTracking': instance.isTracking,
      'trackingDocument': instance.trackingDocument,
      'keystrokeCount': instance.keystrokeCount,
      'trackingDuration': instance.trackingDuration,
      'vdfCalibrated': instance.vdfCalibrated,
      'vdfIterPerSec': instance.vdfIterPerSec,
      'tpmAvailable': instance.tpmAvailable,
      'tpmInfo': instance.tpmInfo,
      'databaseEvents': instance.databaseEvents,
      'databaseFiles': instance.databaseFiles,
    };

SentinelStatus _$SentinelStatusFromJson(Map<String, dynamic> json) =>
    SentinelStatus(
      isRunning: json['isRunning'] as bool? ?? false,
      pid: json['pid'] as int? ?? 0,
      uptime: json['uptime'] as String? ?? '',
      trackedDocuments: json['trackedDocuments'] as int? ?? 0,
    );

Map<String, dynamic> _$SentinelStatusToJson(SentinelStatus instance) =>
    <String, dynamic>{
      'isRunning': instance.isRunning,
      'pid': instance.pid,
      'uptime': instance.uptime,
      'trackedDocuments': instance.trackedDocuments,
    };

TrackedFile _$TrackedFileFromJson(Map<String, dynamic> json) => TrackedFile(
      id: json['id'] as String,
      name: json['name'] as String,
      path: json['path'] as String,
      events: json['events'] as int,
      lastModified: json['lastModified'] == null
          ? null
          : DateTime.parse(json['lastModified'] as String),
    );

Map<String, dynamic> _$TrackedFileToJson(TrackedFile instance) =>
    <String, dynamic>{
      'id': instance.id,
      'name': instance.name,
      'path': instance.path,
      'events': instance.events,
      'lastModified': instance.lastModified?.toIso8601String(),
    };
