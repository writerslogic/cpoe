import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import '../theme.dart';
import '../../bridge.dart';
import '../../core/report_file.dart';
import '../widgets/cta_buttons.dart';
import 'playback_screen.dart';

class DocumentLogScreen extends StatefulWidget {
  const DocumentLogScreen({super.key});

  @override
  State<DocumentLogScreen> createState() => _DocumentLogScreenState();
}

class _DocumentLogScreenState extends State<DocumentLogScreen> {
  List<ReportFile> _reports = const [];
  Timer? _timer;
  bool _loading = true;
  String? _error;
  String _query = '';
  DateTime? _lastUpdated;
  bool _filterRecent = false;
  int _minEvents = 0;

  @override
  void initState() {
    super.initState();
    _load();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _load());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final frbList = await reportFiles();
      final reports = frbList.map((f) => ReportFile.fromFrb(f)).toList();
      if (!mounted) return;
      setState(() {
        _reports = reports;
        _loading = false;
        _lastUpdated = DateTime.now();
      });
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _error = err.toString();
        _loading = false;
      });
    }
  }

  Future<void> _exportReports() async {
    try {
      final location = await getSaveLocation(
        suggestedName: 'witnessd-reports.json',
        acceptedTypeGroups: [
          const XTypeGroup(label: 'JSON', extensions: ['json']),
        ],
      );
      if (location == null) return;
      final path = location.path;
      final payload = {
        'exported_at': DateTime.now().toIso8601String(),
        'reports': _reports.map((r) => r.toJson()).toList(),
      };
      final file = File(path);
      await file.writeAsString(
        const JsonEncoder.withIndent('  ').convert(payload),
      );
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Report export complete.')));
    } catch (err) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Export failed: $err')));
    }
  }

  Future<void> _showFilters() async {
    final result = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (ctx) {
        bool recent = _filterRecent;
        double minEvents = _minEvents.toDouble();
        return AlertDialog(
          title: const Text('Filters'),
          content: StatefulBuilder(
            builder: (ctx, setState) {
              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  SwitchListTile(
                    value: recent,
                    onChanged: (value) => setState(() => recent = value),
                    title: const Text('Only last 24 hours'),
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      const Text('Minimum events'),
                      Expanded(
                        child: Slider(
                          value: minEvents,
                          min: 0,
                          max: 50,
                          divisions: 10,
                          label: minEvents.round().toString(),
                          onChanged: (value) =>
                              setState(() => minEvents = value),
                        ),
                      ),
                    ],
                  ),
                ],
              );
            },
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(
                ctx,
              ).pop({'recent': recent, 'minEvents': minEvents.round()}),
              child: const Text('Apply'),
            ),
          ],
        );
      },
    );

    if (result == null) return;
    setState(() {
      _filterRecent = result['recent'] as bool? ?? _filterRecent;
      _minEvents = result['minEvents'] as int? ?? _minEvents;
    });
  }

  @override
  Widget build(BuildContext context) {
    final filtered = _filteredReports();
    final totals = _summaryStats(filtered);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _headerRow(),
        const SizedBox(height: 16),
        _summaryRow(totals),
        const SizedBox(height: 16),
        _searchRow(),
        const SizedBox(height: 20),
        if (_loading)
          const Center(
            child: CircularProgressIndicator(color: WitnessdTheme.accentBlue),
          )
        else if (filtered.isEmpty)
          _emptyState()
        else
          Expanded(
            child: ListView.builder(
              itemCount: filtered.length,
              itemBuilder: (context, index) {
                return _reportTile(filtered[index]);
              },
            ),
          ),
        if (_error != null) ...[
          const SizedBox(height: 16),
          Text(
            _error!,
            style: const TextStyle(color: WitnessdTheme.warningRed),
          ),
        ],
      ],
    );
  }

  Widget _headerRow() {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: const [
            Text(
              'Reports',
              style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 6),
            Text(
              'Evidence availability by file.',
              style: TextStyle(color: WitnessdTheme.mutedText),
            ),
          ],
        ),
        const Spacer(),
        GhostButton(
          icon: Icons.refresh_rounded,
          label: 'Refresh',
          onTap: _load,
        ),
        const SizedBox(width: 12),
        PrimaryButton(
          icon: Icons.cloud_download_rounded,
          label: 'Export',
          onTap: _exportReports,
        ),
      ],
    );
  }

  Widget _summaryRow(_SummaryStats stats) {
    return Wrap(
      spacing: 16,
      runSpacing: 16,
      children: [
        SizedBox(
          width: 300,
          child: _summaryCard(
            title: 'Tracked Documents',
            value: stats.reportCount.toString(),
            subtitle: 'Active evidence reports',
            icon: Icons.folder_open_rounded,
          ),
        ),
        SizedBox(
          width: 300,
          child: _summaryCard(
            title: 'Total Events',
            value: stats.totalEvents.toString(),
            subtitle: 'Cumulative chain events',
            icon: Icons.bolt_rounded,
          ),
        ),
        SizedBox(
          width: 300,
          child: _summaryCard(
            title: 'Last Update',
            value: _lastUpdatedLabel(),
            subtitle: 'Local report refresh',
            icon: Icons.schedule_rounded,
          ),
        ),
      ],
    );
  }

  Widget _searchRow() {
    return Row(
      children: [
        Expanded(
          child: TextField(
            onChanged: (value) => setState(() => _query = value),
            decoration: InputDecoration(
              hintText: 'Search by filename or path',
              prefixIcon: const Icon(Icons.search_rounded),
              filled: true,
              fillColor: WitnessdTheme.surface,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(14),
                borderSide: BorderSide.none,
              ),
            ),
          ),
        ),
        const SizedBox(width: 12),
        GhostButton(
          icon: Icons.tune_rounded,
          label: 'Filters',
          onTap: _showFilters,
          compact: true,
        ),
      ],
    );
  }

  Widget _summaryCard({
    required String title,
    required String value,
    required String subtitle,
    required IconData icon,
  }) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: WitnessdTheme.accentBlue.withOpacity(0.12),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, color: WitnessdTheme.accentBlue),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: const TextStyle(color: WitnessdTheme.mutedText),
                ),
                const SizedBox(height: 4),
                Text(
                  value,
                  style: const TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: WitnessdTheme.strongText,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  subtitle,
                  style: const TextStyle(
                    color: WitnessdTheme.mutedText,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _emptyState() {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: WitnessdTheme.surfaceElevated,
          borderRadius: BorderRadius.circular(18),
          border: Border.all(color: WitnessdTheme.surface.withOpacity(0.6)),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: const [
            Icon(
              Icons.auto_awesome_rounded,
              color: WitnessdTheme.accentBlue,
              size: 40,
            ),
            SizedBox(height: 12),
            Text(
              'No evidence captured yet',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
            ),
            SizedBox(height: 8),
            Text(
              'Start writing and Witnessd will populate reports automatically.',
              style: TextStyle(color: WitnessdTheme.mutedText),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _reportTile(ReportFile report) {
    return Container(
      margin: const EdgeInsets.only(bottom: 16),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.1)),
      ),
      child: Row(
        children: [
          Column(
            children: [
              const Icon(
                Icons.description_rounded,
                color: WitnessdTheme.secureGreen,
                size: 20,
              ),
              if (report.eventCount > 1)
                Container(
                  width: 2,
                  height: 40,
                  color: WitnessdTheme.mutedText.withOpacity(0.2),
                ),
            ],
          ),
          const SizedBox(width: 24),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      report.filePath.split('/').last,
                      style: const TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    Text(
                      _formatRelative(report.lastEventTimestampNs),
                      style: const TextStyle(
                        color: WitnessdTheme.mutedText,
                        fontSize: 12,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Text(
                      'Events: ${report.eventCount}',
                      style: const TextStyle(
                        fontFamily: 'Menlo',
                        fontSize: 12,
                        color: WitnessdTheme.accentBlue,
                      ),
                    ),
                    const SizedBox(width: 12),
                    if (report.eventCount > 0)
                      TextButton.icon(
                        style: TextButton.styleFrom(
                          padding: EdgeInsets.zero,
                          minimumSize: Size.zero,
                          tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        ),
                        onPressed: () {
                          Navigator.of(context).push(MaterialPageRoute(
                            builder: (_) => PlaybackScreen(
                              filePath: report.filePath,
                              fileName: report.filePath.split('/').last,
                            ),
                          ));
                        },
                        icon: const Icon(Icons.play_circle_outline, size: 14),
                        label: const Text('Playback', style: TextStyle(fontSize: 12)),
                      ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  _strengthLabel(report.eventCount),
                  style: const TextStyle(color: Colors.white70, fontSize: 14),
                ),
              ],
            ),
          ),
          const SizedBox(width: 24),
          _confidenceIndicator(_scoreFromCount(report.eventCount)),
        ],
      ),
    );
  }

  Widget _confidenceIndicator(double score) {
    return Column(
      children: [
        Text(
          '${(score * 100).toStringAsFixed(1)}%',
          style: TextStyle(
            color: score > 0.9
                ? WitnessdTheme.secureGreen
                : WitnessdTheme.accentBlue,
            fontWeight: FontWeight.bold,
          ),
        ),
        const Text(
          'Prob.',
          style: TextStyle(fontSize: 10, color: WitnessdTheme.mutedText),
        ),
      ],
    );
  }

  String _formatRelative(int ns) {
    if (ns == 0) return '—';
    final dt = DateTime.fromMillisecondsSinceEpoch(
      (ns / 1e6).round(),
    ).toLocal();
    final diff = DateTime.now().difference(dt);
    if (diff.inSeconds < 60) return 'just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  String _strengthLabel(int count) {
    if (count < 5) return 'Basic evidence';
    if (count < 20) return 'Standard evidence';
    if (count < 60) return 'Enhanced evidence';
    return 'Maximum evidence';
  }

  double _scoreFromCount(int count) {
    if (count <= 0) return 0.5;
    if (count < 5) return 0.8;
    if (count < 20) return 0.92;
    return 0.98;
  }

  List<ReportFile> _filteredReports() {
    final needle = _query.trim().toLowerCase();
    final now = DateTime.now();
    return _reports.where((report) {
      if (needle.isNotEmpty) {
        final path = report.filePath.toLowerCase();
        final name = report.filePath.split('/').last.toLowerCase();
        if (!path.contains(needle) && !name.contains(needle)) {
          return false;
        }
      }
      if (_filterRecent) {
        final dt = DateTime.fromMillisecondsSinceEpoch(
          (report.lastEventTimestampNs / 1e6).round(),
        ).toLocal();
        if (now.difference(dt).inHours > 24) {
          return false;
        }
      }
      if (_minEvents > 0 && report.eventCount < _minEvents) {
        return false;
      }
      return true;
    }).toList();
  }

  _SummaryStats _summaryStats(List<ReportFile> reports) {
    final totalEvents = reports.fold<int>(0, (sum, r) => sum + r.eventCount);
    return _SummaryStats(reportCount: reports.length, totalEvents: totalEvents);
  }

  String _lastUpdatedLabel() {
    if (_lastUpdated == null) return '—';
    final diff = DateTime.now().difference(_lastUpdated!);
    if (diff.inSeconds < 60) return 'now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m';
    if (diff.inHours < 24) return '${diff.inHours}h';
    return '${diff.inDays}d';
  }
}

class _SummaryStats {
  const _SummaryStats({required this.reportCount, required this.totalEvents});

  final int reportCount;
  final int totalEvents;
}
