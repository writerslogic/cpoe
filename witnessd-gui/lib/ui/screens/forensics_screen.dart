import 'dart:convert';
import 'dart:io';
import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../theme.dart';
import '../widgets/cta_buttons.dart';

class ForensicsScreen extends StatefulWidget {
  const ForensicsScreen({super.key});

  @override
  State<ForensicsScreen> createState() => _ForensicsScreenState();
}

class _ForensicsScreenState extends State<ForensicsScreen> {
  double _sensitivity = 0.65;
  bool _includeRaw = true;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _headerRow(),
        const SizedBox(height: 16),
        _summaryStrip(),
        const SizedBox(height: 20),
        Expanded(
          child: LayoutBuilder(
            builder: (context, constraints) {
              final narrow = constraints.maxWidth < 980;
              return narrow
                  ? Column(
                      children: [
                        Expanded(child: _signalGrid()),
                        const SizedBox(height: 20),
                        SizedBox(height: 280, child: _auditPanel()),
                      ],
                    )
                  : Row(
                      children: [
                        Expanded(flex: 2, child: _signalGrid()),
                        const SizedBox(width: 24),
                        Expanded(child: _auditPanel()),
                      ],
                    );
            },
          ),
        ),
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
              'Forensic Analysis',
              style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 6),
            Text(
              'Deep-dive into the physical signals of authorship.',
              style: TextStyle(color: WitnessdTheme.mutedText),
            ),
          ],
        ),
        const Spacer(),
        GhostButton(
          icon: Icons.tune_rounded,
          label: 'Adjust',
          onTap: _openAdjustments,
        ),
        const SizedBox(width: 12),
        PrimaryButton(
          icon: Icons.shield_rounded,
          label: 'Export Bundle',
          onTap: _exportBundle,
        ),
      ],
    );
  }

  Future<void> _exportBundle() async {
    try {
      final location = await getSaveLocation(
        suggestedName: 'witnessd-forensics.json',
        acceptedTypeGroups: [
          const XTypeGroup(label: 'JSON', extensions: ['json']),
        ],
      );
      if (location == null) return;
      final path = location.path;
      final payload = {
        'exported_at': DateTime.now().toIso8601String(),
        'sensitivity': _sensitivity,
        'include_raw': _includeRaw,
        'signals': [
          {'name': 'Clock Skew', 'score': 0.998, 'status': 'Stable'},
          {'name': 'Thermal Proxy', 'score': 0.945, 'status': 'Nominal'},
          {'name': 'I/O Latency', 'score': 0.982, 'status': 'Verified'},
          {'name': 'Cognitive Cadence', 'score': 0.912, 'status': 'Human'},
        ],
      };
      await File(
        path,
      ).writeAsString(const JsonEncoder.withIndent('  ').convert(payload));
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Forensics bundle exported.')),
      );
    } catch (err) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Export failed: $err')));
    }
  }

  Future<void> _openAdjustments() async {
    await showDialog<void>(
      context: context,
      builder: (ctx) {
        double sensitivity = _sensitivity;
        bool includeRaw = _includeRaw;
        return AlertDialog(
          title: const Text('Forensics Adjustments'),
          content: StatefulBuilder(
            builder: (ctx, setState) {
              return Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      const Text('Sensitivity'),
                      Expanded(
                        child: Slider(
                          value: sensitivity,
                          min: 0.2,
                          max: 1.0,
                          divisions: 8,
                          label: sensitivity.toStringAsFixed(2),
                          onChanged: (value) =>
                              setState(() => sensitivity = value),
                        ),
                      ),
                    ],
                  ),
                  SwitchListTile(
                    value: includeRaw,
                    onChanged: (value) => setState(() => includeRaw = value),
                    title: const Text('Include raw signal summaries'),
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
              onPressed: () {
                setState(() {
                  _sensitivity = sensitivity;
                  _includeRaw = includeRaw;
                });
                Navigator.of(ctx).pop();
              },
              child: const Text('Apply'),
            ),
          ],
        );
      },
    );
  }

  Widget _summaryStrip() {
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: [
        _chip('Integrity', WitnessdTheme.secureGreen),
        _chip('Signal Density: High', WitnessdTheme.accentBlue),
        _chip('Anomalies: 2', WitnessdTheme.warningRed),
      ],
    );
  }

  Widget _signalGrid() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final crossAxisCount = constraints.maxWidth < 700 ? 1 : 2;
        final ratio = crossAxisCount == 1 ? 2.2 : 1.5;
        return GridView.count(
          crossAxisCount: crossAxisCount,
          childAspectRatio: ratio,
          crossAxisSpacing: 24,
          mainAxisSpacing: 24,
          children: [
            _signalCard('Clock Skew', 'TSC vs HPET Drift', 0.998, 'Stable'),
            _signalCard(
              'Thermal Proxy',
              'Phonon Scattering Echo',
              0.945,
              'Nominal',
            ),
            _signalCard(
              'I/O Latency',
              'Bus Write Signature',
              0.982,
              'Verified',
            ),
            _signalCard(
              'Cognitive Cadence',
              'IKI Burst Analysis',
              0.912,
              'Human',
            ),
          ],
        );
      },
    );
  }

  Widget _auditPanel() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Audit Trail',
              style: TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 16,
                color: WitnessdTheme.strongText,
              ),
            ),
            const SizedBox(height: 6),
            const Text(
              'Recent integrity observations',
              style: TextStyle(color: WitnessdTheme.mutedText, fontSize: 12),
            ),
            const SizedBox(height: 16),
            _auditItem(
              'Thermal variance peaked at 0.08',
              '2m ago',
              WitnessdTheme.warningRed,
            ),
            _auditItem(
              'TSC drift normalized',
              '5m ago',
              WitnessdTheme.secureGreen,
            ),
            _auditItem(
              'I/O latency within baseline',
              '9m ago',
              WitnessdTheme.secureGreen,
            ),
            const SizedBox(height: 16),
            _auditSummary(),
          ],
        ),
      ),
    );
  }

  Widget _auditItem(String message, String time, Color color) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: WitnessdTheme.surface,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(color: WitnessdTheme.strongText),
            ),
          ),
          Text(
            time,
            style: const TextStyle(
              color: WitnessdTheme.mutedText,
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }

  Widget _auditSummary() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: WitnessdTheme.darkBackground,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: const [
          Icon(
            Icons.timeline_rounded,
            color: WitnessdTheme.accentBlue,
            size: 18,
          ),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              'Full trace stored with report bundle',
              style: TextStyle(color: WitnessdTheme.mutedText),
            ),
          ),
        ],
      ),
    );
  }

  Widget _chip(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withOpacity(0.35)),
      ),
      child: Text(
        label,
        style: const TextStyle(
          color: WitnessdTheme.strongText,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  Widget _signalCard(
    String title,
    String subtitle,
    double probability,
    String status,
  ) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Text(
                  title,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 18,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: WitnessdTheme.secureGreen.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  status,
                  style: const TextStyle(
                    color: WitnessdTheme.secureGreen,
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: const TextStyle(
              color: WitnessdTheme.mutedText,
              fontSize: 12,
            ),
          ),
          const SizedBox(height: 16),
          Expanded(
            child: _miniChart(probability),
          ),
          const SizedBox(height: 16),
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                '${(probability * 100).toStringAsFixed(3)}%',
                style: const TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  fontFamily: 'Menlo',
                ),
              ),
              const Padding(
                padding: EdgeInsets.only(bottom: 4, left: 8),
                child: Text(
                  'Confidence',
                  style: TextStyle(
                    color: WitnessdTheme.mutedText,
                    fontSize: 10,
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _miniChart(double value) {
    // Generate dummy trend line based on probability
    final List<FlSpot> spots = List.generate(10, (i) {
      final variance = (i == 9) ? 0 : (0.02 * (5 - i).abs());
      return FlSpot(i.toDouble(), value - variance);
    });

    return LineChart(
      LineChartData(
        gridData: const FlGridData(show: false),
        titlesData: const FlTitlesData(show: false),
        borderData: FlBorderData(show: false),
        lineBarsData: [
          LineChartBarData(
            spots: spots,
            isCurved: true,
            color: WitnessdTheme.accentBlue,
            barWidth: 2,
            dotData: const FlDotData(show: false),
            belowBarData: BarAreaData(
              show: true,
              color: WitnessdTheme.accentBlue.withOpacity(0.1),
            ),
          ),
        ],
      ),
    );
  }
}
