import 'dart:async';
import 'package:flutter/material.dart';
import '../theme.dart';
import '../../core/engine_status.dart';
import '../../bridge.dart';
import '../../core/app_state.dart';
import '../../core/engine_controller.dart';
import '../widgets/heartbeat_graph.dart';
import '../widgets/persona_card.dart';
import '../widgets/cta_buttons.dart';
import 'document_log_screen.dart';
import 'forensics_screen.dart';
import 'preferences_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, this.initialTab = 0});

  final int initialTab;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();

  static void openTab(int index) {
    final context = AppState.navigatorKey.currentContext;
    if (context == null) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => DashboardScreen(initialTab: index)),
      (route) => false,
    );
  }
}

class _DashboardScreenState extends State<DashboardScreen> {
  late int _activeTab;
  EngineStatus? _status;
  Timer? _statusTimer;
  final List<double> _eventRates = [];
  final List<double> _jitterRates = [];
  double? _eventEma;
  double? _jitterEma;
  int? _lastEventCount;
  int? _lastJitterCount;
  DateTime? _lastSampleTime;

  @override
  void initState() {
    super.initState();
    _activeTab = widget.initialTab;
    _refreshStatus();
    _statusTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      _refreshStatus();
    });
  }

  @override
  void dispose() {
    _statusTimer?.cancel();
    super.dispose();
  }

  Future<void> _refreshStatus() async {
    try {
      final frbStatus = await engineStatus();
      final parsed = frbStatus == null ? null : EngineStatus.fromFrb(frbStatus);
      if (!mounted || parsed == null) return;
      _updateRates(parsed);
      setState(() => _status = parsed);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            colors: [WitnessdTheme.darkBackground, Color(0xFF0B0F14)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        child: Row(
          children: [
            // Sidebar
            Container(
              width: 272,
              color: WitnessdTheme.surface,
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(
                        Icons.shield_rounded,
                        color: WitnessdTheme.accentBlue,
                      ),
                      const SizedBox(width: 10),
                      const Text(
                        'WITNESSD',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          letterSpacing: 2,
                          fontSize: 16,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 36),
                  _navItem(Icons.dashboard_rounded, 'Dashboard', index: 0),
                  _navItem(Icons.history_edu_rounded, 'Document Log', index: 1),
                  _navItem(Icons.analytics_outlined, 'Forensics', index: 2),
                  _navItem(Icons.settings_rounded, 'Preferences', index: 3),
                  const Spacer(),
                  const PersonaCard(),
                ],
              ),
            ),

            // Main Content
            Expanded(
              child: Padding(
                padding: const EdgeInsets.all(40.0),
                child: _buildActiveTab(),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildActiveTab() {
    switch (_activeTab) {
      case 0:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _headerRow(),
            const SizedBox(height: 16),
            _topStatusRow(),
            const SizedBox(height: 20),
            _overviewRow(),
            if (AppState.engine.phase == EnginePhase.error &&
                AppState.engine.lastError != null) ...[
              const SizedBox(height: 16),
              _errorBanner(AppState.engine.lastError!),
            ],
            const SizedBox(height: 20),
            Expanded(
              child: Row(
                children: [
                  Expanded(flex: 2, child: _graphPanel()),
                  const SizedBox(width: 20),
                  Expanded(child: _engineStatusPanel()),
                ],
              ),
            ),
            const SizedBox(height: 24),
            _systemStatusFooter(),
          ],
        );
      case 1:
        return const DocumentLogScreen();
      case 2:
        return const ForensicsScreen();
      case 3:
        return const PreferencesScreen();
      default:
        return Container();
    }
  }

  Widget _headerRow() {
    return AnimatedBuilder(
      animation: AppState.engine,
      builder: (context, _) {
        final running = AppState.engine.isRunning;
        return Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: const [
                Text(
                  'Authorship Pulse',
                  style: TextStyle(
                    fontSize: 32,
                    fontWeight: FontWeight.bold,
                    color: WitnessdTheme.strongText,
                  ),
                ),
                SizedBox(height: 6),
                Text(
                  'Continuous proof-of-process with secure chain-of-custody.',
                  style: TextStyle(color: WitnessdTheme.mutedText),
                ),
              ],
            ),
            const Spacer(),
            GhostButton(
              icon: Icons.pause_circle_filled_rounded,
              label: 'Pause',
              onTap: running
                  ? () async {
                      await AppState.engine.stop();
                      if (AppState.engine.phase == EnginePhase.error &&
                          AppState.engine.lastError != null &&
                          mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(AppState.engine.lastError!)),
                        );
                      }
                    }
                  : null,
            ),
            const SizedBox(width: 12),
            PrimaryButton(
              icon: Icons.flash_on_rounded,
              label: 'Resume',
              onTap: running
                  ? null
                  : () async {
                      await AppState.engine.refreshPermission(prompt: false);
                      if (AppState.engine.phase ==
                          EnginePhase.needsPermission) {
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(
                            content: Text('Grant Accessibility to resume.'),
                          ),
                        );
                        return;
                      }
                      await AppState.engine.start();
                      if (AppState.engine.phase == EnginePhase.error &&
                          AppState.engine.lastError != null &&
                          mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(AppState.engine.lastError!)),
                        );
                      }
                    },
            ),
          ],
        );
      },
    );
  }

  Widget _overviewRow() {
    final eventRate = _latestRate(_eventRates);
    final jitterRate = _latestRate(_jitterRates);
    return Row(
      children: [
        Expanded(
          child: _statCard(
            title: 'Signal Health',
            subtitle: 'Events/sec vs jitter/sec',
            leftLabel: 'Event Rate',
            leftValue: eventRate.toStringAsFixed(1),
            rightLabel: 'Jitter Rate',
            rightValue: jitterRate.toStringAsFixed(1),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: _statCard(
            title: 'Continuity',
            subtitle: 'Proof chain activity',
            leftLabel: 'Window',
            leftValue: '${_eventRates.length}s',
            rightLabel: 'Stability',
            rightValue: _stabilityLabel(),
          ),
        ),
      ],
    );
  }

  Widget _statCard({
    required String title,
    required String subtitle,
    required String leftLabel,
    required String leftValue,
    required String rightLabel,
    required String rightValue,
  }) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: WitnessdTheme.surface.withOpacity(0.6)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(
              fontWeight: FontWeight.w700,
              color: WitnessdTheme.strongText,
              fontSize: 16,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            subtitle,
            style: const TextStyle(color: WitnessdTheme.mutedText),
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              _miniStat(leftLabel, leftValue),
              const SizedBox(width: 20),
              _miniStat(rightLabel, rightValue),
            ],
          ),
        ],
      ),
    );
  }

  Widget _miniStat(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: WitnessdTheme.mutedText)),
        const SizedBox(height: 6),
        Text(
          value,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
            color: WitnessdTheme.strongText,
            fontSize: 18,
          ),
        ),
      ],
    );
  }

  Widget _graphPanel() {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: WitnessdTheme.surface.withOpacity(0.6)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Signal Timeline',
                style: TextStyle(
                  fontWeight: FontWeight.w700,
                  color: WitnessdTheme.strongText,
                  fontSize: 16,
                ),
              ),
              const Spacer(),
              _legendDot(WitnessdTheme.accentBlue, 'Events'),
              const SizedBox(width: 12),
              _legendDot(WitnessdTheme.secureGreen, 'Jitter'),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: HeartbeatGraph(
              primary: _eventRates,
              secondary: _jitterRates,
            ),
          ),
        ],
      ),
    );
  }

  Widget _legendDot(Color color, String label) {
    return Row(
      children: [
        Container(
          width: 8,
          height: 8,
          decoration: BoxDecoration(color: color, shape: BoxShape.circle),
        ),
        const SizedBox(width: 6),
        Text(label, style: const TextStyle(color: WitnessdTheme.mutedText)),
      ],
    );
  }

  double _latestRate(List<double> series) {
    if (series.isEmpty) return 0;
    return series.last;
  }

  String _stabilityLabel() {
    if (_eventRates.isEmpty) return 'Cold';
    final avg = _eventRates.reduce((a, b) => a + b) / _eventRates.length;
    if (avg > 20) return 'High';
    if (avg > 10) return 'Steady';
    return 'Low';
  }

  Widget _navItem(IconData icon, String label, {required int index}) {
    final active = _activeTab == index;
    return InkWell(
      onTap: () => setState(() => _activeTab = index),
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
        child: Row(
          children: [
            Icon(
              icon,
              color: active
                  ? WitnessdTheme.accentBlue
                  : WitnessdTheme.mutedText,
            ),
            const SizedBox(width: 16),
            Text(
              label,
              style: TextStyle(
                color: active ? Colors.white : WitnessdTheme.mutedText,
                fontWeight: active ? FontWeight.bold : FontWeight.normal,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _systemStatusFooter() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        children: [
          _StatusIndicator(label: 'Secure Enclave Connected', active: true),
          Spacer(),
          _StatusIndicator(label: 'VDF Clock Synchronized', active: true),
        ],
      ),
    );
  }

  Widget _engineStatusPanel() {
    final status = _status;
    final running = status?.running ?? false;
    final events = status?.eventsWritten ?? 0;
    final jitter = status?.jitterSamples ?? 0;
    final lastNs = status?.lastEventTimestampNs;
    final lastTime = lastNs == null
        ? '—'
        : DateTime.fromMillisecondsSinceEpoch(
            (lastNs / 1e6).round(),
          ).toLocal().toString();

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'Engine Status',
                style: TextStyle(
                  fontWeight: FontWeight.w700,
                  color: WitnessdTheme.strongText,
                ),
              ),
              const Spacer(),
              _statusChip(running ? 'Running' : 'Paused', running),
            ],
          ),
          const SizedBox(height: 16),
          _metricRow('Events', events.toString()),
          const SizedBox(height: 12),
          _metricRow('Jitter Samples', jitter.toString()),
          const SizedBox(height: 12),
          _metricRow(
            'Last Event',
            lastTime,
            onTap: lastNs == null ? null : () => _showLastEventDetails(lastNs),
          ),
        ],
      ),
    );
  }

  Widget _errorBanner(String message) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: WitnessdTheme.warningRed.withOpacity(0.12),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: WitnessdTheme.warningRed.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          const Icon(
            Icons.warning_amber_rounded,
            color: WitnessdTheme.warningRed,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              message,
              style: const TextStyle(color: WitnessdTheme.warningRed),
            ),
          ),
        ],
      ),
    );
  }

  Widget _statusChip(String label, bool active) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: active
            ? WitnessdTheme.secureGreen.withOpacity(0.15)
            : WitnessdTheme.warningRed.withOpacity(0.15),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: active
                  ? WitnessdTheme.secureGreen
                  : WitnessdTheme.warningRed,
            ),
          ),
          const SizedBox(width: 8),
          Text(label),
        ],
      ),
    );
  }

  Widget _metricTile(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: WitnessdTheme.mutedText)),
        const SizedBox(height: 4),
        Text(
          value,
          style: const TextStyle(
            fontWeight: FontWeight.bold,
            color: WitnessdTheme.strongText,
          ),
          overflow: TextOverflow.ellipsis,
        ),
      ],
    );
  }

  Widget _metricRow(String label, String value, {VoidCallback? onTap}) {
    final row = Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: const TextStyle(color: WitnessdTheme.mutedText)),
        const SizedBox(width: 12),
        Expanded(
          child: Text(
            value,
            textAlign: TextAlign.right,
            style: const TextStyle(
              fontWeight: FontWeight.w600,
              color: WitnessdTheme.strongText,
            ),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );

    if (onTap == null) return row;
    return InkWell(onTap: onTap, child: row);
  }

  void _showLastEventDetails(int lastNs) {
    final dt = DateTime.fromMillisecondsSinceEpoch(
      (lastNs / 1e6).round(),
    ).toLocal();
    showDialog<void>(
      context: context,
      builder: (ctx) {
        return AlertDialog(
          title: const Text('Last Event'),
          content: Text('Last witnessed event at ${dt.toString()}.'),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: const Text('Close'),
            ),
          ],
        );
      },
    );
  }

  Widget _topStatusRow() {
    final trusted = AppState.engine.phase != EnginePhase.needsPermission;
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      children: [
        _pill(
          trusted ? 'System Trust: Verified' : 'System Trust: Pending',
          trusted ? WitnessdTheme.secureGreen : WitnessdTheme.warningRed,
        ),
        _pill(
          AppState.engine.isRunning
              ? 'Witnessing: Active'
              : 'Witnessing: Paused',
          AppState.engine.isRunning
              ? WitnessdTheme.secureGreen
              : WitnessdTheme.warningRed,
        ),
      ],
    );
  }

  Widget _pill(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: color.withOpacity(0.35)),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: WitnessdTheme.strongText,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }

  void _updateRates(EngineStatus status) {
    final now = DateTime.now();
    if (_lastSampleTime != null &&
        _lastEventCount != null &&
        _lastJitterCount != null) {
      final dt = now.difference(_lastSampleTime!).inMilliseconds / 1000.0;
      if (dt > 0) {
        final eventDelta = status.eventsWritten - _lastEventCount!;
        final jitterDelta = status.jitterSamples - _lastJitterCount!;
        final eventRate = _clampRate(eventDelta / dt);
        final jitterRate = _clampRate(jitterDelta / dt);
        _eventEma = _ema(_eventEma, eventRate, 0.25);
        _jitterEma = _ema(_jitterEma, jitterRate, 0.25);
        _pushRate(_eventRates, _eventEma ?? eventRate);
        _pushRate(_jitterRates, _jitterEma ?? jitterRate);
      }
    }
    _lastSampleTime = now;
    _lastEventCount = status.eventsWritten;
    _lastJitterCount = status.jitterSamples;
  }

  double _ema(double? previous, double next, double alpha) {
    if (previous == null) return next;
    return previous + alpha * (next - previous);
  }

  double _clampRate(double value) {
    if (!value.isFinite) return 0;
    if (value < 0) return 0;
    return value > 40 ? 40 : value;
  }

  void _pushRate(List<double> series, double value) {
    const maxPoints = 120;
    series.add(value.isFinite ? value : 0);
    if (series.length > maxPoints) {
      series.removeAt(0);
    }
  }
}

class _StatusIndicator extends StatelessWidget {
  const _StatusIndicator({required this.label, required this.active});

  final String label;
  final bool active;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(
            color: active
                ? WitnessdTheme.secureGreen
                : WitnessdTheme.warningRed,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 8),
        Text(
          label,
          style: TextStyle(
            color: active ? Colors.white : WitnessdTheme.mutedText,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}
