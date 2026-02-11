import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import '../../bridge.dart';
import '../theme.dart';
import 'tray_panel.dart';
import '../../core/app_state.dart';
import '../widgets/cta_buttons.dart';

class PermissionGate extends StatefulWidget {
  const PermissionGate({super.key, this.initialTab});

  final int? initialTab;

  @override
  State<PermissionGate> createState() => _PermissionGateState();
}

class _PermissionGateState extends State<PermissionGate> {
  bool _checking = true;
  bool _trusted = false;
  bool _inputTrusted = false;
  bool _starting = false;
  String? _error;
  Timer? _poller;
  bool _prompted = false;
  bool _blocked = false;

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    setState(() {
      _checking = true;
      _error = null;
    });
    try {
      final trusted = await accessibilityTrusted();
      final inputTrusted = await inputMonitoringTrusted();
      final allTrusted = trusted && inputTrusted;

      // Debug: show what permissions are detected
      debugPrint(
        'Permission check: accessibility=$trusted, inputMonitoring=$inputTrusted',
      );

      setState(() {
        _trusted = trusted;
        _inputTrusted = inputTrusted;
        _checking = false;
      });

      // If all permissions granted, start engine immediately
      if (allTrusted) {
        await _startEngineAndContinue();
        return;
      }

      // Only open settings automatically on first launch if permissions missing
      // Don't auto-open if user has already been to this screen
      if (!_prompted && !trusted) {
        _prompted = true;
        // Don't auto-open settings - let user click the button
        // await openAccessibilitySettings();
      } else if (!_prompted && !inputTrusted) {
        _prompted = true;
        // Don't auto-open settings - let user click the button
        // await openInputMonitoringSettings();
      }

      setState(() {
        _blocked = !allTrusted;
      });
      _startPolling();
    } catch (err) {
      setState(() {
        _error = 'Permission check failed: $err';
        _checking = false;
      });
    }
  }

  void _startPolling() {
    _poller?.cancel();
    _poller = Timer.periodic(const Duration(seconds: 2), (_) async {
      final trusted = await accessibilityTrusted();
      final inputTrusted = await inputMonitoringTrusted();
      final allTrusted = trusted && inputTrusted;
      final updated = await AppState.engine.refreshPermission(prompt: false);
      if (!mounted) return;
      if (updated && allTrusted) {
        _poller?.cancel();
        setState(() {
          _trusted = true;
          _inputTrusted = true;
        });
        await _startEngineAndContinue();
      } else {
        setState(() {
          _trusted = trusted;
          _inputTrusted = inputTrusted;
          _blocked = _prompted;
        });
      }
    });
  }

  Future<void> _startEngineAndContinue() async {
    if (_starting) return;
    setState(() => _starting = true);
    try {
      await AppState.engine.start();
      if (!mounted) return;
      Navigator.of(
        context,
      ).pushReplacement(MaterialPageRoute(builder: (_) => const TrayPanel()));
    } catch (err) {
      setState(() {
        _error = err.toString();
        _starting = false;
      });
    }
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
        child: Center(
          child: Container(
            width: 680,
            padding: const EdgeInsets.all(48),
            decoration: BoxDecoration(
              color: WitnessdTheme.surface,
              borderRadius: BorderRadius.circular(32),
              border: Border.all(
                color: WitnessdTheme.accentBlue.withOpacity(0.12),
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.35),
                  blurRadius: 24,
                  offset: const Offset(0, 12),
                ),
              ],
            ),
            child: _checking ? _loading() : _content(),
          ),
        ),
      ),
    );
  }

  Widget _loading() {
    return const Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        CircularProgressIndicator(color: WitnessdTheme.accentBlue),
        SizedBox(height: 24),
        Text(
          'Verifying system trust...',
          style: TextStyle(fontWeight: FontWeight.w600),
        ),
      ],
    );
  }

  Widget _content() {
    if (_trusted && _inputTrusted) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          _statusHeader(
            icon: Icons.verified_rounded,
            title: 'System Trust Confirmed',
            subtitle: 'Starting secure witnessing engine...',
            accent: WitnessdTheme.secureGreen,
          ),
          const SizedBox(height: 24),
          _statusChecklist([
            _StatusLine('Accessibility granted', _trusted),
            _StatusLine('Input Monitoring granted', _inputTrusted),
            _StatusLine('Engine starting', _starting),
            _StatusLine('Background watchers armed', true),
          ]),
          if (_starting) ...[
            const SizedBox(height: 24),
            const CircularProgressIndicator(color: WitnessdTheme.accentBlue),
          ],
        ],
      );
    }

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        _statusHeader(
          icon: Icons.shield_rounded,
          title: 'Establish System Trust',
          subtitle:
              'Witnessd uses global timing metadata (never key content) to prove authorship with chain-of-custody integrity.',
          accent: WitnessdTheme.accentBlue,
        ),
        const SizedBox(height: 20),
        Text(
          _blocked
              ? 'macOS still reports permissions disabled.'
              : 'Waiting for Accessibility and Input Monitoring...',
          style: const TextStyle(color: WitnessdTheme.mutedText),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 28),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            GhostButton(
              icon: Icons.refresh_rounded,
              label: 'Refresh Status',
              onTap: _boot,
            ),
            const SizedBox(width: 12),
            PrimaryButton(
              icon: Icons.settings,
              label: 'Open Privacy Settings',
              onTap: () async {
                if (!_trusted) {
                  await openAccessibilitySettings();
                } else if (!_inputTrusted) {
                  await openInputMonitoringSettings();
                } else {
                  await openAccessibilitySettings();
                }
              },
            ),
          ],
        ),
        const SizedBox(height: 16),
        TextButton(
          onPressed: _startEngineAndContinue,
          child: const Text(
            'Skip (permissions already granted)',
            style: TextStyle(color: WitnessdTheme.mutedText, fontSize: 12),
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 20),
          Text(
            _error!,
            style: const TextStyle(color: WitnessdTheme.warningRed),
          ),
        ],
      ],
    );
  }

  Widget _statusHeader({
    required IconData icon,
    required String title,
    required String subtitle,
    required Color accent,
  }) {
    return Column(
      children: [
        Container(
          width: 72,
          height: 72,
          decoration: BoxDecoration(
            color: accent.withOpacity(0.12),
            shape: BoxShape.circle,
          ),
          child: Icon(icon, size: 36, color: accent),
        ),
        const SizedBox(height: 20),
        Text(
          title,
          style: const TextStyle(fontSize: 26, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 12),
        Text(
          subtitle,
          textAlign: TextAlign.center,
          style: const TextStyle(color: WitnessdTheme.mutedText, height: 1.5),
        ),
      ],
    );
  }

  Widget _statusChecklist(List<_StatusLine> lines) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: Column(
        children: lines
            .map(
              (line) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: Row(
                  children: [
                    Icon(
                      line.active
                          ? Icons.check_circle
                          : Icons.radio_button_unchecked,
                      size: 18,
                      color: line.active
                          ? WitnessdTheme.secureGreen
                          : WitnessdTheme.mutedText,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        line.label,
                        style: TextStyle(
                          color: line.active
                              ? WitnessdTheme.strongText
                              : WitnessdTheme.mutedText,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            )
            .toList(),
      ),
    );
  }

  @override
  void dispose() {
    _poller?.cancel();
    super.dispose();
  }

  String? _resolveAppBundlePath() {
    if (!Platform.isMacOS) return null;
    final exec = Platform.resolvedExecutable;
    final contentsIndex = exec.indexOf('/Contents/MacOS/');
    if (contentsIndex == -1) return null;
    return exec.substring(0, contentsIndex);
  }
}

class _StatusLine {
  const _StatusLine(this.label, this.active);

  final String label;
  final bool active;
}
