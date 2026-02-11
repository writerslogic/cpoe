import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';
import 'package:file_selector/file_selector.dart';
import '../../bridge.dart';
import '../../core/app_state.dart';
import '../theme.dart';

class TrayPanel extends StatefulWidget {
  const TrayPanel({super.key});

  @override
  State<TrayPanel> createState() => _TrayPanelState();
}

class _TrayPanelState extends State<TrayPanel> {
  int _fileCount = 0;

  @override
  void initState() {
    super.initState();
    _loadCount();
    AppState.engine.addListener(_loadCount);
  }

  @override
  void dispose() {
    AppState.engine.removeListener(_loadCount);
    super.dispose();
  }

  Future<void> _loadCount() async {
    try {
      final files = await reportFiles();
      if (mounted) setState(() => _fileCount = files.length);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: WitnessdTheme.darkBackground,
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _header(),
            const SizedBox(height: 20),
            _statusCard(),
            const SizedBox(height: 16),
            _actionButtons(),
            const Spacer(),
            _footer(),
          ],
        ),
      ),
    );
  }

  Widget _header() {
    return Row(
      children: [
        const Icon(Icons.shield, color: WitnessdTheme.accentBlue),
        const SizedBox(width: 10),
        const Text(
          'Witnessd',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
        ),
        const Spacer(),
        IconButton(
          icon: const Icon(Icons.close, size: 18),
          tooltip: 'Hide',
          onPressed: () => windowManager.hide(),
        ),
      ],
    );
  }

  Widget _statusCard() {
    return AnimatedBuilder(
      animation: AppState.engine,
      builder: (context, _) {
        final running = AppState.engine.isRunning;
        return Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: WitnessdTheme.surface,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(
            children: [
              Container(
                width: 12,
                height: 12,
                decoration: BoxDecoration(
                  color: running
                      ? WitnessdTheme.secureGreen
                      : WitnessdTheme.mutedText,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    running ? 'Witnessing' : 'Paused',
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                  Text(
                    '$_fileCount files tracked',
                    style: const TextStyle(
                      color: WitnessdTheme.mutedText,
                      fontSize: 12,
                    ),
                  ),
                ],
              ),
              const Spacer(),
              Switch(
                value: running,
                onChanged: (_) => AppState.engine.toggle(),
                activeThumbColor: WitnessdTheme.secureGreen,
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _actionButtons() {
    return Column(
      children: [
        _actionTile(Icons.verified_outlined, 'Verify File', _verifyFile),
        _actionTile(Icons.download_outlined, 'Export Certificate', _exportCert),
        _actionTile(Icons.folder_outlined, 'Watch Folders', _manageFolders),
      ],
    );
  }

  Widget _actionTile(IconData icon, String label, VoidCallback onTap) {
    return ListTile(
      dense: true,
      leading: Icon(icon, color: WitnessdTheme.accentBlue, size: 20),
      title: Text(label, style: const TextStyle(fontSize: 14)),
      trailing: const Icon(
        Icons.chevron_right,
        size: 18,
        color: WitnessdTheme.mutedText,
      ),
      onTap: onTap,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
    );
  }

  Widget _footer() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        FutureBuilder<String>(
          future: getVersion(),
          builder: (ctx, snap) => Text(
            'v${snap.data ?? "..."}',
            style: const TextStyle(
              color: WitnessdTheme.mutedText,
              fontSize: 11,
            ),
          ),
        ),
        TextButton(
          onPressed: _quit,
          child: const Text('Quit', style: TextStyle(fontSize: 12)),
        ),
      ],
    );
  }

  Future<void> _verifyFile() async {
    final file = await openFile();
    if (file == null) return;
    try {
      final result = await verifyDocument(path: file.path);
      final data = jsonDecode(result);
      if (!mounted) return;
      final valid = data['valid'] == true;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(valid ? 'Verified' : 'Failed'),
          backgroundColor: valid
              ? WitnessdTheme.secureGreen
              : WitnessdTheme.warningRed,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('$e'),
          backgroundColor: WitnessdTheme.warningRed,
        ),
      );
    }
  }

  Future<void> _exportCert() async {
    final file = await openFile();
    if (file == null) return;
    try {
      await exportEvidence(path: file.path, title: file.name, tier: 'basic');
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Certificate exported')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('$e'),
          backgroundColor: WitnessdTheme.warningRed,
        ),
      );
    }
  }

  Future<void> _manageFolders() async {
    final dir = await getDirectoryPath();
    if (dir == null) return;
    // Add to watch list
    try {
      final configJson = await getEngineConfig();
      final config = jsonDecode(configJson);
      final dirs = List<String>.from(config['watch_dirs'] ?? []);
      if (!dirs.contains(dir)) {
        dirs.add(dir);
        config['watch_dirs'] = dirs;
        await setEngineConfig(raw: jsonEncode(config));
        if (AppState.engine.isRunning) {
          await AppState.engine.stop();
          await AppState.engine.start();
        }
        if (!mounted) return;
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Added: $dir')));
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('$e'),
          backgroundColor: WitnessdTheme.warningRed,
        ),
      );
    }
  }

  Future<void> _quit() async {
    await AppState.engine.stop();
    await windowManager.destroy();
  }
}
