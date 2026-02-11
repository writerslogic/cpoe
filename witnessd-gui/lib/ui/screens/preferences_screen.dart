import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import '../../bridge.dart';
import '../../core/app_state.dart';
import '../../core/engine_config.dart';
import '../../core/startup_manager.dart';
import '../../core/engine_controller.dart';
import '../theme.dart';
import '../widgets/section_card.dart';

class PreferencesScreen extends StatefulWidget {
  const PreferencesScreen({super.key});

  @override
  State<PreferencesScreen> createState() => _PreferencesScreenState();
}

class _PreferencesScreenState extends State<PreferencesScreen> {
  EngineConfig? _config;
  bool _loading = true;
  bool _startAtLogin = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final frbConfig = await getEngineConfig();
      final config = EngineConfig.fromFrb(frbConfig);
      final startAtLogin = await StartupManager.isEnabled();
      if (!mounted) return;
      setState(() {
        _config = config;
        _startAtLogin = startAtLogin;
        _loading = false;
      });
    } catch (err) {
      if (!mounted) return;
      setState(() {
        _error = err.toString();
        _loading = false;
      });
    }
  }

  Future<void> _saveConfig() async {
    final config = _config;
    if (config == null) return;
    try {
      // Stop engine before config change
      final wasRunning = AppState.engine.isRunning;
      if (wasRunning) {
        await AppState.engine.stop();
      }

      await setEngineConfig(config: config.toFrb());

      // Restart engine if it was running
      if (wasRunning) {
        await AppState.engine.start();
      }

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Preferences saved and applied.')),
      );
    } catch (err) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Save failed: $err')));
    }
  }

  Future<void> _addFolder() async {
    try {
      final path = await getDirectoryPath();
      if (path == null || _config == null) return;
      final dirs = List<String>.from(_config!.watchDirs);
      if (!dirs.contains(path)) {
        dirs.add(path);
        setState(() {
          _config = EngineConfig(
            dataDir: _config!.dataDir,
            watchDirs: dirs,
            retentionDays: _config!.retentionDays,
          );
        });
        await _saveConfig();
      }
    } catch (err) {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Add folder failed: $err')));
    }
  }

  Future<void> _removeFolder(String path) async {
    if (_config == null) return;
    final dirs = List<String>.from(_config!.watchDirs);
    dirs.remove(path);
    setState(() {
      _config = EngineConfig(
        dataDir: _config!.dataDir,
        watchDirs: dirs,
        retentionDays: _config!.retentionDays,
      );
    });
    await _saveConfig();
  }

  Future<void> _updateRetention(double value) async {
    if (_config == null) return;
    setState(() {
      _config = EngineConfig(
        dataDir: _config!.dataDir,
        watchDirs: _config!.watchDirs,
        retentionDays: value.round(),
      );
    });
    await _saveConfig();
  }

  Future<void> _toggleStartAtLogin(bool value) async {
    setState(() => _startAtLogin = value);
    if (value) {
      await StartupManager.enable();
    } else {
      await StartupManager.disable();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(
        child: CircularProgressIndicator(color: WitnessdTheme.accentBlue),
      );
    }

    if (_error != null) {
      return Text(
        _error!,
        style: const TextStyle(color: WitnessdTheme.warningRed),
      );
    }

    final config =
        _config ?? EngineConfig(dataDir: '', watchDirs: [], retentionDays: 30);

    return ListView(
      children: [
        _header(),
        const SizedBox(height: 16),
        _heroCard(),
        const SizedBox(height: 24),
        SectionCard(
          title: 'Watch Locations',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (config.watchDirs.isEmpty) _emptyWatchDirs(),
              for (final dir in config.watchDirs)
                _dirRow(dir, () => _removeFolder(dir)),
              const SizedBox(height: 12),
              Align(
                alignment: Alignment.centerLeft,
                child: OutlinedButton.icon(
                  onPressed: _addFolder,
                  icon: const Icon(Icons.add),
                  label: const Text('Add Folder'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        SectionCard(
          title: 'Retention',
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Raw signal retention: ${config.retentionDays} days',
                style: const TextStyle(
                  fontWeight: FontWeight.w600,
                  color: WitnessdTheme.strongText,
                ),
              ),
              const SizedBox(height: 6),
              const Text(
                'Shorter retention improves privacy; longer retention aids audits.',
                style: TextStyle(color: WitnessdTheme.mutedText, fontSize: 12),
              ),
              const SizedBox(height: 10),
              Slider(
                value: config.retentionDays.toDouble(),
                min: 1,
                max: 90,
                divisions: 89,
                onChanged: _updateRetention,
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        SectionCard(
          title: 'Startup & Background',
          child: Column(
            children: [
              SwitchListTile(
                value: _startAtLogin,
                onChanged: StartupManager.isSupported
                    ? _toggleStartAtLogin
                    : null,
                title: const Text('Start at login'),
                subtitle: StartupManager.isSupported
                    ? const Text('Launch Witnessd automatically')
                    : const Text('Unavailable in this build'),
              ),
              AnimatedBuilder(
                animation: AppState.engine,
                builder: (context, _) {
                  return SwitchListTile(
                    value: AppState.engine.isRunning,
                    onChanged: (_) async {
                      await AppState.engine.toggle();
                      if (AppState.engine.phase == EnginePhase.error &&
                          AppState.engine.lastError != null) {
                        if (!mounted) return;
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(AppState.engine.lastError!)),
                        );
                      }
                    },
                    title: const Text('Witnessing active'),
                    subtitle: const Text(
                      'Pause to stop collecting new evidence',
                    ),
                  );
                },
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _header() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: const [
        Text(
          'Preferences',
          style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
        ),
        SizedBox(height: 6),
        Text(
          'Control what Witnessd observes and how long raw signals are retained.',
          style: TextStyle(color: WitnessdTheme.mutedText),
        ),
      ],
    );
  }

  Widget _heroCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: WitnessdTheme.surfaceElevated,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.12)),
      ),
      child: Row(
        children: [
          Container(
            width: 56,
            height: 56,
            decoration: BoxDecoration(
              color: WitnessdTheme.accentBlue.withOpacity(0.12),
              borderRadius: BorderRadius.circular(16),
            ),
            child: const Icon(
              Icons.security_rounded,
              color: WitnessdTheme.accentBlue,
              size: 28,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: const [
                Text(
                  'Security Posture',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                    color: WitnessdTheme.strongText,
                  ),
                ),
                SizedBox(height: 6),
                Text(
                  'Witnessd is running with secure logging enabled and background capture active.',
                  style: TextStyle(color: WitnessdTheme.mutedText),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: WitnessdTheme.secureGreen.withOpacity(0.12),
              borderRadius: BorderRadius.circular(999),
              border: Border.all(
                color: WitnessdTheme.secureGreen.withOpacity(0.3),
              ),
            ),
            child: const Text(
              'Healthy',
              style: TextStyle(
                color: WitnessdTheme.strongText,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _emptyWatchDirs() {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: WitnessdTheme.darkBackground,
        borderRadius: BorderRadius.circular(12),
      ),
      child: const Text(
        'No watch folders configured yet. Add a folder to begin capturing evidence.',
        style: TextStyle(color: WitnessdTheme.mutedText),
      ),
    );
  }

  Widget _dirRow(String path, VoidCallback onRemove) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
      decoration: BoxDecoration(
        color: WitnessdTheme.darkBackground,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        children: [
          Expanded(child: Text(path, overflow: TextOverflow.ellipsis)),
          IconButton(
            onPressed: onRemove,
            icon: const Icon(Icons.close, size: 18),
          ),
        ],
      ),
    );
  }
}
