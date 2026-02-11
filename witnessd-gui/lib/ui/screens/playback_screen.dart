import 'package:flutter/material.dart';
import '../../bridge.dart';
import '../theme.dart';
import '../widgets/cta_buttons.dart';

class PlaybackScreen extends StatefulWidget {
  final String filePath;
  final String fileName;

  const PlaybackScreen({
    super.key,
    required this.filePath,
    required this.fileName,
  });

  @override
  State<PlaybackScreen> createState() => _PlaybackScreenState();
}

class _PlaybackScreenState extends State<PlaybackScreen> {
  List<FrbCheckpointInfo> _checkpoints = [];
  int _currentIndex = 0;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  Future<void> _loadHistory() async {
    try {
      final history = await getDocumentLog(path: widget.filePath);
      if (!mounted) return;
      setState(() {
        _checkpoints = history;
        _currentIndex = history.isNotEmpty ? history.length - 1 : 0;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: WitnessdTheme.darkBackground,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.fileName, style: const TextStyle(fontSize: 16)),
            const Text('Time Machine Playback', style: TextStyle(fontSize: 12, color: WitnessdTheme.mutedText)),
          ],
        ),
      ),
      body: _loading 
        ? const Center(child: CircularProgressIndicator())
        : _error != null 
          ? Center(child: Text(_error!, style: const TextStyle(color: WitnessdTheme.warningRed)))
          : _checkpoints.isEmpty
            ? const Center(child: Text('No history found for this file.'))
            : _buildContent(),
    );
  }

  Widget _buildContent() {
    final current = _checkpoints[_currentIndex];
    
    return Column(
      children: [
        // Visual Preview Placeholder
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: WitnessdTheme.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.2)),
            ),
            child: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  const Icon(Icons.history_edu_rounded, size: 64, color: WitnessdTheme.accentBlue),
                  const SizedBox(height: 16),
                  Text(
                    'Checkpoint #${current.ordinal}',
                    style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Hash: ${current.contentHash.substring(0, 12)}...',
                    style: const TextStyle(fontFamily: 'Menlo', color: WitnessdTheme.mutedText),
                  ),
                  const SizedBox(height: 24),
                  _buildStatsRow(current),
                ],
              ),
            ),
          ),
        ),

        // Controls
        Container(
          padding: const EdgeInsets.all(32),
          decoration: BoxDecoration(
            color: WitnessdTheme.surface,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(32)),
          ),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Sequence: ${_currentIndex + 1} / ${_checkpoints.length}',
                    style: const TextStyle(fontWeight: FontWeight.bold),
                  ),
                  Text(
                    current.timestamp.split('T').first,
                    style: const TextStyle(color: WitnessdTheme.mutedText),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Slider(
                value: _currentIndex.toDouble(),
                min: 0,
                max: (_checkpoints.length - 1).toDouble(),
                divisions: _checkpoints.length > 1 ? _checkpoints.length - 1 : 1,
                onChanged: (val) => setState(() => _currentIndex = val.round()),
                activeColor: WitnessdTheme.accentBlue,
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  IconButton(
                    icon: const Icon(Icons.skip_previous_rounded),
                    onPressed: _currentIndex > 0 ? () => setState(() => _currentIndex--) : null,
                  ),
                  const SizedBox(width: 24),
                  PrimaryButton(
                    icon: Icons.play_arrow_rounded,
                    label: 'Autoplay',
                    onTap: () {}, // TODO: Implement autoplay
                  ),
                  const SizedBox(width: 24),
                  IconButton(
                    icon: const Icon(Icons.skip_next_rounded),
                    onPressed: _currentIndex < _checkpoints.length - 1 ? () => setState(() => _currentIndex++) : null,
                  ),
                ],
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildStatsRow(FrbCheckpointInfo cp) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        _miniStat('Size', '${cp.contentSize}B'),
        const SizedBox(width: 24),
        _miniStat('VDF Proof', cp.hasVdfProof ? 'Verified' : 'None'),
        if (cp.elapsedTimeSecs != null) ...[
          const SizedBox(width: 24),
          _miniStat('Time', '${cp.elapsedTimeSecs!.toStringAsFixed(1)}s'),
        ],
      ],
    );
  }

  Widget _miniStat(String label, String value) {
    return Column(
      children: [
        Text(label, style: const TextStyle(fontSize: 10, color: WitnessdTheme.mutedText)),
        Text(value, style: const TextStyle(fontWeight: FontWeight.bold)),
      ],
    );
  }
}
