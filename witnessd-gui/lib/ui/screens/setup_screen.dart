import 'package:flutter/material.dart';
import '../theme.dart';

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  int _step = 0;
  final List<String> _mnemonic = List.filled(12, "...");
  bool _wordsConfirmed = false;

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
            width: 720,
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
                  offset: const Offset(0, 14),
                ),
              ],
            ),
            child: _buildStep(),
          ),
        ),
      ),
    );
  }

  Widget _buildStep() {
    switch (_step) {
      case 0:
        return _introStep();
      case 1:
        return _mnemonicStep();
      case 2:
        return _confirmStep();
      default:
        return Container();
    }
  }

  Widget _introStep() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        _stepHeader(
          icon: Icons.security_rounded,
          title: 'Initialize Your Identity',
          subtitle:
              'Witnessd will generate a unique physical signature for your machine. Secure your 12-word recovery phrase to own your authorship records.',
        ),
        const Text(
          'Step 1 of 3',
          style: TextStyle(color: WitnessdTheme.mutedText, letterSpacing: 1),
        ),
        const SizedBox(height: 32),
        _progressBar(1),
        const SizedBox(height: 36),
        ElevatedButton(
          onPressed: () => setState(() => _step = 1),
          style: ElevatedButton.styleFrom(
            backgroundColor: WitnessdTheme.accentBlue,
            foregroundColor: Colors.white,
            minimumSize: const Size(double.infinity, 56),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
          child: const Text('Generate 12 Words'),
        ),
      ],
    );
  }

  Widget _mnemonicStep() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        _stepHeader(
          icon: Icons.vpn_key_rounded,
          title: 'Your Recovery Phrase',
          subtitle: 'Write these down. They never leave this machine.',
          accent: WitnessdTheme.warningRed,
        ),
        const Text(
          'Step 2 of 3',
          style: TextStyle(color: WitnessdTheme.mutedText, letterSpacing: 1),
        ),
        const SizedBox(height: 16),
        _progressBar(2),
        const SizedBox(height: 32),
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: WitnessdTheme.surfaceElevated,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: WitnessdTheme.accentBlue.withOpacity(0.08),
            ),
          ),
          child: Wrap(
            spacing: 12,
            runSpacing: 12,
            children: List.generate(12, (i) => _wordChip(i + 1, 'word')),
          ),
        ),
        const SizedBox(height: 32),
        Row(
          children: [
            Checkbox(
              value: _wordsConfirmed,
              onChanged: (val) => setState(() => _wordsConfirmed = val!),
              activeColor: WitnessdTheme.accentBlue,
            ),
            const Expanded(
              child: Text(
                'I have secured my 12 words in a safe place.',
                style: TextStyle(fontSize: 13),
              ),
            ),
          ],
        ),
        const SizedBox(height: 32),
        ElevatedButton(
          onPressed: _wordsConfirmed ? () => setState(() => _step = 2) : null,
          style: ElevatedButton.styleFrom(
            backgroundColor: WitnessdTheme.accentBlue,
            foregroundColor: Colors.white,
            minimumSize: const Size(double.infinity, 56),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
          ),
          child: const Text('Initialize Silicon Binding'),
        ),
      ],
    );
  }

  Widget _confirmStep() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        _stepHeader(
          icon: Icons.memory_rounded,
          title: 'Binding in Progress',
          subtitle: 'Entangling seed with silicon.',
        ),
        const Text(
          'Step 3 of 3',
          style: TextStyle(color: WitnessdTheme.mutedText, letterSpacing: 1),
        ),
        const SizedBox(height: 16),
        _progressBar(3),
        const SizedBox(height: 24),
        const CircularProgressIndicator(color: WitnessdTheme.accentBlue),
        const SizedBox(height: 20),
        const Text(
          'Measuring thermal jitter and cache-timing PUF.',
          style: TextStyle(color: WitnessdTheme.mutedText, fontSize: 12),
        ),
      ],
    );
  }

  Widget _wordChip(int index, String word) {
    return Container(
      width: 110,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: WitnessdTheme.darkBackground,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: WitnessdTheme.mutedText.withOpacity(0.1)),
      ),
      child: Row(
        children: [
          Text(
            '$index.',
            style: const TextStyle(
              color: WitnessdTheme.mutedText,
              fontSize: 10,
            ),
          ),
          const SizedBox(width: 8),
          Text(
            word,
            style: const TextStyle(
              fontWeight: FontWeight.bold,
              fontFamily: 'Menlo',
            ),
          ),
        ],
      ),
    );
  }

  Widget _progressBar(int step) {
    return Row(
      children: List.generate(
        3,
        (index) => Expanded(
          child: Container(
            margin: EdgeInsets.only(right: index == 2 ? 0 : 8),
            height: 6,
            decoration: BoxDecoration(
              color: step >= index + 1
                  ? WitnessdTheme.accentBlue
                  : WitnessdTheme.surfaceElevated,
              borderRadius: BorderRadius.circular(999),
            ),
          ),
        ),
      ),
    );
  }

  Widget _stepHeader({
    required IconData icon,
    required String title,
    required String subtitle,
    Color accent = WitnessdTheme.accentBlue,
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
        const SizedBox(height: 10),
        Text(
          subtitle,
          textAlign: TextAlign.center,
          style: TextStyle(
            color: accent == WitnessdTheme.warningRed
                ? accent
                : WitnessdTheme.mutedText,
          ),
        ),
        const SizedBox(height: 20),
      ],
    );
  }
}
