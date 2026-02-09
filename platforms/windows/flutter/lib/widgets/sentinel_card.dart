import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class SentinelCard extends ConsumerWidget {
  const SentinelCard({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Document Tracking',
          style: theme.typography.bodyStrong?.copyWith(
            color: theme.resources.textFillColorSecondary,
          ),
        ),
        const SizedBox(height: WindowsTheme.spacingSM),
        Card(
          padding: const EdgeInsets.all(WindowsTheme.spacingMD),
          child: Column(
            children: [
              // Status row
              Row(
                children: [
                  Container(
                    width: 40,
                    height: 40,
                    decoration: BoxDecoration(
                      color: state.sentinelStatus.isRunning
                          ? WindowsTheme.success.withOpacity(0.15)
                          : theme.resources.subtleFillColorSecondary,
                      borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
                    ),
                    child: Icon(
                      state.sentinelStatus.isRunning
                          ? FluentIcons.view
                          : FluentIcons.hide3,
                      color: state.sentinelStatus.isRunning
                          ? WindowsTheme.success
                          : theme.resources.textFillColorTertiary,
                    ),
                  ),
                  const SizedBox(width: WindowsTheme.spacingMD),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          state.sentinelStatus.isRunning
                              ? 'Sentinel Active'
                              : 'Sentinel Stopped',
                          style: theme.typography.body,
                        ),
                        const SizedBox(height: WindowsTheme.spacingXXS),
                        Text(
                          state.sentinelStatus.isRunning
                              ? 'Tracking focused documents automatically'
                              : 'Start sentinel to track documents as you work',
                          style: theme.typography.caption?.copyWith(
                            color: theme.resources.textFillColorSecondary,
                          ),
                        ),
                      ],
                    ),
                  ),
                  _SentinelToggleButton(
                    isRunning: state.sentinelStatus.isRunning,
                    isLoading: state.isLoading,
                    onPressed: () {
                      if (state.sentinelStatus.isRunning) {
                        ref.read(witnessdServiceProvider.notifier).stopSentinel();
                      } else {
                        ref.read(witnessdServiceProvider.notifier).startSentinel();
                      }
                    },
                  ),
                ],
              ),

              // Additional info when stopped
              if (!state.sentinelStatus.isRunning) ...[
                const SizedBox(height: WindowsTheme.spacingMD),
                Container(
                  padding: const EdgeInsets.all(WindowsTheme.spacingSM),
                  decoration: BoxDecoration(
                    color: theme.resources.subtleFillColorSecondary,
                    borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
                  ),
                  child: Row(
                    children: [
                      Icon(
                        FluentIcons.info,
                        size: WindowsTheme.iconSM,
                        color: theme.resources.textFillColorTertiary,
                      ),
                      const SizedBox(width: WindowsTheme.spacingSM),
                      Expanded(
                        child: Text(
                          'The sentinel monitors which document has focus and automatically creates checkpoints when you save.',
                          style: theme.typography.caption?.copyWith(
                            color: theme.resources.textFillColorTertiary,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],

              // Stats when running
              if (state.sentinelStatus.isRunning) ...[
                const SizedBox(height: WindowsTheme.spacingMD),
                const Divider(),
                const SizedBox(height: WindowsTheme.spacingMD),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _SentinelStat(
                      icon: FluentIcons.document,
                      value: '${state.sentinelStatus.trackedDocuments}',
                      label: 'Documents',
                    ),
                    _SentinelStat(
                      icon: FluentIcons.clock,
                      value: state.sentinelStatus.uptime.isEmpty
                          ? 'Just started'
                          : state.sentinelStatus.uptime,
                      label: 'Uptime',
                    ),
                    _SentinelStat(
                      icon: FluentIcons.database,
                      value: '${state.status.databaseEvents}',
                      label: 'Events',
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
}

class _SentinelToggleButton extends StatelessWidget {
  final bool isRunning;
  final bool isLoading;
  final VoidCallback onPressed;

  const _SentinelToggleButton({
    required this.isRunning,
    required this.isLoading,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    if (isLoading) {
      return const SizedBox(
        width: 32,
        height: 32,
        child: ProgressRing(strokeWidth: 2),
      );
    }

    return Button(
      onPressed: onPressed,
      child: Icon(
        isRunning ? FluentIcons.stop : FluentIcons.play,
        size: WindowsTheme.iconSM,
      ),
    );
  }
}

class _SentinelStat extends StatelessWidget {
  final IconData icon;
  final String value;
  final String label;

  const _SentinelStat({
    required this.icon,
    required this.value,
    required this.label,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return Column(
      children: [
        Icon(
          icon,
          size: WindowsTheme.iconSM,
          color: theme.resources.textFillColorTertiary,
        ),
        const SizedBox(height: WindowsTheme.spacingXS),
        Text(
          value,
          style: theme.typography.bodyStrong,
        ),
        Text(
          label,
          style: theme.typography.caption?.copyWith(
            color: theme.resources.textFillColorTertiary,
          ),
        ),
      ],
    );
  }
}
