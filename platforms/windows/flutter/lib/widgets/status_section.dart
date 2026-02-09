import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class StatusSection extends ConsumerWidget {
  const StatusSection({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    if (!state.status.isTracking) {
      return const SizedBox.shrink();
    }

    return Card(
      padding: const EdgeInsets.all(WindowsTheme.spacingMD),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                FluentIcons.edit,
                size: WindowsTheme.iconSM,
                color: WindowsTheme.success,
              ),
              const SizedBox(width: WindowsTheme.spacingSM),
              Text(
                'Active Tracking Session',
                style: theme.typography.bodyStrong,
              ),
            ],
          ),

          const SizedBox(height: WindowsTheme.spacingMD),

          // Document being tracked
          if (state.status.trackingDocument != null) ...[
            _InfoRow(
              label: 'Document',
              value: _getFileName(state.status.trackingDocument!),
            ),
            const SizedBox(height: WindowsTheme.spacingSM),
          ],

          // Stats row
          Row(
            children: [
              Expanded(
                child: _StatWidget(
                  icon: FluentIcons.keyboard_classic,
                  value: '${state.status.keystrokeCount}',
                  label: 'Keystrokes',
                ),
              ),
              Container(
                width: 1,
                height: 40,
                color: theme.resources.dividerStrokeColorDefault,
              ),
              Expanded(
                child: _StatWidget(
                  icon: FluentIcons.clock,
                  value: state.status.trackingDuration.isEmpty
                      ? '0:00'
                      : state.status.trackingDuration,
                  label: 'Duration',
                ),
              ),
            ],
          ),

          const SizedBox(height: WindowsTheme.spacingMD),

          // Stop button
          SizedBox(
            width: double.infinity,
            child: Button(
              onPressed: () {
                ref.read(witnessdServiceProvider.notifier).stopTracking();
              },
              child: const Text('Stop Tracking'),
            ),
          ),
        ],
      ),
    );
  }

  String _getFileName(String path) {
    final parts = path.split(RegExp(r'[/\\]'));
    return parts.isNotEmpty ? parts.last : path;
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;

  const _InfoRow({
    required this.label,
    required this.value,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return Row(
      children: [
        Text(
          '$label: ',
          style: theme.typography.caption?.copyWith(
            color: theme.resources.textFillColorSecondary,
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: theme.typography.body,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }
}

class _StatWidget extends StatelessWidget {
  final IconData icon;
  final String value;
  final String label;

  const _StatWidget({
    required this.icon,
    required this.value,
    required this.label,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return Padding(
      padding: const EdgeInsets.symmetric(
        horizontal: WindowsTheme.spacingMD,
      ),
      child: Row(
        children: [
          Icon(
            icon,
            size: WindowsTheme.iconSM,
            color: theme.resources.textFillColorTertiary,
          ),
          const SizedBox(width: WindowsTheme.spacingSM),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
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
          ),
        ],
      ),
    );
  }
}
