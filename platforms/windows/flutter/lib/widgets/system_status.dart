import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class SystemStatusSection extends ConsumerWidget {
  const SystemStatusSection({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'System',
          style: theme.typography.bodyStrong?.copyWith(
            color: theme.resources.textFillColorSecondary,
          ),
        ),
        const SizedBox(height: WindowsTheme.spacingSM),
        Card(
          padding: const EdgeInsets.symmetric(
            horizontal: WindowsTheme.spacingXS,
            vertical: WindowsTheme.spacingXS,
          ),
          child: Column(
            children: [
              _SystemStatusRow(
                icon: FluentIcons.speed_high,
                title: 'VDF',
                value: state.status.vdfCalibrated ? 'Calibrated' : 'Not calibrated',
                isGood: state.status.vdfCalibrated,
                action: state.status.vdfCalibrated
                    ? null
                    : () => ref.read(witnessdServiceProvider.notifier).calibrate(),
              ),
              _SystemStatusRow(
                icon: FluentIcons.processing,
                title: 'TPM',
                value: state.status.tpmAvailable ? 'Available' : 'Unavailable',
                isGood: state.status.tpmAvailable,
              ),
              _SystemStatusRow(
                icon: FluentIcons.database,
                title: 'Database',
                value: '${state.status.databaseEvents} events',
                isGood: true,
              ),
            ],
          ),
        ),
      ],
    );
  }
}

class _SystemStatusRow extends StatefulWidget {
  final IconData icon;
  final String title;
  final String value;
  final bool isGood;
  final VoidCallback? action;

  const _SystemStatusRow({
    required this.icon,
    required this.title,
    required this.value,
    required this.isGood,
    this.action,
  });

  @override
  State<_SystemStatusRow> createState() => _SystemStatusRowState();
}

class _SystemStatusRowState extends State<_SystemStatusRow> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return MouseRegion(
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: GestureDetector(
        onTap: widget.action,
        child: Container(
          padding: const EdgeInsets.symmetric(
            horizontal: WindowsTheme.spacingMD,
            vertical: WindowsTheme.spacingSM,
          ),
          decoration: BoxDecoration(
            color: _isHovered && widget.action != null
                ? theme.resources.subtleFillColorSecondary
                : Colors.transparent,
            borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
          ),
          child: Row(
            children: [
              Icon(
                widget.icon,
                size: WindowsTheme.iconSM,
                color: theme.resources.textFillColorTertiary,
              ),
              const SizedBox(width: WindowsTheme.spacingMD),
              Text(
                widget.title,
                style: theme.typography.body,
              ),
              const Spacer(),
              if (widget.action != null) ...[
                // Show as actionable badge
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: WindowsTheme.spacingSM,
                    vertical: WindowsTheme.spacingXXS,
                  ),
                  decoration: BoxDecoration(
                    color: WindowsTheme.warning.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        widget.value,
                        style: theme.typography.caption?.copyWith(
                          color: WindowsTheme.warning,
                        ),
                      ),
                      const SizedBox(width: WindowsTheme.spacingXS),
                      Icon(
                        FluentIcons.chevron_right,
                        size: 10,
                        color: WindowsTheme.warning,
                      ),
                    ],
                  ),
                ),
              ] else ...[
                // Show as status badge
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(
                        color: widget.isGood
                            ? WindowsTheme.success
                            : theme.resources.textFillColorTertiary.withOpacity(0.5),
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: WindowsTheme.spacingXS),
                    Text(
                      widget.value,
                      style: theme.typography.caption?.copyWith(
                        color: theme.resources.textFillColorSecondary,
                      ),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
