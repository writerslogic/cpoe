import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class HeaderBar extends ConsumerWidget {
  const HeaderBar({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    return Row(
      children: [
        // App icon with status indicator
        Stack(
          children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: state.sentinelStatus.isRunning
                      ? [theme.accentColor, theme.accentColor.lighter]
                      : [
                          theme.resources.subtleFillColorSecondary,
                          theme.resources.subtleFillColorTertiary,
                        ],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(WindowsTheme.radiusMD),
              ),
              child: Icon(
                state.sentinelStatus.isRunning
                    ? FluentIcons.view
                    : FluentIcons.hide3,
                size: WindowsTheme.iconLG,
                color: state.sentinelStatus.isRunning
                    ? Colors.white
                    : theme.resources.textFillColorSecondary,
              ),
            ),
            // Status dot
            if (state.sentinelStatus.isRunning)
              Positioned(
                right: -2,
                bottom: -2,
                child: Container(
                  width: 14,
                  height: 14,
                  decoration: BoxDecoration(
                    color: WindowsTheme.success,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: theme.scaffoldBackgroundColor,
                      width: 2,
                    ),
                  ),
                ),
              ),
          ],
        ),

        const SizedBox(width: WindowsTheme.spacingMD),

        // Title and status
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Witnessd',
                style: theme.typography.subtitle,
              ),
              const SizedBox(height: WindowsTheme.spacingXXS),
              _StatusBadge(
                text: _getStatusText(state),
                style: _getStatusStyle(state),
              ),
            ],
          ),
        ),

        // Refresh button
        IconButton(
          icon: const Icon(FluentIcons.refresh),
          onPressed: () {
            ref.read(witnessdServiceProvider.notifier).refreshStatus();
          },
        ),
      ],
    );
  }

  String _getStatusText(WitnessdState state) {
    if (state.sentinelStatus.isRunning) {
      final docCount = state.sentinelStatus.trackedDocuments;
      return 'Active - $docCount document${docCount == 1 ? '' : 's'}';
    } else if (state.status.isInitialized) {
      return 'Ready';
    } else {
      return 'Setup Required';
    }
  }

  _BadgeStyle _getStatusStyle(WitnessdState state) {
    if (state.sentinelStatus.isRunning) {
      return _BadgeStyle.success;
    } else if (state.status.isInitialized) {
      return _BadgeStyle.neutral;
    } else {
      return _BadgeStyle.warning;
    }
  }
}

enum _BadgeStyle { success, warning, neutral }

class _StatusBadge extends StatelessWidget {
  final String text;
  final _BadgeStyle style;

  const _StatusBadge({
    required this.text,
    required this.style,
  });

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    Color backgroundColor;
    Color textColor;
    Color dotColor;

    switch (style) {
      case _BadgeStyle.success:
        backgroundColor = WindowsTheme.success.withOpacity(0.15);
        textColor = WindowsTheme.success;
        dotColor = WindowsTheme.success;
        break;
      case _BadgeStyle.warning:
        backgroundColor = WindowsTheme.warning.withOpacity(0.15);
        textColor = WindowsTheme.warning;
        dotColor = WindowsTheme.warning;
        break;
      case _BadgeStyle.neutral:
        backgroundColor = theme.resources.subtleFillColorSecondary;
        textColor = theme.resources.textFillColorSecondary;
        dotColor = theme.resources.textFillColorTertiary;
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: WindowsTheme.spacingSM,
        vertical: WindowsTheme.spacingXXS,
      ),
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 6,
            height: 6,
            decoration: BoxDecoration(
              color: dotColor,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: WindowsTheme.spacingXS),
          Text(
            text,
            style: theme.typography.caption?.copyWith(
              color: textColor,
            ),
          ),
        ],
      ),
    );
  }
}
