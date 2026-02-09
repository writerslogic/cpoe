import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';
import '../widgets/header_bar.dart';
import '../widgets/status_section.dart';
import '../widgets/sentinel_card.dart';
import '../widgets/quick_actions.dart';
import '../widgets/system_status.dart';
import 'settings_screen.dart';
import 'history_screen.dart';

class MainScreen extends ConsumerStatefulWidget {
  const MainScreen({super.key});

  @override
  ConsumerState<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends ConsumerState<MainScreen> {
  int _currentPage = 0;

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    return NavigationView(
      appBar: NavigationAppBar(
        height: 40,
        title: const DragToMoveArea(
          child: Align(
            alignment: AlignmentDirectional.centerStart,
            child: Text('Witnessd'),
          ),
        ),
        leading: const SizedBox.shrink(),
        actions: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Loading indicator
            if (state.isLoading)
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(
                      width: 14,
                      height: 14,
                      child: ProgressRing(strokeWidth: 2),
                    ),
                    if (state.loadingMessage.isNotEmpty)
                      Padding(
                        padding: const EdgeInsets.only(left: 8),
                        child: Text(
                          state.loadingMessage,
                          style: theme.typography.caption,
                        ),
                      ),
                  ],
                ),
              ),

            // Window controls
            const WindowButtons(),
          ],
        ),
      ),
      pane: NavigationPane(
        selected: _currentPage,
        onChanged: (index) => setState(() => _currentPage = index),
        displayMode: PaneDisplayMode.compact,
        items: [
          PaneItem(
            icon: const Icon(FluentIcons.home),
            title: const Text('Home'),
            body: _buildHomeContent(context, theme, state),
          ),
          PaneItem(
            icon: const Icon(FluentIcons.history),
            title: const Text('History'),
            body: const HistoryScreen(),
          ),
        ],
        footerItems: [
          PaneItem(
            icon: const Icon(FluentIcons.settings),
            title: const Text('Settings'),
            body: const SettingsScreen(),
          ),
        ],
      ),
    );
  }

  Widget _buildHomeContent(
    BuildContext context,
    FluentThemeData theme,
    WitnessdState state,
  ) {
    return ScaffoldPage(
      padding: EdgeInsets.zero,
      content: SingleChildScrollView(
        padding: const EdgeInsets.all(WindowsTheme.spacingLG),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header with status
            const HeaderBar(),

            const SizedBox(height: WindowsTheme.spacingLG),

            // Main content based on initialization state
            if (!state.status.isInitialized)
              _buildSetupRequired(context, theme)
            else ...[
              // Sentinel card
              const SentinelCard(),

              const SizedBox(height: WindowsTheme.spacingLG),

              // Quick actions
              const QuickActionsSection(),

              const SizedBox(height: WindowsTheme.spacingLG),

              // System status
              const SystemStatusSection(),
            ],

            // Error display
            if (state.lastError != null)
              Padding(
                padding: const EdgeInsets.only(top: WindowsTheme.spacingLG),
                child: InfoBar(
                  title: const Text('Error'),
                  content: Text(state.lastError!),
                  severity: InfoBarSeverity.error,
                  isLong: true,
                  onClose: () {
                    ref.read(witnessdServiceProvider.notifier).clearError();
                  },
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSetupRequired(BuildContext context, FluentThemeData theme) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(height: WindowsTheme.spacingXXL),

          // Hero icon
          Container(
            width: 80,
            height: 80,
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  theme.accentColor,
                  theme.accentColor.lighter,
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(WindowsTheme.radiusLG),
            ),
            child: const Icon(
              FluentIcons.star_burst,
              size: WindowsTheme.iconHero,
              color: Colors.white,
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          Text(
            'Welcome to Witnessd',
            style: theme.typography.title,
          ),

          const SizedBox(height: WindowsTheme.spacingSM),

          Text(
            'Set up Witnessd to start creating cryptographic\nproof of your authorship.',
            style: theme.typography.body?.copyWith(
              color: theme.resources.textFillColorSecondary,
            ),
            textAlign: TextAlign.center,
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          FilledButton(
            onPressed: () async {
              await ref
                  .read(witnessdServiceProvider.notifier)
                  .initializeWitnessd();
            },
            child: const Padding(
              padding: EdgeInsets.symmetric(
                horizontal: WindowsTheme.spacingLG,
                vertical: WindowsTheme.spacingSM,
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(FluentIcons.play),
                  SizedBox(width: WindowsTheme.spacingSM),
                  Text('Get Started'),
                ],
              ),
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXXL),
        ],
      ),
    );
  }
}

/// Custom window buttons for Windows 11 style
class WindowButtons extends StatelessWidget {
  const WindowButtons({super.key});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        _WindowButton(
          icon: FluentIcons.chrome_minimize,
          onPressed: () => windowManager.minimize(),
        ),
        _WindowButton(
          icon: FluentIcons.chrome_close,
          onPressed: () => windowManager.hide(),
          isClose: true,
        ),
      ],
    );
  }
}

class _WindowButton extends StatefulWidget {
  final IconData icon;
  final VoidCallback onPressed;
  final bool isClose;

  const _WindowButton({
    required this.icon,
    required this.onPressed,
    this.isClose = false,
  });

  @override
  State<_WindowButton> createState() => _WindowButtonState();
}

class _WindowButtonState extends State<_WindowButton> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return MouseRegion(
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: GestureDetector(
        onTap: widget.onPressed,
        child: Container(
          width: 46,
          height: 40,
          color: _isHovered
              ? (widget.isClose ? Colors.red : theme.resources.subtleFillColorSecondary)
              : Colors.transparent,
          child: Icon(
            widget.icon,
            size: 10,
            color: _isHovered && widget.isClose
                ? Colors.white
                : theme.resources.textFillColorPrimary,
          ),
        ),
      ),
    );
  }
}
