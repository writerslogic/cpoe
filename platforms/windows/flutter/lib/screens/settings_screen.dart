import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  int _selectedTab = 0;

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return ScaffoldPage.scrollable(
      header: PageHeader(
        title: const Text('Settings'),
      ),
      children: [
        // Tab navigation
        SizedBox(
          width: double.infinity,
          child: TabView(
            currentIndex: _selectedTab,
            onChanged: (index) => setState(() => _selectedTab = index),
            tabWidthBehavior: TabWidthBehavior.sizeToContent,
            closeButtonVisibility: CloseButtonVisibilityMode.never,
            tabs: const [
              Tab(text: Text('General')),
              Tab(text: Text('Tracking')),
              Tab(text: Text('Security')),
              Tab(text: Text('Notifications')),
              Tab(text: Text('Advanced')),
            ],
            bodies: [
              _buildGeneralTab(context, theme),
              _buildTrackingTab(context, theme),
              _buildSecurityTab(context, theme),
              _buildNotificationsTab(context, theme),
              _buildAdvancedTab(context, theme),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildGeneralTab(BuildContext context, FluentThemeData theme) {
    final settings = ref.read(witnessdServiceProvider.notifier).settings;

    return Padding(
      padding: const EdgeInsets.all(WindowsTheme.spacingLG),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Startup section
          _buildSectionHeader(theme, 'Startup'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: ToggleSwitch(
              checked: settings?.openAtLogin ?? false,
              content: const Text('Open Witnessd at login'),
              onChanged: (value) async {
                await settings?.setOpenAtLogin(value);
                setState(() {});
              },
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // Auto-checkpoint section
          _buildSectionHeader(theme, 'Auto-Checkpoint'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                ToggleSwitch(
                  checked: settings?.autoCheckpoint ?? false,
                  content: const Text('Automatically create checkpoints'),
                  onChanged: (value) async {
                    await settings?.setAutoCheckpoint(value);
                    setState(() {});
                  },
                ),
                if (settings?.autoCheckpoint ?? false) ...[
                  const SizedBox(height: WindowsTheme.spacingMD),
                  Row(
                    children: [
                      const Text('Interval: '),
                      const SizedBox(width: WindowsTheme.spacingSM),
                      ComboBox<int>(
                        value: settings?.checkpointIntervalMinutes ?? 30,
                        items: const [
                          ComboBoxItem(value: 5, child: Text('5 minutes')),
                          ComboBoxItem(value: 15, child: Text('15 minutes')),
                          ComboBoxItem(value: 30, child: Text('30 minutes')),
                          ComboBoxItem(value: 60, child: Text('1 hour')),
                          ComboBoxItem(value: 120, child: Text('2 hours')),
                        ],
                        onChanged: (value) async {
                          if (value != null) {
                            await settings?.setCheckpointIntervalMinutes(value);
                            setState(() {});
                          }
                        },
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTrackingTab(BuildContext context, FluentThemeData theme) {
    final settings = ref.read(witnessdServiceProvider.notifier).settings;

    return Padding(
      padding: const EdgeInsets.all(WindowsTheme.spacingLG),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // File patterns section
          _buildSectionHeader(theme, 'File Extensions'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Only track files with these extensions:',
                  style: theme.typography.caption,
                ),
                const SizedBox(height: WindowsTheme.spacingSM),
                Wrap(
                  spacing: WindowsTheme.spacingXS,
                  runSpacing: WindowsTheme.spacingXS,
                  children: (settings?.includePatterns ?? []).map((pattern) {
                    return Chip(
                      text: Text(pattern),
                      onPressed: () async {
                        await settings?.removeIncludePattern(pattern);
                        setState(() {});
                      },
                    );
                  }).toList(),
                ),
                const SizedBox(height: WindowsTheme.spacingSM),
                _AddPatternField(
                  onAdd: (pattern) async {
                    await settings?.addIncludePattern(pattern);
                    setState(() {});
                  },
                ),
              ],
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // Quick presets
          _buildSectionHeader(theme, 'Quick Presets'),
          const SizedBox(height: WindowsTheme.spacingSM),
          Row(
            children: [
              Button(
                child: const Text('Text Files'),
                onPressed: () async {
                  for (final ext in ['.txt', '.md', '.rtf']) {
                    await settings?.addIncludePattern(ext);
                  }
                  setState(() {});
                },
              ),
              const SizedBox(width: WindowsTheme.spacingSM),
              Button(
                child: const Text('Documents'),
                onPressed: () async {
                  for (final ext in ['.doc', '.docx', '.odt', '.pdf']) {
                    await settings?.addIncludePattern(ext);
                  }
                  setState(() {});
                },
              ),
              const SizedBox(width: WindowsTheme.spacingSM),
              Button(
                child: const Text('Code'),
                onPressed: () async {
                  for (final ext in ['.js', '.ts', '.py', '.go', '.rs']) {
                    await settings?.addIncludePattern(ext);
                  }
                  setState(() {});
                },
              ),
            ],
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // Debounce interval
          _buildSectionHeader(theme, 'Performance'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Debounce Interval'),
                const SizedBox(height: WindowsTheme.spacingSM),
                Row(
                  children: [
                    Expanded(
                      child: Slider(
                        value: (settings?.debounceIntervalMs ?? 500).toDouble(),
                        min: 100,
                        max: 2000,
                        divisions: 19,
                        onChanged: (value) async {
                          await settings?.setDebounceIntervalMs(value.toInt());
                          setState(() {});
                        },
                      ),
                    ),
                    const SizedBox(width: WindowsTheme.spacingMD),
                    SizedBox(
                      width: 70,
                      child: Text(
                        '${settings?.debounceIntervalMs ?? 500} ms',
                        style: theme.typography.body,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: WindowsTheme.spacingXS),
                Text(
                  'Time to wait after the last keystroke before saving.',
                  style: theme.typography.caption?.copyWith(
                    color: theme.resources.textFillColorSecondary,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityTab(BuildContext context, FluentThemeData theme) {
    final state = ref.watch(witnessdServiceProvider);
    final serviceNotifier = ref.read(witnessdServiceProvider.notifier);

    return Padding(
      padding: const EdgeInsets.all(WindowsTheme.spacingLG),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // TPM Attestation
          _buildSectionHeader(theme, 'Hardware Attestation'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      state.status.tpmAvailable
                          ? FluentIcons.shield
                          : FluentIcons.warning,
                      color: state.status.tpmAvailable
                          ? WindowsTheme.success
                          : WindowsTheme.warning,
                    ),
                    const SizedBox(width: WindowsTheme.spacingSM),
                    Text(
                      state.status.tpmAvailable
                          ? 'TPM is available'
                          : 'TPM is not available',
                      style: theme.typography.body,
                    ),
                  ],
                ),
                if (state.status.tpmAvailable) ...[
                  const SizedBox(height: WindowsTheme.spacingMD),
                  ToggleSwitch(
                    checked: serviceNotifier.settings?.tpmAttestationEnabled ?? false,
                    content: const Text('Enable TPM attestation'),
                    onChanged: (value) async {
                      await serviceNotifier.settings?.setTpmAttestationEnabled(value);
                      setState(() {});
                    },
                  ),
                ],
              ],
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // VDF Calibration
          _buildSectionHeader(theme, 'VDF Timing Proofs'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(
                      state.status.vdfCalibrated
                          ? FluentIcons.check_mark
                          : FluentIcons.warning,
                      color: state.status.vdfCalibrated
                          ? WindowsTheme.success
                          : WindowsTheme.warning,
                    ),
                    const SizedBox(width: WindowsTheme.spacingSM),
                    Text(
                      state.status.vdfCalibrated
                          ? 'VDF Calibrated'
                          : 'VDF Not Calibrated',
                      style: theme.typography.body,
                    ),
                  ],
                ),
                if (state.status.vdfIterPerSec.isNotEmpty) ...[
                  const SizedBox(height: WindowsTheme.spacingXS),
                  Text(
                    'Performance: ${state.status.vdfIterPerSec} iterations/sec',
                    style: theme.typography.caption?.copyWith(
                      color: theme.resources.textFillColorSecondary,
                      fontFamily: 'Consolas',
                    ),
                  ),
                ],
                const SizedBox(height: WindowsTheme.spacingMD),
                Button(
                  onPressed: state.isLoading
                      ? null
                      : () async {
                          await serviceNotifier.calibrate();
                        },
                  child: const Text('Recalibrate VDF'),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNotificationsTab(BuildContext context, FluentThemeData theme) {
    final settings = ref.read(witnessdServiceProvider.notifier).settings;

    return Padding(
      padding: const EdgeInsets.all(WindowsTheme.spacingLG),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildSectionHeader(theme, 'Alerts'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: ToggleSwitch(
              checked: settings?.showNotifications ?? true,
              content: const Text('Show notifications'),
              onChanged: (value) async {
                await settings?.setShowNotifications(value);
                setState(() {});
              },
            ),
          ),
          const SizedBox(height: WindowsTheme.spacingSM),
          Text(
            'Receive notifications when tracking starts, stops, or when checkpoints are created.',
            style: theme.typography.caption?.copyWith(
              color: theme.resources.textFillColorSecondary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAdvancedTab(BuildContext context, FluentThemeData theme) {
    final serviceNotifier = ref.read(witnessdServiceProvider.notifier);

    return Padding(
      padding: const EdgeInsets.all(WindowsTheme.spacingLG),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Data location
          _buildSectionHeader(theme, 'Storage'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('Data Location'),
                      const SizedBox(height: WindowsTheme.spacingXS),
                      Text(
                        serviceNotifier.dataDirectoryPath,
                        style: theme.typography.caption?.copyWith(
                          color: theme.resources.textFillColorSecondary,
                          fontFamily: 'Consolas',
                        ),
                      ),
                    ],
                  ),
                ),
                Button(
                  onPressed: () {
                    launchUrl(Uri.file(serviceNotifier.dataDirectoryPath));
                  },
                  child: const Text('Open'),
                ),
              ],
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // Export defaults
          _buildSectionHeader(theme, 'Export Defaults'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    const Text('Default Format: '),
                    const SizedBox(width: WindowsTheme.spacingSM),
                    ComboBox<String>(
                      value: serviceNotifier.settings?.defaultExportFormat ?? 'json',
                      items: const [
                        ComboBoxItem(value: 'json', child: Text('JSON')),
                        ComboBoxItem(value: 'cbor', child: Text('CBOR')),
                      ],
                      onChanged: (value) async {
                        if (value != null) {
                          await serviceNotifier.settings?.setDefaultExportFormat(value);
                          setState(() {});
                        }
                      },
                    ),
                  ],
                ),
                const SizedBox(height: WindowsTheme.spacingMD),
                Row(
                  children: [
                    const Text('Default Tier: '),
                    const SizedBox(width: WindowsTheme.spacingSM),
                    ComboBox<String>(
                      value: serviceNotifier.settings?.defaultExportTier ?? 'standard',
                      items: const [
                        ComboBoxItem(value: 'basic', child: Text('Basic')),
                        ComboBoxItem(value: 'standard', child: Text('Standard')),
                        ComboBoxItem(value: 'enhanced', child: Text('Enhanced')),
                        ComboBoxItem(value: 'maximum', child: Text('Maximum')),
                      ],
                      onChanged: (value) async {
                        if (value != null) {
                          await serviceNotifier.settings?.setDefaultExportTier(value);
                          setState(() {});
                        }
                      },
                    ),
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: WindowsTheme.spacingXL),

          // Help links
          _buildSectionHeader(theme, 'Help'),
          const SizedBox(height: WindowsTheme.spacingSM),
          _buildSettingsCard(
            theme,
            child: Column(
              children: [
                ListTile(
                  leading: const Icon(FluentIcons.book_answers),
                  title: const Text('Documentation'),
                  trailing: const Icon(FluentIcons.open_in_new_window, size: 12),
                  onPressed: () {
                    launchUrl(Uri.parse('https://github.com/witnessd/witnessd'));
                  },
                ),
                ListTile(
                  leading: const Icon(FluentIcons.bug),
                  title: const Text('Report Issue'),
                  trailing: const Icon(FluentIcons.open_in_new_window, size: 12),
                  onPressed: () {
                    launchUrl(Uri.parse('https://github.com/witnessd/witnessd/issues'));
                  },
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(FluentThemeData theme, String title) {
    return Text(
      title,
      style: theme.typography.bodyStrong?.copyWith(
        color: theme.resources.textFillColorSecondary,
      ),
    );
  }

  Widget _buildSettingsCard(
    FluentThemeData theme, {
    required Widget child,
  }) {
    return Card(
      padding: const EdgeInsets.all(WindowsTheme.spacingMD),
      child: child,
    );
  }
}

class _AddPatternField extends StatefulWidget {
  final Function(String) onAdd;

  const _AddPatternField({required this.onAdd});

  @override
  State<_AddPatternField> createState() => _AddPatternFieldState();
}

class _AddPatternFieldState extends State<_AddPatternField> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: TextBox(
            controller: _controller,
            placeholder: 'Add extension (e.g., .md)',
            onSubmitted: _submit,
          ),
        ),
        const SizedBox(width: WindowsTheme.spacingSM),
        Button(
          onPressed: _submit,
          child: const Text('Add'),
        ),
      ],
    );
  }

  void _submit([String? _]) {
    final text = _controller.text.trim();
    if (text.isNotEmpty) {
      widget.onAdd(text);
      _controller.clear();
    }
  }
}
