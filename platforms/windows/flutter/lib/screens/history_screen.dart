import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path/path.dart' as path;

import '../models/witness_status.dart';
import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class HistoryScreen extends ConsumerStatefulWidget {
  const HistoryScreen({super.key});

  @override
  ConsumerState<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends ConsumerState<HistoryScreen> {
  String _searchQuery = '';
  TrackedFile? _selectedFile;

  @override
  void initState() {
    super.initState();
    // Load tracked files when screen opens
    ref.read(witnessdServiceProvider.notifier).loadTrackedFiles();
  }

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);
    final state = ref.watch(witnessdServiceProvider);

    final filteredFiles = state.trackedFiles.where((file) {
      if (_searchQuery.isEmpty) return true;
      final query = _searchQuery.toLowerCase();
      return file.name.toLowerCase().contains(query) ||
          file.path.toLowerCase().contains(query);
    }).toList();

    return ScaffoldPage(
      header: PageHeader(
        title: const Text('History'),
        commandBar: CommandBar(
          mainAxisAlignment: MainAxisAlignment.end,
          primaryItems: [
            CommandBarButton(
              icon: const Icon(FluentIcons.refresh),
              label: const Text('Refresh'),
              onPressed: () {
                ref.read(witnessdServiceProvider.notifier).loadTrackedFiles();
              },
            ),
          ],
        ),
      ),
      content: Column(
        children: [
          // Search bar
          Padding(
            padding: const EdgeInsets.all(WindowsTheme.spacingMD),
            child: TextBox(
              placeholder: 'Search documents...',
              prefix: const Padding(
                padding: EdgeInsets.only(left: WindowsTheme.spacingSM),
                child: Icon(FluentIcons.search, size: 16),
              ),
              onChanged: (value) {
                setState(() {
                  _searchQuery = value;
                });
              },
            ),
          ),

          // Main content
          Expanded(
            child: filteredFiles.isEmpty
                ? _buildEmptyState(theme)
                : _buildFileList(theme, filteredFiles),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState(FluentThemeData theme) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            FluentIcons.document_set,
            size: WindowsTheme.iconHero,
            color: theme.resources.textFillColorTertiary,
          ),
          const SizedBox(height: WindowsTheme.spacingLG),
          Text(
            _searchQuery.isEmpty
                ? 'No tracked documents yet'
                : 'No documents match your search',
            style: theme.typography.subtitle,
          ),
          const SizedBox(height: WindowsTheme.spacingSM),
          Text(
            _searchQuery.isEmpty
                ? 'Start tracking documents to see them here.'
                : 'Try a different search term.',
            style: theme.typography.body?.copyWith(
              color: theme.resources.textFillColorSecondary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFileList(FluentThemeData theme, List<TrackedFile> files) {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(horizontal: WindowsTheme.spacingMD),
      itemCount: files.length,
      itemBuilder: (context, index) {
        final file = files[index];
        final isSelected = _selectedFile?.id == file.id;

        return Padding(
          padding: const EdgeInsets.only(bottom: WindowsTheme.spacingXS),
          child: ListTile.selectable(
            selected: isSelected,
            onPressed: () {
              setState(() {
                _selectedFile = isSelected ? null : file;
              });
            },
            leading: Container(
              width: 40,
              height: 40,
              decoration: BoxDecoration(
                color: theme.accentColor.withOpacity(0.1),
                borderRadius: BorderRadius.circular(WindowsTheme.radiusSM),
              ),
              child: Icon(
                _getFileIcon(file.name),
                color: theme.accentColor,
              ),
            ),
            title: Text(
              file.name,
              style: theme.typography.body,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            subtitle: Text(
              file.path,
              style: theme.typography.caption?.copyWith(
                color: theme.resources.textFillColorSecondary,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: WindowsTheme.spacingSM,
                    vertical: WindowsTheme.spacingXXS,
                  ),
                  decoration: BoxDecoration(
                    color: theme.resources.subtleFillColorSecondary,
                    borderRadius: BorderRadius.circular(WindowsTheme.radiusXS),
                  ),
                  child: Text(
                    '${file.events} events',
                    style: theme.typography.caption,
                  ),
                ),
                if (isSelected) ...[
                  const SizedBox(width: WindowsTheme.spacingSM),
                  IconButton(
                    icon: const Icon(FluentIcons.export, size: 16),
                    onPressed: () => _exportFile(file),
                  ),
                  IconButton(
                    icon: const Icon(FluentIcons.check_mark, size: 16),
                    onPressed: () => _verifyFile(file),
                  ),
                  IconButton(
                    icon: const Icon(FluentIcons.clock, size: 16),
                    onPressed: () => _viewLog(file),
                  ),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  IconData _getFileIcon(String filename) {
    final ext = path.extension(filename).toLowerCase();
    switch (ext) {
      case '.txt':
      case '.md':
      case '.rtf':
        return FluentIcons.text_document;
      case '.doc':
      case '.docx':
      case '.odt':
        return FluentIcons.document;
      case '.pdf':
        return FluentIcons.pdf;
      case '.js':
      case '.ts':
      case '.py':
      case '.go':
      case '.rs':
      case '.java':
        return FluentIcons.code;
      default:
        return FluentIcons.document;
    }
  }

  Future<void> _exportFile(TrackedFile file) async {
    // Show export dialog
    final tier = await showDialog<String>(
      context: context,
      builder: (context) => _ExportDialog(file: file),
    );

    if (tier != null && mounted) {
      final settings = ref.read(witnessdServiceProvider.notifier).settings;
      final outputPath = '${file.path}.evidence.json';

      final result = await ref.read(witnessdServiceProvider.notifier).export(
            filePath: file.path,
            tier: tier,
            outputPath: outputPath,
          );

      if (mounted) {
        await displayInfoBar(context, builder: (context, close) {
          return InfoBar(
            title: Text(result.success ? 'Evidence Exported' : 'Export Failed'),
            content: Text(result.message),
            severity: result.success ? InfoBarSeverity.success : InfoBarSeverity.error,
            action: IconButton(
              icon: const Icon(FluentIcons.clear),
              onPressed: close,
            ),
          );
        });
      }
    }
  }

  Future<void> _verifyFile(TrackedFile file) async {
    final result = await ref.read(witnessdServiceProvider.notifier).verify(file.path);

    if (mounted) {
      await displayInfoBar(context, builder: (context, close) {
        return InfoBar(
          title: Text(result.success ? 'Verification Passed' : 'Verification Failed'),
          content: Text(result.message),
          severity: result.success ? InfoBarSeverity.success : InfoBarSeverity.error,
          action: IconButton(
            icon: const Icon(FluentIcons.clear),
            onPressed: close,
          ),
        );
      });
    }
  }

  Future<void> _viewLog(TrackedFile file) async {
    final result = await ref.read(witnessdServiceProvider.notifier).getLog(file.path);

    if (mounted) {
      await showDialog(
        context: context,
        builder: (context) => ContentDialog(
          title: Text('Log: ${file.name}'),
          content: SingleChildScrollView(
            child: SelectableText(
              result.message,
              style: FluentTheme.of(context).typography.caption?.copyWith(
                    fontFamily: 'Consolas',
                  ),
            ),
          ),
          actions: [
            FilledButton(
              child: const Text('Close'),
              onPressed: () => Navigator.of(context).pop(),
            ),
          ],
        ),
      );
    }
  }
}

class _ExportDialog extends StatefulWidget {
  final TrackedFile file;

  const _ExportDialog({required this.file});

  @override
  State<_ExportDialog> createState() => _ExportDialogState();
}

class _ExportDialogState extends State<_ExportDialog> {
  String _selectedTier = 'standard';

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return ContentDialog(
      title: const Text('Export Evidence'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Select evidence tier for: ${widget.file.name}',
            style: theme.typography.body,
          ),
          const SizedBox(height: WindowsTheme.spacingLG),
          ...ExportTier.values.map((tier) {
            return Padding(
              padding: const EdgeInsets.only(bottom: WindowsTheme.spacingSM),
              child: RadioButton(
                checked: _selectedTier == tier.value,
                content: Row(
                  children: [
                    Text(tier.displayName),
                    const SizedBox(width: WindowsTheme.spacingSM),
                    Text(
                      tier.description,
                      style: theme.typography.caption?.copyWith(
                        color: theme.resources.textFillColorSecondary,
                      ),
                    ),
                  ],
                ),
                onChanged: (checked) {
                  if (checked) {
                    setState(() => _selectedTier = tier.value);
                  }
                },
              ),
            );
          }),
        ],
      ),
      actions: [
        Button(
          child: const Text('Cancel'),
          onPressed: () => Navigator.of(context).pop(),
        ),
        FilledButton(
          child: const Text('Export'),
          onPressed: () => Navigator.of(context).pop(_selectedTier),
        ),
      ],
    );
  }
}
