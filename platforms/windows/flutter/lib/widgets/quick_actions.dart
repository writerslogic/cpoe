import 'dart:io';

import 'package:fluent_ui/fluent_ui.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:path/path.dart' as path;

import '../models/witness_status.dart';
import '../services/witnessd_service.dart';
import '../theme/windows_theme.dart';

class QuickActionsSection extends ConsumerWidget {
  const QuickActionsSection({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = FluentTheme.of(context);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Quick Actions',
          style: theme.typography.bodyStrong?.copyWith(
            color: theme.resources.textFillColorSecondary,
          ),
        ),
        const SizedBox(height: WindowsTheme.spacingSM),
        Row(
          children: [
            Expanded(
              child: _QuickActionButton(
                icon: FluentIcons.check_mark,
                label: 'Checkpoint',
                onPressed: () => _createCheckpoint(context, ref),
              ),
            ),
            const SizedBox(width: WindowsTheme.spacingSM),
            Expanded(
              child: _QuickActionButton(
                icon: FluentIcons.export,
                label: 'Export',
                onPressed: () => _exportEvidence(context, ref),
              ),
            ),
            const SizedBox(width: WindowsTheme.spacingSM),
            Expanded(
              child: _QuickActionButton(
                icon: FluentIcons.shield,
                label: 'Verify',
                onPressed: () => _verifyEvidence(context, ref),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Future<void> _createCheckpoint(BuildContext context, WidgetRef ref) async {
    final theme = FluentTheme.of(context);

    // First, let user select a file if not already tracking
    final state = ref.read(witnessdServiceProvider);
    String? filePath = state.status.trackingDocument;

    if (filePath == null) {
      final result = await FilePicker.platform.pickFiles(
        dialogTitle: 'Select document to checkpoint',
        type: FileType.any,
      );

      if (result == null || result.files.isEmpty) return;
      filePath = result.files.first.path;
    }

    if (filePath == null || !context.mounted) return;

    // Show message dialog
    final messageController = TextEditingController();
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => ContentDialog(
        title: const Text('Create Checkpoint'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Document: ${path.basename(filePath!)}',
              style: theme.typography.body,
            ),
            const SizedBox(height: WindowsTheme.spacingMD),
            TextBox(
              controller: messageController,
              placeholder: 'Optional checkpoint message...',
              maxLines: 3,
            ),
          ],
        ),
        actions: [
          Button(
            child: const Text('Cancel'),
            onPressed: () => Navigator.of(context).pop(false),
          ),
          FilledButton(
            child: const Text('Create'),
            onPressed: () => Navigator.of(context).pop(true),
          ),
        ],
      ),
    );

    if (confirmed != true || !context.mounted) return;

    // Create the checkpoint
    final result = await ref.read(witnessdServiceProvider.notifier).createCheckpoint(
          message: messageController.text,
        );

    if (context.mounted) {
      await displayInfoBar(context, builder: (context, close) {
        return InfoBar(
          title: Text(result.success ? 'Checkpoint Created' : 'Error'),
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

  Future<void> _exportEvidence(BuildContext context, WidgetRef ref) async {
    // Select source file
    final sourceResult = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select document to export evidence for',
      type: FileType.any,
    );

    if (sourceResult == null || sourceResult.files.isEmpty) return;
    final sourcePath = sourceResult.files.first.path;
    if (sourcePath == null || !context.mounted) return;

    // Show tier selection
    final tier = await showDialog<String>(
      context: context,
      builder: (context) => _ExportTierDialog(
        fileName: path.basename(sourcePath),
      ),
    );

    if (tier == null || !context.mounted) return;

    // Select output location
    final outputPath = await FilePicker.platform.saveFile(
      dialogTitle: 'Save evidence file',
      fileName: '${path.basenameWithoutExtension(sourcePath)}.evidence.json',
      type: FileType.custom,
      allowedExtensions: ['json'],
    );

    if (outputPath == null || !context.mounted) return;

    // Export
    final result = await ref.read(witnessdServiceProvider.notifier).export(
          filePath: sourcePath,
          tier: tier,
          outputPath: outputPath,
        );

    if (context.mounted) {
      await displayInfoBar(context, builder: (context, close) {
        return InfoBar(
          title: Text(result.success ? 'Evidence Exported' : 'Export Failed'),
          content: Text(result.success
              ? 'Saved to: ${path.basename(outputPath)}'
              : result.message),
          severity: result.success ? InfoBarSeverity.success : InfoBarSeverity.error,
          action: IconButton(
            icon: const Icon(FluentIcons.clear),
            onPressed: close,
          ),
        );
      });
    }
  }

  Future<void> _verifyEvidence(BuildContext context, WidgetRef ref) async {
    // Select evidence file
    final result = await FilePicker.platform.pickFiles(
      dialogTitle: 'Select evidence file to verify',
      type: FileType.custom,
      allowedExtensions: ['json'],
    );

    if (result == null || result.files.isEmpty) return;
    final filePath = result.files.first.path;
    if (filePath == null || !context.mounted) return;

    // Verify
    final verifyResult =
        await ref.read(witnessdServiceProvider.notifier).verify(filePath);

    if (context.mounted) {
      await displayInfoBar(context, builder: (context, close) {
        return InfoBar(
          title: Text(
              verifyResult.success ? 'Verification Passed' : 'Verification Failed'),
          content: Text(verifyResult.message),
          severity:
              verifyResult.success ? InfoBarSeverity.success : InfoBarSeverity.error,
          action: IconButton(
            icon: const Icon(FluentIcons.clear),
            onPressed: close,
          ),
        );
      });
    }
  }
}

class _QuickActionButton extends StatefulWidget {
  final IconData icon;
  final String label;
  final VoidCallback onPressed;

  const _QuickActionButton({
    required this.icon,
    required this.label,
    required this.onPressed,
  });

  @override
  State<_QuickActionButton> createState() => _QuickActionButtonState();
}

class _QuickActionButtonState extends State<_QuickActionButton> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final theme = FluentTheme.of(context);

    return MouseRegion(
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: GestureDetector(
        onTap: widget.onPressed,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(
            horizontal: WindowsTheme.spacingMD,
            vertical: WindowsTheme.spacingLG,
          ),
          decoration: BoxDecoration(
            color: _isHovered
                ? theme.accentColor.withOpacity(0.1)
                : theme.resources.subtleFillColorSecondary,
            borderRadius: BorderRadius.circular(WindowsTheme.radiusMD),
            border: Border.all(
              color: _isHovered
                  ? theme.accentColor.withOpacity(0.3)
                  : theme.resources.dividerStrokeColorDefault,
            ),
          ),
          child: Column(
            children: [
              Icon(
                widget.icon,
                size: WindowsTheme.iconLG,
                color: _isHovered
                    ? theme.accentColor
                    : theme.resources.textFillColorSecondary,
              ),
              const SizedBox(height: WindowsTheme.spacingSM),
              Text(
                widget.label,
                style: theme.typography.caption?.copyWith(
                  color: _isHovered
                      ? theme.accentColor
                      : theme.resources.textFillColorSecondary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _ExportTierDialog extends StatefulWidget {
  final String fileName;

  const _ExportTierDialog({required this.fileName});

  @override
  State<_ExportTierDialog> createState() => _ExportTierDialogState();
}

class _ExportTierDialogState extends State<_ExportTierDialog> {
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
            'Select evidence tier for: ${widget.fileName}',
            style: theme.typography.body,
          ),
          const SizedBox(height: WindowsTheme.spacingLG),
          ...ExportTier.values.map((tier) {
            return Padding(
              padding: const EdgeInsets.only(bottom: WindowsTheme.spacingSM),
              child: RadioButton(
                checked: _selectedTier == tier.value,
                content: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(tier.displayName),
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
