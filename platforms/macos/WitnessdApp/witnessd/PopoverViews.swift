import SwiftUI

// MARK: - Export Tier

enum ExportTier: String, CaseIterable, Identifiable {
    case basic, standard, enhanced, maximum

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .basic: return "Basic"
        case .standard: return "Standard"
        case .enhanced: return "Enhanced"
        case .maximum: return "Maximum"
        }
    }

    var description: String {
        switch self {
        case .basic: return "Checkpoint chain + VDF proofs only"
        case .standard: return "Includes keystroke evidence"
        case .enhanced: return "Adds TPM attestation"
        case .maximum: return "All available evidence"
        }
    }

    var icon: String {
        switch self {
        case .basic: return "lock"
        case .standard: return "lock.shield"
        case .enhanced: return "lock.shield.fill"
        case .maximum: return "checkmark.shield.fill"
        }
    }
}

// MARK: - Export Tier Sheet

struct ExportTierSheet: View {
    @Binding var selectedTier: ExportTier
    @Binding var sourceURL: URL?
    @Binding var destinationURL: URL?
    let onExport: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            // Header
            VStack(spacing: Design.Spacing.xs) {
                Image(systemName: "square.and.arrow.up")
                    .font(.system(size: Design.IconSize.xl))
                    .foregroundStyle(Design.Colors.brandGradient)

                Text("Export Evidence")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)
            }
            .padding(.top, Design.Spacing.md)

            VStack(alignment: .leading, spacing: Design.Spacing.md) {
                // Source document section
                VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                    Text("Source Document")
                        .font(Design.Typography.labelMedium)
                        .foregroundColor(Design.Colors.secondaryText)

                    HStack {
                        Image(systemName: "doc.text")
                            .foregroundColor(Design.Colors.tertiaryText)
                        Text(sourceURL?.lastPathComponent ?? "No document selected")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(sourceURL != nil ? Design.Colors.primaryText : Design.Colors.tertiaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button("Browse...") {
                            browseForSource()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(Design.Spacing.sm)
                    .background(Design.Colors.secondaryBackground)
                    .cornerRadius(Design.Radius.sm)
                }

                // Destination section
                VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                    Text("Save To")
                        .font(Design.Typography.labelMedium)
                        .foregroundColor(Design.Colors.secondaryText)

                    HStack {
                        Image(systemName: "folder")
                            .foregroundColor(Design.Colors.tertiaryText)
                        Text(destinationURL?.lastPathComponent ?? "Choose location...")
                            .font(Design.Typography.bodyMedium)
                            .foregroundColor(destinationURL != nil ? Design.Colors.primaryText : Design.Colors.tertiaryText)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Button("Browse...") {
                            browseForDestination()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(Design.Spacing.sm)
                    .background(Design.Colors.secondaryBackground)
                    .cornerRadius(Design.Radius.sm)
                }

                // Tier selection
                VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                    Text("Export Tier")
                        .font(Design.Typography.labelMedium)
                        .foregroundColor(Design.Colors.secondaryText)

                    Picker("", selection: $selectedTier) {
                        ForEach(ExportTier.allCases) { tier in
                            HStack {
                                Image(systemName: tier.icon)
                                Text(tier.displayName)
                            }
                            .tag(tier)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    Text(selectedTier.description)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
            }
            .padding(.horizontal, Design.Spacing.md)

            Spacer()

            // Buttons
            HStack(spacing: Design.Spacing.md) {
                Button("Cancel") {
                    onCancel()
                }
                .buttonStyle(.bordered)
                .keyboardShortcut(.cancelAction)

                Button("Export") {
                    onExport()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(sourceURL == nil || destinationURL == nil)
            }
            .padding(.bottom, Design.Spacing.md)
        }
        .frame(width: 380, height: 360)
        .background(Design.Colors.background)
    }

    private func browseForSource() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.message = "Select a document to export evidence for"
        panel.prompt = "Select"

        if panel.runModal() == .OK, let url = panel.url {
            sourceURL = url
            // Auto-suggest destination name based on source
            if destinationURL == nil {
                let suggestedName = url.deletingPathExtension().lastPathComponent + ".evidence.json"
                let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
                destinationURL = downloadsURL?.appendingPathComponent(suggestedName)
            }
        }
    }

    private func browseForDestination() {
        let savePanel = NSSavePanel()
        if let source = sourceURL {
            savePanel.nameFieldStringValue = source.deletingPathExtension().lastPathComponent + ".evidence.json"
        } else {
            savePanel.nameFieldStringValue = "evidence.json"
        }
        savePanel.allowedContentTypes = [.json]

        if savePanel.runModal() == .OK, let url = savePanel.url {
            destinationURL = url
        }
    }
}

struct ExportTierRow: View {
    let tier: ExportTier
    let isSelected: Bool
    let onSelect: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: onSelect) {
            HStack(spacing: Design.Spacing.md) {
                // Radio indicator
                ZStack {
                    Circle()
                        .strokeBorder(isSelected ? Color.accentColor : Design.Colors.separator, lineWidth: 2)
                        .frame(width: 20, height: 20)

                    if isSelected {
                        Circle()
                            .fill(Color.accentColor)
                            .frame(width: 12, height: 12)
                    }
                }

                // Icon
                Image(systemName: tier.icon)
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(isSelected ? .accentColor : Design.Colors.secondaryText)
                    .frame(width: Design.IconSize.lg)

                // Text
                VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                    Text(tier.displayName)
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(isSelected ? Design.Colors.primaryText : Design.Colors.secondaryText)

                    Text(tier.description)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                        .lineLimit(1)
                }

                Spacer()
            }
            .padding(Design.Spacing.md)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .fill(isSelected ? Color.accentColor.opacity(0.1) : (isHovered ? Design.Colors.hover : Design.Colors.secondaryBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(isSelected ? Color.accentColor : Design.Colors.separator, lineWidth: isSelected ? 1 : 0.5)
            )
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .accessibilityLabel("\(tier.displayName) tier: \(tier.description)")
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

// MARK: - Window Management

/// Manages window lifecycle to prevent memory leaks
/// Uses a weak reference pattern with a strong holder to ensure proper cleanup
@MainActor
final class WindowManager {
    static let shared = WindowManager()

    /// Weak reference to track the window without preventing deallocation
    private weak var _historyWindow: NSWindow?

    /// Strong reference holder - cleared when window is closed
    private var historyWindowHolder: NSWindow?

    private init() {}

    var historyWindow: NSWindow? {
        get { _historyWindow }
        set {
            // Release previous window holder
            historyWindowHolder = nil
            _historyWindow = newValue
            // Keep strong reference while window is visible
            historyWindowHolder = newValue
        }
    }

    func closeHistoryWindow() {
        historyWindow?.close()
        historyWindowHolder = nil
        _historyWindow = nil
    }
}

// MARK: - Main Popover Content

struct PopoverContentView: View {
    let bridge: WitnessdBridge
    let closeAction: () -> Void

    @State private var service = WitnessdService.shared
    @State private var showingAlert = false
    @State private var alertTitle = ""
    @State private var alertMessage = ""

    // Export tier selection state
    @State private var showingTierSheet = false
    @State private var selectedExportTier: ExportTier = .standard
    @State private var pendingExportSourceURL: URL? = nil
    @State private var pendingExportDestURL: URL? = nil

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        VStack(spacing: 0) {
            headerSection
            Divider()
            mainContent
            Divider()
            footerSection
        }
        .frame(width: Design.Layout.popoverWidth, height: Design.Layout.popoverHeight)
        .background(Design.Colors.background)
        .task {
            await service.refreshStatus()
        }
        .alert(alertTitle, isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(alertMessage)
        }
        .sheet(isPresented: $showingTierSheet) {
            ExportTierSheet(
                selectedTier: $selectedExportTier,
                sourceURL: $pendingExportSourceURL,
                destinationURL: $pendingExportDestURL,
                onExport: {
                    showingTierSheet = false
                    performExport()
                },
                onCancel: {
                    showingTierSheet = false
                    pendingExportSourceURL = nil
                    pendingExportDestURL = nil
                }
            )
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: Design.Spacing.md) {
            // App icon with animated status indicator
            ZStack(alignment: .bottomTrailing) {
                // Glow effect when active
                if service.sentinelStatus.isRunning && !reduceMotion {
                    Circle()
                        .fill(Design.Colors.success.opacity(0.2))
                        .frame(width: Design.IconSize.xl + 16, height: Design.IconSize.xl + 16)
                        .blur(radius: 8)
                }

                Image(systemName: service.sentinelStatus.isRunning ? "eye.circle.fill" : "eye.circle")
                    .font(.system(size: Design.IconSize.xl, weight: .medium))
                    .foregroundStyle(
                        service.sentinelStatus.isRunning
                            ? Design.Colors.brandGradient
                            : LinearGradient(colors: [Design.Colors.secondaryText], startPoint: .top, endPoint: .bottom)
                    )
                    .symbolEffect(.bounce, value: service.sentinelStatus.isRunning)

                if service.sentinelStatus.isRunning {
                    Circle()
                        .fill(Design.Colors.success)
                        .frame(width: 10, height: 10)
                        .overlay(
                            Circle()
                                .stroke(Design.Colors.background, lineWidth: 2)
                        )
                        .offset(x: 2, y: 2)
                        .transition(.scale.combined(with: .opacity))
                }
            }
            .animation(Design.Animation.stateChange, value: service.sentinelStatus.isRunning)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text("Witnessd")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)

                HStack(spacing: Design.Spacing.xs) {
                    if service.sentinelStatus.isRunning {
                        statusPill(text: "Active", style: .success)
                    } else if service.isInitialized {
                        statusPill(text: "Ready", style: .neutral)
                    } else {
                        statusPill(text: "Setup Required", style: .warning)
                    }
                }
                .animation(Design.Animation.stateChange, value: service.sentinelStatus.isRunning)
                .animation(Design.Animation.stateChange, value: service.isInitialized)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Witnessd, \(headerSubtitle)")

            Spacer()

            if service.isLoading {
                LoadingIndicator(message: service.loadingMessage)
                    .transition(.asymmetric(
                        insertion: .scale(scale: 0.8).combined(with: .opacity),
                        removal: .opacity
                    ))
            }

            RefreshButton {
                Task { await service.refreshStatus() }
            }
        }
        .padding(Design.Spacing.lg)
        .background(Design.Colors.secondaryBackground)
    }

    private func statusPill(text: String, style: Badge.BadgeStyle) -> some View {
        HStack(spacing: Design.Spacing.xxs) {
            if differentiateWithoutColor {
                Image(systemName: style == .success ? "checkmark.circle.fill" : style == .warning ? "exclamationmark.triangle.fill" : "circle.fill")
                    .font(.system(size: 8))
            } else {
                Circle()
                    .fill(style == .success ? Design.Colors.success : style == .warning ? Design.Colors.warning : Design.Colors.secondaryText)
                    .frame(width: 6, height: 6)
            }
            Text(text)
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.secondaryText)
        }
        .padding(.horizontal, Design.Spacing.sm)
        .padding(.vertical, Design.Spacing.xxs)
        .background(
            Capsule()
                .fill(Design.Colors.secondaryBackground)
                .overlay(
                    Capsule()
                        .strokeBorder(Design.Colors.separator, lineWidth: 0.5)
                )
        )
    }

    private var headerSubtitle: String {
        if service.sentinelStatus.isRunning { return "Sentinel Active" }
        else if service.isInitialized { return "Ready" }
        else { return "Setup Required" }
    }

    // MARK: - Main Content

    private var mainContent: some View {
        ScrollView {
            VStack(spacing: Design.Spacing.lg) {
                // Show CLI unavailable error if applicable
                if !service.isCliAvailable {
                    cliUnavailableSection
                }
                // Show current error banner if any
                else if let error = service.currentError {
                    errorBannerSection(error: error)
                }

                if !service.isCliAvailable {
                    // Don't show other content if CLI is unavailable
                } else if !service.isInitialized {
                    setupRequiredSection
                } else {
                    trackingSection
                    quickActionsSection
                    systemStatusSection
                }
            }
            .padding(Design.Spacing.lg)
        }
    }

    // MARK: - CLI Unavailable

    private var cliUnavailableSection: some View {
        VStack(spacing: Design.Spacing.lg) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: Design.IconSize.hero))
                .foregroundColor(Design.Colors.error)

            VStack(spacing: Design.Spacing.sm) {
                Text("Witnessd CLI Not Available")
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.primaryText)

                if let error = service.cliError {
                    Text(error.localizedDescription)
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.secondaryText)
                        .multilineTextAlignment(.center)

                    if let suggestion = error.recoverySuggestion {
                        Text(suggestion)
                            .font(Design.Typography.labelSmall)
                            .foregroundColor(Design.Colors.tertiaryText)
                            .padding(.top, Design.Spacing.xs)
                    }
                }
            }
        }
        .padding(Design.Spacing.xxxl)
    }

    // MARK: - Error Banner

    private func errorBannerSection(error: ServiceError) -> some View {
        ErrorBanner(
            title: error.title,
            message: error.message,
            suggestion: error.suggestion,
            isRetryable: error.isRetryable,
            onRetry: error.isRetryable ? {
                Task {
                    await service.retryCurrentError()
                }
            } : nil,
            onDismiss: {
                service.dismissError()
            }
        )
        .transition(.asymmetric(
            insertion: .move(edge: .top).combined(with: .opacity),
            removal: .opacity
        ))
        .animation(Design.Animation.stateChange, value: service.currentError?.id)
    }

    // MARK: - Setup Required

    private var setupRequiredSection: some View {
        SetupRequiredContent(
            reduceMotion: reduceMotion,
            action: initializeWitness
        )
    }

    // MARK: - Sentinel Section

    private var trackingSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("Document Tracking")

            sentinelCard
        }
    }

    private var sentinelCard: some View {
        VStack(spacing: Design.Spacing.md) {
            // Status header with animation
            HStack(spacing: Design.Spacing.sm) {
                ZStack {
                    // Pulsing background when active
                    if service.sentinelStatus.isRunning {
                        Circle()
                            .fill(Design.Colors.success.opacity(0.2))
                            .frame(width: 28, height: 28)
                            .scaleEffect(reduceMotion ? 1.0 : 1.3)
                            .opacity(reduceMotion ? 0.5 : 0.0)
                            .animation(
                                reduceMotion ? nil : Design.Animation.pulse,
                                value: service.sentinelStatus.isRunning
                            )
                    }

                    Image(systemName: service.sentinelStatus.isRunning ? "eye.circle.fill" : "eye.slash.circle")
                        .font(.system(size: Design.IconSize.lg))
                        .foregroundColor(service.sentinelStatus.isRunning ? Design.Colors.success : Design.Colors.tertiaryText)
                        .symbolEffect(.bounce, value: service.sentinelStatus.isRunning)
                }
                .frame(width: 32, height: 32)

                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: Design.Spacing.xs) {
                        Text(service.sentinelStatus.isRunning ? "Sentinel Active" : "Sentinel Stopped")
                            .font(Design.Typography.headlineSmall)
                            .foregroundColor(Design.Colors.primaryText)
                            .contentTransition(.numericText())

                        if service.sentinelStatus.isRunning {
                            AnimatedStatusIndicator(isActive: true)
                        }
                    }

                    Text(service.sentinelStatus.isRunning
                        ? "Tracking focused documents automatically"
                        : "Start sentinel to track documents as you work")
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.secondaryText)
                        .contentTransition(.opacity)
                }
                .animation(Design.Animation.stateChange, value: service.sentinelStatus.isRunning)

                Spacer()

                // Toggle sentinel button with improved styling
                SentinelToggleButton(
                    isRunning: service.sentinelStatus.isRunning,
                    action: toggleSentinel
                )
            }

            // Info about sentinel with animated appearance
            if !service.sentinelStatus.isRunning {
                HStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "info.circle")
                        .foregroundColor(Design.Colors.info.opacity(0.7))
                    Text("The sentinel monitors which document has focus and automatically creates checkpoints when you save.")
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .padding(Design.Spacing.sm)
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                        .fill(Design.Colors.info.opacity(0.05))
                        .overlay(
                            RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                                .strokeBorder(Design.Colors.info.opacity(0.1), lineWidth: 0.5)
                        )
                )
                .transition(.asymmetric(
                    insertion: .scale(scale: 0.95).combined(with: .opacity),
                    removal: .scale(scale: 0.95).combined(with: .opacity)
                ))
            }
        }
        .animation(Design.Animation.stateChange, value: service.sentinelStatus.isRunning)
        .cardStyle()
    }

    private func toggleSentinel() {
        Task {
            if service.sentinelStatus.isRunning {
                let result = await service.stopSentinel()
                if !result.success {
                    showAlert(title: "Stop Sentinel Failed", message: result.userFriendlyMessage)
                }
            } else {
                let result = await service.startSentinel()
                if !result.success {
                    // Check for accessibility permission error
                    if result.error == .accessibilityPermissionRequired {
                        showAccessibilityPermissionAlert()
                    } else {
                        showAlert(
                            title: "Start Sentinel Failed",
                            message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                        )
                    }
                }
            }
        }
    }

    private func showAccessibilityPermissionAlert() {
        let alert = NSAlert()
        alert.messageText = "Accessibility Permission Required"
        alert.informativeText = "The sentinel needs accessibility permissions to track which document you are working on.\n\nWould you like to open System Settings?"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Open Settings")
        alert.addButton(withTitle: "Not Now")

        if alert.runModal() == .alertFirstButtonReturn {
            // Open System Settings to Accessibility pane
            if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
                NSWorkspace.shared.open(url)
            }
        }
    }

    // MARK: - Quick Actions

    private var quickActionsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("Quick Actions")

            HStack(spacing: Design.Spacing.sm) {
                QuickActionButton(
                    icon: "checkmark.circle",
                    label: "Checkpoint",
                    action: createCheckpoint
                )

                QuickActionButton(
                    icon: "square.and.arrow.up",
                    label: "Export",
                    action: exportEvidence
                )

                QuickActionButton(
                    icon: "checkmark.shield",
                    label: "Verify",
                    action: verifyEvidence
                )

                QuickActionButton(
                    icon: "clock.arrow.circlepath",
                    label: "History",
                    action: viewHistory
                )
            }
        }
    }

    // MARK: - System Status

    private var systemStatusSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            SectionHeader("System")

            VStack(spacing: Design.Spacing.xxs) {
                SystemStatusRow(
                    icon: "speedometer",
                    title: "VDF",
                    value: service.vdfCalibrated ? "Calibrated" : "Not calibrated",
                    isGood: service.vdfCalibrated,
                    action: service.vdfCalibrated ? nil : { calibrateVDF() }
                )

                SystemStatusRow(
                    icon: "cpu",
                    title: "TPM",
                    value: service.tpmAvailable ? "Available" : "Unavailable",
                    isGood: service.tpmAvailable,
                    action: nil
                )

                SystemStatusRow(
                    icon: "cylinder.split.1x2",
                    title: "Database",
                    value: "\(service.status.databaseEvents) events",
                    isGood: true,
                    action: nil
                )
            }
            .cardStyle(padding: Design.Spacing.sm)
        }
    }

    // MARK: - Footer

    private var footerSection: some View {
        HStack {
            IconButton(icon: "gear", label: "Settings", size: Design.IconSize.sm) {
                openSettings()
            }

            Spacer()

            Text("v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")")
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.tertiaryText)

            Spacer()

            IconButton(icon: "questionmark.circle", label: "Help", size: Design.IconSize.sm) {
                showHelp()
            }
        }
        .padding(.horizontal, Design.Spacing.lg)
        .padding(.vertical, Design.Spacing.md)
        .background(Design.Colors.secondaryBackground)
    }

    // MARK: - Actions

    private func initializeWitness() {
        Task {
            let result = await service.initialize()
            if result.success {
                showAlert(title: "Initialized", message: "Witnessd is ready. Consider calibrating VDF for accurate timing proofs.")
            } else {
                showAlert(
                    title: "Initialization Failed",
                    message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                )
            }
        }
    }

    private func stopTracking() {
        Task {
            let result = await service.stopTracking()
            if result.success {
                showAlert(title: "Tracking Stopped", message: result.message)
            } else {
                showAlert(
                    title: "Stop Tracking Failed",
                    message: result.userFriendlyMessage
                )
            }
        }
    }

    private func createCheckpoint() {
        closeAction()
        NSApp.activate(ignoringOtherApps: true)

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.message = "Select a document to checkpoint"
            panel.prompt = "Create Checkpoint"

            if panel.runModal() == .OK, let url = panel.url {
                // Validate file exists and is readable
                let fm = FileManager.default
                guard fm.fileExists(atPath: url.path) else {
                    self.showAlert(title: "File Not Found", message: "The selected file could not be found.")
                    return
                }
                guard fm.isReadableFile(atPath: url.path) else {
                    self.showAlert(title: "Cannot Read File", message: "You don't have permission to read this file.")
                    return
                }

                let alert = NSAlert()
                alert.messageText = "Checkpoint Message"
                alert.informativeText = "Enter an optional message for this checkpoint:"
                alert.addButton(withTitle: "Create")
                alert.addButton(withTitle: "Cancel")

                let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
                input.placeholderString = "Optional message..."
                alert.accessoryView = input

                if alert.runModal() == .alertFirstButtonReturn {
                    Task {
                        let result = await self.bridge.commit(filePath: url.path, message: input.stringValue)
                        if result.success {
                            self.showAlert(title: "Checkpoint Created", message: result.message)
                        } else {
                            self.showAlert(
                                title: "Checkpoint Failed",
                                message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                            )
                        }
                    }
                }
            }
        }
    }

    private func exportEvidence() {
        // Pre-fill with current tracking document if available
        if let trackingDoc = service.trackingDocument {
            pendingExportSourceURL = URL(fileURLWithPath: trackingDoc)
            // Suggest destination in Downloads folder
            let suggestedName = URL(fileURLWithPath: trackingDoc).deletingPathExtension().lastPathComponent + ".evidence.json"
            if let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first {
                pendingExportDestURL = downloadsURL.appendingPathComponent(suggestedName)
            }
        } else {
            pendingExportSourceURL = nil
            pendingExportDestURL = nil
        }

        selectedExportTier = ExportTier(rawValue: service.settings.defaultExportTier) ?? .standard
        showingTierSheet = true
    }

    private func performExport() {
        guard let sourceURL = pendingExportSourceURL,
              let destURL = pendingExportDestURL else {
            return
        }

        // Validate source file exists
        guard FileManager.default.fileExists(atPath: sourceURL.path) else {
            showAlert(title: "Source File Not Found", message: "The source document could not be found at: \(sourceURL.lastPathComponent)")
            pendingExportSourceURL = nil
            pendingExportDestURL = nil
            return
        }

        // Validate destination directory is writable
        let destDir = destURL.deletingLastPathComponent().path
        guard FileManager.default.isWritableFile(atPath: destDir) else {
            showAlert(title: "Cannot Write to Destination", message: "You don't have permission to write to the selected folder.")
            pendingExportSourceURL = nil
            pendingExportDestURL = nil
            return
        }

        Task {
            let result = await service.export(filePath: sourceURL.path, tier: selectedExportTier.rawValue, outputPath: destURL.path)

            pendingExportSourceURL = nil
            pendingExportDestURL = nil

            if result.success {
                showAlert(title: "Evidence Exported", message: "Saved to: \(destURL.lastPathComponent)")
            } else {
                showAlert(
                    title: "Export Failed",
                    message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                )
            }
        }
    }

    private func verifyEvidence() {
        closeAction()
        NSApp.activate(ignoringOtherApps: true)

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            let panel = NSOpenPanel()
            panel.canChooseFiles = true
            panel.canChooseDirectories = false
            panel.allowedContentTypes = [.json]
            panel.message = "Select an evidence file to verify"
            panel.prompt = "Verify"

            if panel.runModal() == .OK, let url = panel.url {
                // Validate file exists and is readable
                guard FileManager.default.fileExists(atPath: url.path) else {
                    self.showAlert(title: "File Not Found", message: "The selected file could not be found.")
                    return
                }

                Task {
                    let result = await self.service.verify(filePath: url.path)
                    if result.success {
                        self.showAlert(title: "Verification Passed", message: result.message)
                    } else {
                        self.showAlert(
                            title: "Verification Failed",
                            message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                        )
                    }
                }
            }
        }
    }

    private func viewHistory() {
        closeAction()

        // Close existing history window if open
        WindowManager.shared.closeHistoryWindow()

        let historyWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: Design.Layout.historyWidth, height: Design.Layout.historyHeight),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        historyWindow.title = "Document History"
        historyWindow.center()
        historyWindow.isReleasedWhenClosed = true
        historyWindow.minSize = NSSize(width: 500, height: 400)

        // Store reference to prevent immediate release
        WindowManager.shared.historyWindow = historyWindow

        let historyView = HistoryView(
            bridge: bridge,
            closeAction: {
                WindowManager.shared.closeHistoryWindow()
            }
        )

        historyWindow.contentView = NSHostingView(rootView: historyView)
        historyWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func calibrateVDF() {
        Task {
            let result = await service.calibrate()
            if result.success {
                showAlert(title: "Calibration Complete", message: result.message)
            } else {
                showAlert(
                    title: "Calibration Failed",
                    message: result.userFriendlyMessage + (result.recoverySuggestion.map { "\n\n\($0)" } ?? "")
                )
            }
        }
    }

    private func openSettings() {
        closeAction()

        // Single delay to allow popover to close before opening settings
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            // For menu bar apps (.accessory policy), we need to temporarily
            // become a regular app to show the settings window
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)

            // Use Settings scene API (macOS 14+) or fallback to selector
            if #available(macOS 14.0, *) {
                if !NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil) {
                    // Fallback if selector fails
                    NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
                }
            } else {
                NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
            }
        }
    }

    private func showHelp() {
        NSWorkspace.shared.open(AppConfig.documentationURL)
    }

    private func showAlert(title: String, message: String) {
        alertTitle = title
        alertMessage = message
        showingAlert = true
    }
}

// MARK: - Loading Indicator

struct LoadingIndicator: View {
    let message: String

    @State private var isAnimating = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Design.Spacing.xs) {
            ZStack {
                // Spinning arc
                Circle()
                    .stroke(Design.Colors.separator, lineWidth: 2)
                    .frame(width: 14, height: 14)

                Circle()
                    .trim(from: 0, to: 0.7)
                    .stroke(
                        Color.accentColor,
                        style: StrokeStyle(lineWidth: 2, lineCap: .round)
                    )
                    .frame(width: 14, height: 14)
                    .rotationEffect(.degrees(isAnimating ? 360 : 0))
            }

            if !message.isEmpty {
                Text(message)
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .lineLimit(1)
            }
        }
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 1).repeatForever(autoreverses: false)) {
                isAnimating = true
            }
        }
    }
}

// MARK: - Refresh Button

struct RefreshButton: View {
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false
    @State private var rotation: Double = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: {
            if !reduceMotion {
                withAnimation(Design.Animation.spring) {
                    rotation += 360
                }
            }
            action()
        }) {
            Image(systemName: "arrow.clockwise")
                .font(.system(size: Design.IconSize.sm, weight: .medium))
                .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
                .rotationEffect(.degrees(rotation))
                .frame(width: Design.IconSize.md + Design.Spacing.md, height: Design.IconSize.md + Design.Spacing.md)
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                        .fill(isPressed ? Design.Colors.pressed : (isHovered ? Design.Colors.hover : Color.clear))
                )
                .scaleEffect(isPressed ? 0.9 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(Design.Animation.fast) { isHovered = hovering }
        }
        .pressEvents {
            withAnimation(Design.Animation.fast) { isPressed = true }
        } onRelease: {
            withAnimation(Design.Animation.spring) { isPressed = false }
        }
        .accessibilityLabel("Refresh")
        .accessibilityHint("Double-tap to refresh status")
        .accessibilityIdentifier("refresh-button")
    }
}

// MARK: - Supporting Components

struct StatWidget: View {
    let icon: String
    let value: String
    let label: String

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(Design.Colors.tertiaryText)
                .frame(width: Design.IconSize.lg)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 0) {
                Text(value)
                    .font(Design.Typography.statValue)
                    .foregroundColor(Design.Colors.primaryText)

                Text(label)
                    .font(Design.Typography.statLabel)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .textCase(.uppercase)
                    .tracking(0.3)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}

struct AnimatedStatWidget: View {
    let icon: String
    let value: Int
    let label: String
    let isPulsing: Bool

    @State private var scale: CGFloat = 1.0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: icon)
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(Design.Colors.tertiaryText)
                .frame(width: Design.IconSize.lg)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 0) {
                Text(formatNumber(value))
                    .font(Design.Typography.statValue)
                    .foregroundColor(Design.Colors.primaryText)
                    .scaleEffect(scale)
                    .animation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.5), value: scale)

                Text(label)
                    .font(Design.Typography.statLabel)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .textCase(.uppercase)
                    .tracking(0.3)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(formatNumber(value)) \(label)")
        .onChange(of: isPulsing) { _, newValue in
            if newValue && !reduceMotion {
                scale = 1.15
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                    scale = 1.0
                }
            }
        }
    }

    private func formatNumber(_ n: Int) -> String {
        if n >= 1000000 {
            return String(format: "%.1fM", Double(n) / 1000000.0)
        } else if n >= 1000 {
            return String(format: "%.1fk", Double(n) / 1000.0)
        }
        return "\(n)"
    }
}

// MARK: - Sentinel Toggle Button

struct SentinelToggleButton: View {
    let isRunning: Bool
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: action) {
            HStack(spacing: Design.Spacing.xs) {
                Image(systemName: isRunning ? "stop.fill" : "play.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .contentTransition(.symbolEffect(.replace))

                Text(isRunning ? "Stop" : "Start")
                    .font(Design.Typography.labelMedium)
                    .contentTransition(.numericText())
            }
            .foregroundColor(isRunning ? Design.Colors.error : Design.Colors.success)
            .padding(.horizontal, Design.Spacing.md)
            .padding(.vertical, Design.Spacing.sm)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .fill(
                        isRunning
                            ? Design.Colors.error.opacity(isPressed ? 0.2 : (isHovered ? 0.15 : 0.1))
                            : Design.Colors.success.opacity(isPressed ? 0.2 : (isHovered ? 0.15 : 0.1))
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(
                        isRunning
                            ? Design.Colors.error.opacity(isHovered ? 0.3 : 0.2)
                            : Design.Colors.success.opacity(isHovered ? 0.3 : 0.2),
                        lineWidth: 1
                    )
            )
            .scaleEffect(isPressed ? 0.95 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(Design.Animation.fast) {
                isHovered = hovering
            }
        }
        .pressEvents {
            withAnimation(Design.Animation.fast) { isPressed = true }
        } onRelease: {
            withAnimation(Design.Animation.spring) { isPressed = false }
        }
        .animation(Design.Animation.stateChange, value: isRunning)
        .accessibilityLabel(isRunning ? "Stop Sentinel" : "Start Sentinel")
        .accessibilityIdentifier("sentinel-toggle")
    }
}

// MARK: - Quick Action Button

struct QuickActionButton: View {
    let icon: String
    let label: String
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false
    @State private var didTrigger = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: {
            // Trigger success animation
            if !reduceMotion {
                didTrigger = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                    didTrigger = false
                }
            }
            action()
        }) {
            VStack(spacing: Design.Spacing.xs) {
                ZStack {
                    // Hover glow effect
                    if isHovered && !reduceMotion {
                        Circle()
                            .fill(Color.accentColor.opacity(0.15))
                            .frame(width: Design.IconSize.lg + 16, height: Design.IconSize.lg + 16)
                            .blur(radius: 8)
                    }

                    Image(systemName: icon)
                        .font(.system(size: Design.IconSize.lg, weight: .medium))
                        .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
                        .symbolEffect(.bounce, value: didTrigger)
                }
                .frame(height: Design.IconSize.lg + 8)

                Text(label)
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, Design.Spacing.md)
            .background(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .fill(isPressed ? Design.Colors.pressed : (isHovered ? Design.Colors.hover : Design.Colors.secondaryBackground))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(
                        isHovered ? Color.accentColor.opacity(0.3) : Design.Colors.separator.opacity(0.5),
                        lineWidth: isHovered ? 1 : 0.5
                    )
            )
            .scaleEffect(isPressed ? 0.95 : (isHovered ? 1.02 : 1.0))
            .shadow(
                color: isHovered ? Color.accentColor.opacity(0.1) : .clear,
                radius: isHovered ? 8 : 0,
                y: isHovered ? 2 : 0
            )
        }
        .buttonStyle(.plain)
        .focusable()
        .onHover { hovering in
            withAnimation(Design.Animation.fast) {
                isHovered = hovering
            }
        }
        .pressEvents {
            withAnimation(Design.Animation.fast) { isPressed = true }
        } onRelease: {
            withAnimation(Design.Animation.spring) { isPressed = false }
        }
        .accessibilityLabel(label)
        .accessibilityHint("Double-tap to \(label.lowercased())")
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("action-\(label.lowercased())")
    }
}

struct SystemStatusRow: View {
    let icon: String
    let title: String
    let value: String
    let isGood: Bool
    let action: (() -> Void)?

    @State private var isHovered = false
    @State private var isPressed = false
    @State private var didAppear = false
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            // Icon with subtle background
            ZStack {
                RoundedRectangle(cornerRadius: Design.Radius.xs, style: .continuous)
                    .fill(isGood ? Design.Colors.success.opacity(0.1) : Design.Colors.secondaryBackground)
                    .frame(width: Design.IconSize.lg + 4, height: Design.IconSize.lg + 4)

                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.sm))
                    .foregroundColor(isGood ? Design.Colors.success : Design.Colors.tertiaryText)
            }
            .accessibilityHidden(true)

            Text(title)
                .font(Design.Typography.bodyMedium)
                .foregroundColor(Design.Colors.primaryText)

            Spacer()

            if let action = action {
                Button(action: action) {
                    HStack(spacing: Design.Spacing.xxs) {
                        if differentiateWithoutColor {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .font(.system(size: 10))
                        }
                        Text(value)
                            .font(Design.Typography.labelMedium)
                    }
                    .foregroundColor(Design.Colors.warning)
                    .padding(.horizontal, Design.Spacing.md)
                    .padding(.vertical, Design.Spacing.xs)
                    .background(
                        Capsule()
                            .fill(Design.Colors.warning.opacity(isPressed ? 0.2 : (isHovered ? 0.15 : 0.1)))
                    )
                    .overlay(
                        Capsule()
                            .strokeBorder(Design.Colors.warning.opacity(isHovered ? 0.3 : 0), lineWidth: 1)
                    )
                    .scaleEffect(isPressed ? 0.95 : 1.0)
                }
                .buttonStyle(.plain)
                .onHover { hovering in
                    withAnimation(Design.Animation.fast) { isHovered = hovering }
                }
                .pressEvents {
                    withAnimation(Design.Animation.fast) { isPressed = true }
                } onRelease: {
                    withAnimation(Design.Animation.spring) { isPressed = false }
                }
                .accessibilityLabel("\(title): \(value)")
                .accessibilityHint("Double-tap to configure")
            } else {
                HStack(spacing: Design.Spacing.xs) {
                    if differentiateWithoutColor {
                        Image(systemName: isGood ? "checkmark.circle.fill" : "xmark.circle")
                            .font(.system(size: 10))
                            .foregroundColor(isGood ? Design.Colors.success : Design.Colors.tertiaryText)
                    } else {
                        AnimatedStatusIndicator(
                            isActive: isGood,
                            activeColor: Design.Colors.success,
                            inactiveColor: Design.Colors.tertiaryText
                        )
                    }

                    Text(value)
                        .font(Design.Typography.labelMedium)
                        .foregroundColor(Design.Colors.secondaryText)
                        .contentTransition(.numericText())
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("\(title): \(value)")
                .accessibilityValue(isGood ? "OK" : "")
            }
        }
        .padding(.vertical, Design.Spacing.sm)
        .padding(.horizontal, Design.Spacing.sm)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                .fill(isHovered ? Design.Colors.hover : Color.clear)
        )
        .onHover { hovering in
            withAnimation(Design.Animation.fast) { isHovered = hovering }
        }
        .opacity(didAppear ? 1 : 0)
        .offset(x: didAppear ? 0 : -10)
        .onAppear {
            guard !reduceMotion else {
                didAppear = true
                return
            }
            withAnimation(Design.Animation.stateChange) {
                didAppear = true
            }
        }
        .accessibilityIdentifier("status-\(title.lowercased())")
    }
}

// MARK: - Setup Required Content

struct SetupRequiredContent: View {
    let reduceMotion: Bool
    let action: () -> Void

    @State private var iconFloat = false
    @State private var appeared = false

    var body: some View {
        VStack(spacing: Design.Spacing.xl) {
            Spacer(minLength: Design.Spacing.xl)

            animatedIconSection
                .opacity(appeared ? 1 : 0)
                .scaleEffect(appeared ? 1 : 0.8)

            textSection
                .opacity(appeared ? 1 : 0)
                .offset(y: appeared ? 0 : 10)

            GetStartedButton(action: action)
                .opacity(appeared ? 1 : 0)
                .scaleEffect(appeared ? 1 : 0.9)

            Spacer(minLength: Design.Spacing.xl)
        }
        .padding(.horizontal, Design.Spacing.lg)
        .onAppear {
            guard !reduceMotion else {
                appeared = true
                return
            }
            withAnimation(Design.Animation.stateChange.delay(0.1)) {
                appeared = true
            }
            withAnimation(Design.Animation.gentle.repeatForever(autoreverses: true)) {
                iconFloat = true
            }
        }
    }

    // MARK: - Subviews (extracted to help Swift type checker)

    @ViewBuilder
    private var animatedIconSection: some View {
        ZStack {
            // Animated background rings
            if !reduceMotion {
                backgroundRings
            }

            // Glow effect
            glowCircle

            Image(systemName: "wand.and.stars")
                .font(.system(size: Design.IconSize.hero))
                .foregroundStyle(Design.Colors.brandGradient)
                .symbolEffect(.bounce, options: .repeating.speed(0.3), value: appeared)
        }
    }

    @ViewBuilder
    private var backgroundRings: some View {
        BackgroundRingView(index: 0, iconFloat: iconFloat, appeared: appeared)
        BackgroundRingView(index: 1, iconFloat: iconFloat, appeared: appeared)
        BackgroundRingView(index: 2, iconFloat: iconFloat, appeared: appeared)
    }
}

// Helper view to work around Swift type checker limitations
private struct BackgroundRingView: View {
    let index: Int
    let iconFloat: Bool
    let appeared: Bool

    var body: some View {
        let size: CGFloat = Design.IconSize.hero + 30 + CGFloat(index * 20)
        let strokeOpacity: Double = 0.1 - Double(index) * 0.03
        let delayValue: Double = Double(index) * 0.15

        Circle()
            .stroke(Color.accentColor.opacity(strokeOpacity), lineWidth: 1)
            .frame(width: size, height: size)
            .scaleEffect(iconFloat ? 1.05 : 0.95)
            .opacity(appeared ? 1 : 0)
            .animation(
                Design.Animation.gentle
                    .repeatForever(autoreverses: true)
                    .delay(delayValue),
                value: iconFloat
            )
    }
}

// Continuation of SetupRequiredContent
private extension SetupRequiredContent {

    private var glowCircle: some View {
        let glowGradient = RadialGradient(
            colors: [Color.accentColor.opacity(0.2), Color.clear],
            center: .center,
            startRadius: 0,
            endRadius: Design.IconSize.hero
        )
        return Circle()
            .fill(glowGradient)
            .frame(width: Design.IconSize.hero * 2, height: Design.IconSize.hero * 2)
            .opacity(appeared ? 1 : 0)
    }

    private var textSection: some View {
        VStack(spacing: Design.Spacing.sm) {
            Text("Welcome to Witnessd")
                .font(Design.Typography.headlineLarge)
                .foregroundColor(Design.Colors.primaryText)

            Text("Set up Witnessd to start creating cryptographic proof of your authorship.")
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.secondaryText)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Get Started Button

struct GetStartedButton: View {
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false
    @State private var shimmerOffset: CGFloat = -1
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: action) {
            HStack(spacing: Design.Spacing.sm) {
                Image(systemName: "arrow.right.circle.fill")
                    .symbolEffect(.bounce, value: isHovered)
                Text("Get Started")
            }
            .font(Design.Typography.headlineMedium)
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, Design.Spacing.md)
            .background(
                ZStack {
                    // Base gradient
                    RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                        .fill(Design.Colors.brandGradient)

                    // Shimmer overlay
                    if !reduceMotion {
                        RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [
                                        Color.white.opacity(0),
                                        Color.white.opacity(0.3),
                                        Color.white.opacity(0)
                                    ],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .offset(x: shimmerOffset * 200)
                            .mask(
                                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                            )
                    }
                }
            )
            .overlay(
                RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                    .strokeBorder(Color.white.opacity(isHovered ? 0.3 : 0.1), lineWidth: 1)
            )
            .scaleEffect(isPressed ? 0.97 : (isHovered ? 1.02 : 1.0))
            .shadow(
                color: Color.accentColor.opacity(isHovered ? 0.4 : 0.2),
                radius: isHovered ? 12 : 6,
                y: isHovered ? 4 : 2
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(Design.Animation.fast) { isHovered = hovering }
        }
        .pressEvents {
            withAnimation(Design.Animation.fast) { isPressed = true }
        } onRelease: {
            withAnimation(Design.Animation.spring) { isPressed = false }
        }
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) {
                shimmerOffset = 1
            }
        }
        .accessibilityLabel("Get Started")
        .accessibilityHint("Double-tap to initialize Witnessd")
        .accessibilityIdentifier("initialize-witness")
    }
}
