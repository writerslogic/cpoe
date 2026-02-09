import SwiftUI

struct HistoryView: View {
    let bridge: WitnessdBridge
    let closeAction: () -> Void

    @State private var service = WitnessdService.shared
    @State private var files: [TrackedFile] = []
    @State private var isLoading = false
    @State private var selectedFile: TrackedFile? = nil
    @State private var searchText: String = ""
    @State private var sortOrder: SortOrder = .dateDescending
    @State private var filterStatus: FilterStatus = .all

    /// Debounce timer for search input
    @State private var searchDebounceTask: Task<Void, Never>?

    /// Cached filtered results to avoid recomputing on every render
    @State private var cachedFilteredFiles: [TrackedFile] = []
    @State private var lastSearchText: String = ""
    @State private var lastSortOrder: SortOrder = .dateDescending
    @State private var lastFilterStatus: FilterStatus = .all
    @State private var lastFilesHash: Int = 0

    enum SortOrder: String, CaseIterable {
        case dateDescending = "Newest First"
        case dateAscending = "Oldest First"
        case nameAscending = "Name A-Z"
        case nameDescending = "Name Z-A"
        case eventsDescending = "Most Events"
    }

    enum FilterStatus: String, CaseIterable {
        case all = "All"
        case verified = "Verified"
        case pending = "Pending"
        case failed = "Failed"
    }

    var filteredAndSortedFiles: [TrackedFile] {
        // Return cached result if inputs haven't changed
        let currentFilesHash = files.hashValue
        if searchText == lastSearchText &&
           sortOrder == lastSortOrder &&
           filterStatus == lastFilterStatus &&
           currentFilesHash == lastFilesHash {
            return cachedFilteredFiles
        }

        var result = files

        // Apply search filter
        if !searchText.isEmpty {
            let lowercasedSearch = searchText.lowercased()
            result = result.filter { file in
                file.name.lowercased().contains(lowercasedSearch) ||
                file.path.lowercased().contains(lowercasedSearch)
            }
        }

        // Apply status filter
        switch filterStatus {
        case .all:
            break
        case .verified:
            result = result.filter { $0.verificationStatus == .verified }
        case .pending:
            result = result.filter { $0.verificationStatus == .pending || $0.verificationStatus == .unknown }
        case .failed:
            result = result.filter { $0.verificationStatus == .failed }
        }

        // Apply sort
        switch sortOrder {
        case .dateDescending:
            result.sort { ($0.lastModified ?? Date.distantPast) > ($1.lastModified ?? Date.distantPast) }
        case .dateAscending:
            result.sort { ($0.lastModified ?? Date.distantPast) < ($1.lastModified ?? Date.distantPast) }
        case .nameAscending:
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .nameDescending:
            result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedDescending }
        case .eventsDescending:
            result.sort { $0.events > $1.events }
        }

        // Update cache (done asynchronously to avoid mutation during view update)
        Task { @MainActor in
            cachedFilteredFiles = result
            lastSearchText = searchText
            lastSortOrder = sortOrder
            lastFilterStatus = filterStatus
            lastFilesHash = currentFilesHash
        }

        return result
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            headerView

            Divider()

            // Toolbar
            toolbarView

            Divider()

            if isLoading {
                Spacer()
                ProgressView("Loading documents...")
                    .font(Design.Typography.bodyMedium)
                Spacer()
            } else if files.isEmpty {
                emptyStateView
            } else if filteredAndSortedFiles.isEmpty {
                noResultsView
            } else {
                HSplitView {
                    // File list
                    fileListView
                        .frame(minWidth: 200, maxWidth: 320)

                    // Detail view
                    detailView
                }
            }
        }
        .frame(width: Design.Layout.historyWidth, height: Design.Layout.historyHeight)
        .task {
            await loadFiles()
        }
    }

    // MARK: - Header

    private var headerView: some View {
        HStack {
            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text("Document History")
                    .font(Design.Typography.headlineLarge)
                    .foregroundColor(Design.Colors.primaryText)
                    .accessibilityAddTraits(.isHeader)

                Text("\(files.count) tracked documents")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Document History, \(files.count) tracked documents")

            Spacer()

            IconButton(icon: "arrow.clockwise", label: "Refresh", hint: "Reload the document list", size: Design.IconSize.sm) {
                Task {
                    AccessibilityAnnouncer.shared.announceLoading("Refreshing documents")
                    await loadFiles()
                    AccessibilityAnnouncer.shared.announce("\(files.count) documents loaded")
                }
            }

            IconButton(icon: "xmark.circle.fill", label: "Close", hint: "Close the history window", size: Design.IconSize.sm) {
                closeAction()
            }
            .keyboardShortcut(.escape, modifiers: [])
        }
        .padding(Design.Spacing.lg)
        .background(Design.Colors.secondaryBackground)
    }

    // MARK: - Toolbar

    /// Internal search text that triggers debounced updates
    @State private var debouncedSearchText: String = ""

    private var toolbarView: some View {
        HStack(spacing: Design.Spacing.md) {
            // Search field with debouncing
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(Design.Colors.tertiaryText)
                    .accessibilityHidden(true)
                TextField("Search documents...", text: $debouncedSearchText)
                    .textFieldStyle(.plain)
                    .accessibilityLabel("Search documents")
                    .accessibilityHint("Type to filter the document list")
                    .onChange(of: debouncedSearchText) { _, newValue in
                        // Cancel previous debounce task
                        searchDebounceTask?.cancel()

                        // Debounce search input by 300ms
                        searchDebounceTask = Task {
                            try? await Task.sleep(nanoseconds: 300_000_000)
                            if !Task.isCancelled {
                                searchText = newValue
                            }
                        }
                    }

                if !debouncedSearchText.isEmpty {
                    Button(action: {
                        debouncedSearchText = ""
                        searchText = ""
                    }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(Design.Colors.tertiaryText)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear search")
                    .accessibilityHint("Clears the search field")
                }
            }
            .padding(.horizontal, Design.Spacing.sm)
            .padding(.vertical, Design.Spacing.xs)
            .background(Design.Colors.secondaryBackground)
            .cornerRadius(Design.Radius.sm)
            .frame(maxWidth: 240)

            Spacer()

            // Filter by status
            Picker("Status", selection: $filterStatus) {
                ForEach(FilterStatus.allCases, id: \.self) { status in
                    Text(status.rawValue).tag(status)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 100)
            .accessibilityLabel("Filter by status")
            .accessibilityValue(filterStatus.rawValue)
            .accessibilityHint("Select a status to filter documents")

            // Sort order
            Picker("Sort", selection: $sortOrder) {
                ForEach(SortOrder.allCases, id: \.self) { order in
                    Text(order.rawValue).tag(order)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 140)
            .accessibilityLabel("Sort order")
            .accessibilityValue(sortOrder.rawValue)
            .accessibilityHint("Select how to sort documents")
        }
        .padding(.horizontal, Design.Spacing.lg)
        .padding(.vertical, Design.Spacing.sm)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Document filters and search")
    }

    // MARK: - Empty State

    private var emptyStateView: some View {
        AnimatedEmptyState(
            icon: "doc.text.magnifyingglass",
            title: "No tracked documents",
            message: "Start tracking a document to see it here.\nYour tracked documents and their evidence will appear in this list.",
            action: nil,
            actionLabel: nil
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("No tracked documents. Start tracking a document to see it here.")
    }

    // MARK: - No Results

    private var noResultsView: some View {
        AnimatedEmptyState(
            icon: "magnifyingglass",
            title: "No matching documents",
            message: "Try adjusting your search or filters.",
            action: {
                searchText = ""
                debouncedSearchText = ""
                filterStatus = .all
                AccessibilityAnnouncer.shared.announce("Filters cleared")
            },
            actionLabel: "Clear Filters"
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("No matching documents. Try adjusting your search or filters.")
    }

    // MARK: - File List

    private var fileListView: some View {
        List(filteredAndSortedFiles, id: \.id, selection: $selectedFile) { file in
            FileRowEnhanced(file: file)
                .tag(file)
                .id(file.id) // Explicit ID for efficient diffing
        }
        .listStyle(.sidebar)
        .accessibilityLabel("Document list")
        .accessibilityHint("Select a document to view its details")
        .onChange(of: selectedFile) { _, newValue in
            if let file = newValue {
                AccessibilityAnnouncer.shared.announce("Selected \(file.name)")
            }
        }
    }

    // MARK: - Detail View

    @ViewBuilder
    private var detailView: some View {
        if let file = selectedFile {
            FileDetailViewEnhanced(file: file, bridge: bridge, service: service)
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Details for \(file.name)")
        } else {
            VStack {
                Spacer()
                VStack(spacing: Design.Spacing.md) {
                    Image(systemName: "doc.text")
                        .font(.system(size: Design.IconSize.xxl))
                        .foregroundColor(Design.Colors.tertiaryText)
                        .accessibilityHidden(true)
                    Text("Select a document to view details")
                        .font(Design.Typography.bodyMedium)
                        .foregroundColor(Design.Colors.secondaryText)
                }
                Spacer()
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("No document selected. Select a document from the list to view its details.")
        }
    }

    // MARK: - Data Loading

    private func loadFiles() async {
        isLoading = true
        let result = await bridge.listTrackedFiles()
        files = result
        isLoading = false
    }
}

// MARK: - Enhanced Tracked File Model

struct TrackedFile: Identifiable, Hashable {
    let id: String
    let path: String
    let name: String
    let events: Int
    let lastModified: Date?
    var verificationStatus: VerificationStatus = .unknown
    var checkpointCount: Int = 0
    var keystrokeCount: Int = 0

    enum VerificationStatus: String {
        case verified = "verified"
        case pending = "pending"
        case failed = "failed"
        case unknown = "unknown"
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    static func == (lhs: TrackedFile, rhs: TrackedFile) -> Bool {
        lhs.id == rhs.id
    }
}

// MARK: - Animated Empty State for History View

struct AnimatedEmptyState: View {
    let icon: String
    let title: String
    let message: String
    let action: (() -> Void)?
    let actionLabel: String?

    @State private var isAppeared = false
    @State private var iconPulse = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            Spacer()

            ZStack {
                // Subtle animated background
                if !reduceMotion {
                    Circle()
                        .fill(Color.accentColor.opacity(0.05))
                        .frame(width: Design.IconSize.hero + 40, height: Design.IconSize.hero + 40)
                        .scaleEffect(iconPulse ? 1.1 : 0.9)
                        .animation(
                            Design.Animation.gentle.repeatForever(autoreverses: true),
                            value: iconPulse
                        )
                }

                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.hero))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Design.Colors.tertiaryText, Design.Colors.tertiaryText.opacity(0.5)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .symbolEffect(.pulse, options: .repeating.speed(0.5), value: isAppeared)
            }
            .opacity(isAppeared ? 1 : 0)
            .scaleEffect(isAppeared ? 1 : 0.8)
            .accessibilityHidden(true)

            VStack(spacing: Design.Spacing.sm) {
                Text(title)
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.secondaryText)

                Text(message)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .multilineTextAlignment(.center)
            }
            .opacity(isAppeared ? 1 : 0)
            .offset(y: isAppeared ? 0 : 10)

            if let action = action, let label = actionLabel {
                Button(label, action: action)
                    .buttonStyle(.bordered)
                    .opacity(isAppeared ? 1 : 0)
                    .scaleEffect(isAppeared ? 1 : 0.9)
            }

            Spacer()
        }
        .onAppear {
            guard !reduceMotion else {
                isAppeared = true
                return
            }
            withAnimation(Design.Animation.stateChange.delay(0.1)) {
                isAppeared = true
            }
            iconPulse = true
        }
    }
}

// MARK: - Enhanced File Row

struct FileRowEnhanced: View {
    let file: TrackedFile

    @State private var isHovered = false
    @State private var didAppear = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            // Status indicator with animation
            statusIcon
                .frame(width: Design.IconSize.lg + 4, height: Design.IconSize.lg + 4)

            // File info
            VStack(alignment: .leading, spacing: Design.Spacing.xxxs) {
                Text(file.name)
                    .font(Design.Typography.bodyMedium)
                    .foregroundColor(Design.Colors.primaryText)
                    .lineLimit(1)

                HStack(spacing: Design.Spacing.xs) {
                    HStack(spacing: Design.Spacing.xxs) {
                        Image(systemName: "number")
                            .font(.system(size: 9))
                        Text("\(file.events)")
                    }
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .padding(.horizontal, Design.Spacing.xs)
                    .padding(.vertical, 2)
                    .background(
                        Capsule()
                            .fill(Design.Colors.secondaryBackground)
                    )

                    if let date = file.lastModified {
                        Text(date.formatted(.relative(presentation: .named)))
                            .font(Design.Typography.labelSmall)
                            .foregroundColor(Design.Colors.tertiaryText)
                    }
                }
            }

            Spacer()

            // Hover indicator
            if isHovered {
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(Design.Colors.tertiaryText)
                    .transition(.opacity.combined(with: .move(edge: .trailing)))
            }
        }
        .padding(.vertical, Design.Spacing.xs)
        .padding(.horizontal, Design.Spacing.xs)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                .fill(isHovered ? Design.Colors.hover : Color.clear)
        )
        .onHover { hovering in
            withAnimation(Design.Animation.fast) { isHovered = hovering }
        }
        .opacity(didAppear ? 1 : 0)
        .offset(x: didAppear ? 0 : -5)
        .onAppear {
            guard !reduceMotion else {
                didAppear = true
                return
            }
            withAnimation(Design.Animation.stateChange.delay(0.05)) {
                didAppear = true
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(file.name), \(file.events) events, \(verificationLabel)")
    }

    @ViewBuilder
    private var statusIcon: some View {
        ZStack {
            // Background circle with status color
            Circle()
                .fill(statusBackgroundColor)

            switch file.verificationStatus {
            case .verified:
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(Design.Colors.success)
                    .help("Verified")
            case .pending:
                Image(systemName: "clock.fill")
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(Design.Colors.warning)
                    .help("Pending verification")
            case .failed:
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(Design.Colors.error)
                    .help("Verification failed")
            case .unknown:
                Image(systemName: "doc.text.fill")
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(.accentColor)
                    .help("Not yet verified")
            }
        }
    }

    private var statusBackgroundColor: Color {
        switch file.verificationStatus {
        case .verified: return Design.Colors.success.opacity(0.1)
        case .pending: return Design.Colors.warning.opacity(0.1)
        case .failed: return Design.Colors.error.opacity(0.1)
        case .unknown: return Color.accentColor.opacity(0.1)
        }
    }

    private var verificationLabel: String {
        switch file.verificationStatus {
        case .verified: return "verified"
        case .pending: return "pending verification"
        case .failed: return "verification failed"
        case .unknown: return "not verified"
        }
    }
}

// MARK: - Enhanced File Detail View

struct FileDetailViewEnhanced: View {
    let file: TrackedFile
    let bridge: WitnessdBridge
    let service: WitnessdService

    @State private var logContent: String = ""
    @State private var isLoading = false
    @State private var isVerifying = false
    @State private var verificationResult: String? = nil
    @State private var verificationPassed: Bool? = nil

    // Export tier selection state
    @State private var showingTierSheet = false
    @State private var selectedExportTier: ExportTier = .standard
    @State private var pendingExportSourceURL: URL? = nil
    @State private var pendingExportDestURL: URL? = nil

    /// Track if log has been loaded for this file
    @State private var hasLoadedLog = false

    /// Track last loaded file to detect selection changes
    @State private var lastLoadedFilePath: String = ""

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Design.Spacing.xl) {
                // Header with document info
                headerSection

                Divider()

                // Statistics grid
                statsSection

                Divider()

                // Verification section
                verificationSection

                Divider()

                // Actions section
                actionsSection

                Divider()

                // Event log section - lazy loaded
                logSection
            }
            .padding(Design.Spacing.lg)
        }
        .task(id: file.id) {
            // Only load log when file selection changes
            if lastLoadedFilePath != file.path {
                lastLoadedFilePath = file.path
                hasLoadedLog = false
                logContent = ""
                verificationResult = nil
                verificationPassed = nil
            }
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

    // MARK: - Header Section

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.sm) {
            HStack {
                VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                    Text(file.name)
                        .font(Design.Typography.displaySmall)
                        .foregroundColor(Design.Colors.primaryText)

                    Text(file.path)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.secondaryText)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }

                Spacer()

                // Open in Finder button
                Button(action: openInFinder) {
                    Image(systemName: "folder")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("Reveal in Finder")
            }
        }
    }

    // MARK: - Stats Section

    private var statsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Statistics")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)

            HStack(spacing: Design.Spacing.xxl) {
                StatBadge(icon: "number", value: "\(file.events)", label: "Events")

                if let date = file.lastModified {
                    StatBadge(icon: "clock", value: date.formatted(.relative(presentation: .named)), label: "Last Modified")
                }

                if file.checkpointCount > 0 {
                    StatBadge(icon: "checkmark.circle", value: "\(file.checkpointCount)", label: "Checkpoints")
                }

                if file.keystrokeCount > 0 {
                    StatBadge(icon: "keyboard", value: formatNumber(file.keystrokeCount), label: "Keystrokes")
                }
            }
        }
    }

    // MARK: - Verification Section

    private var verificationSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Verification")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)

            HStack(spacing: Design.Spacing.lg) {
                // Status badge
                verificationStatusBadge

                Spacer()

                // Verify button
                Button(action: { Task { await verifyEvidence() } }) {
                    HStack(spacing: Design.Spacing.xs) {
                        if isVerifying {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "checkmark.shield")
                        }
                        Text("Verify")
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isVerifying)
            }

            if let result = verificationResult {
                VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                    HStack {
                        Image(systemName: verificationPassed == true ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundColor(verificationPassed == true ? Design.Colors.success : Design.Colors.error)
                        Text(verificationPassed == true ? "Verification Passed" : "Verification Failed")
                            .font(Design.Typography.headlineSmall)
                            .foregroundColor(verificationPassed == true ? Design.Colors.success : Design.Colors.error)
                    }

                    Text(result)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.secondaryText)
                        .padding(Design.Spacing.sm)
                        .background(Design.Colors.tertiaryBackground)
                        .cornerRadius(Design.Radius.sm)
                }
            }
        }
    }

    @ViewBuilder
    private var verificationStatusBadge: some View {
        HStack(spacing: Design.Spacing.xs) {
            switch file.verificationStatus {
            case .verified:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(Design.Colors.success)
                Text("Verified")
                    .foregroundColor(Design.Colors.success)
            case .pending:
                Image(systemName: "clock.badge.questionmark")
                    .foregroundColor(Design.Colors.warning)
                Text("Pending")
                    .foregroundColor(Design.Colors.warning)
            case .failed:
                Image(systemName: "xmark.shield.fill")
                    .foregroundColor(Design.Colors.error)
                Text("Failed")
                    .foregroundColor(Design.Colors.error)
            case .unknown:
                Image(systemName: "questionmark.circle")
                    .foregroundColor(Design.Colors.secondaryText)
                Text("Not Verified")
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .font(Design.Typography.labelMedium)
        .padding(.horizontal, Design.Spacing.md)
        .padding(.vertical, Design.Spacing.sm)
        .background(Design.Colors.secondaryBackground)
        .cornerRadius(Design.Radius.md)
    }

    // MARK: - Actions Section

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            Text("Actions")
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)
                .accessibilityAddTraits(.isHeader)

            HStack(spacing: Design.Spacing.md) {
                Button(action: exportEvidence) {
                    Label("Export Evidence", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Export Evidence")
                .accessibilityHint("Export cryptographic evidence for this document")

                Button(action: { Task { await loadLog() } }) {
                    Label("Refresh Log", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Refresh Log")
                .accessibilityHint("Reload the event log for this document")

                Button(action: copyPath) {
                    Label("Copy Path", systemImage: "doc.on.doc")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Copy Path")
                .accessibilityHint("Copy the document path to clipboard")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Actions section")
    }

    // MARK: - Log Section

    private var logSection: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.md) {
            HStack {
                Text("Event Log")
                    .font(Design.Typography.headlineSmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .textCase(.uppercase)

                Spacer()

                if isLoading {
                    ProgressView()
                        .scaleEffect(0.7)
                }

                // Load log button for lazy loading
                if !hasLoadedLog && !isLoading {
                    Button(action: {
                        Task { await loadLog() }
                    }) {
                        Label("Load Log", systemImage: "arrow.down.circle")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }

            if !hasLoadedLog {
                VStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "doc.text")
                        .font(.system(size: Design.IconSize.lg))
                        .foregroundColor(Design.Colors.tertiaryText)
                    Text("Click 'Load Log' to view events")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .frame(maxWidth: .infinity)
                .padding(Design.Spacing.xl)
                .background(Design.Colors.tertiaryBackground)
                .cornerRadius(Design.Radius.md)
            } else if logContent.isEmpty && !isLoading {
                VStack(spacing: Design.Spacing.sm) {
                    Image(systemName: "doc.text")
                        .font(.system(size: Design.IconSize.lg))
                        .foregroundColor(Design.Colors.tertiaryText)
                    Text("No events recorded yet")
                        .font(Design.Typography.bodySmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .frame(maxWidth: .infinity)
                .padding(Design.Spacing.xl)
                .background(Design.Colors.tertiaryBackground)
                .cornerRadius(Design.Radius.md)
            } else {
                ScrollView {
                    Text(logContent)
                        .font(Design.Typography.mono)
                        .foregroundColor(Design.Colors.primaryText)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Design.Spacing.sm)
                }
                .frame(minHeight: 200)
                .background(Design.Colors.tertiaryBackground)
                .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
            }
        }
    }

    // MARK: - Actions

    private func loadLog() async {
        isLoading = true
        let result = await bridge.log(filePath: file.path)
        logContent = result.message
        hasLoadedLog = true
        isLoading = false
    }

    private func verifyEvidence() async {
        isVerifying = true
        verificationResult = nil
        verificationPassed = nil

        let result = await bridge.verify(filePath: file.path)

        verificationPassed = result.success
        verificationResult = result.message
        isVerifying = false
    }

    private func exportEvidence() {
        // Pre-fill with the current file
        pendingExportSourceURL = URL(fileURLWithPath: file.path)
        // Suggest destination in Downloads folder
        let suggestedName = URL(fileURLWithPath: file.path).deletingPathExtension().lastPathComponent + ".evidence.json"
        if let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first {
            pendingExportDestURL = downloadsURL.appendingPathComponent(suggestedName)
        }
        selectedExportTier = ExportTier(rawValue: service.settings.defaultExportTier) ?? .standard
        showingTierSheet = true
    }

    private func performExport() {
        guard let sourceURL = pendingExportSourceURL,
              let destURL = pendingExportDestURL else {
            return
        }

        Task {
            isLoading = true
            let result = await bridge.export(filePath: sourceURL.path, tier: selectedExportTier.rawValue, outputPath: destURL.path)
            isLoading = false

            pendingExportSourceURL = nil
            pendingExportDestURL = nil

            if result.success {
                let alert = NSAlert()
                alert.messageText = "Evidence Exported"
                alert.informativeText = "Saved to: \(destURL.lastPathComponent)"
                alert.alertStyle = .informational
                alert.runModal()
            } else {
                let alert = NSAlert()
                alert.messageText = "Export Failed"
                alert.informativeText = result.message
                alert.alertStyle = .warning
                alert.runModal()
            }
        }
    }

    private func openInFinder() {
        let url = URL(fileURLWithPath: file.path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    private func copyPath() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(file.path, forType: .string)
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

// MARK: - Stat Badge

struct StatBadge: View {
    let icon: String
    let value: String
    let label: String

    @State private var isHovered = false
    @State private var didAppear = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            ZStack {
                Circle()
                    .fill(Color.accentColor.opacity(0.1))
                    .frame(width: Design.IconSize.lg, height: Design.IconSize.lg)

                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.sm))
                    .foregroundColor(.accentColor)
            }

            VStack(alignment: .leading, spacing: 0) {
                Text(value)
                    .font(Design.Typography.statValue)
                    .foregroundColor(Design.Colors.primaryText)
                    .contentTransition(.numericText())
                Text(label)
                    .font(Design.Typography.statLabel)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .padding(.horizontal, Design.Spacing.md)
        .padding(.vertical, Design.Spacing.sm)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .fill(Design.Colors.secondaryBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                        .strokeBorder(
                            isHovered ? Color.accentColor.opacity(0.2) : Color.clear,
                            lineWidth: 1
                        )
                )
        )
        .scaleEffect(isHovered ? 1.02 : 1.0)
        .shadow(
            color: isHovered ? Color.accentColor.opacity(0.1) : .clear,
            radius: isHovered ? 4 : 0,
            y: isHovered ? 2 : 0
        )
        .onHover { hovering in
            withAnimation(Design.Animation.fast) { isHovered = hovering }
        }
        .opacity(didAppear ? 1 : 0)
        .offset(y: didAppear ? 0 : 5)
        .onAppear {
            guard !reduceMotion else {
                didAppear = true
                return
            }
            withAnimation(Design.Animation.stateChange.delay(0.1)) {
                didAppear = true
            }
        }
    }
}

// MARK: - File List Cache

/// Thread-safe cache for tracked files list
@MainActor
final class TrackedFilesCache {
    static let shared = TrackedFilesCache()

    private var cachedFiles: [TrackedFile] = []
    private var lastFetchTime: Date?
    private var isFetching = false

    /// Cache TTL in seconds - files list doesn't change frequently
    private let cacheTTL: TimeInterval = 30.0

    private init() {}

    var files: [TrackedFile] { cachedFiles }

    var isCacheValid: Bool {
        guard let lastFetch = lastFetchTime else { return false }
        return Date().timeIntervalSince(lastFetch) < cacheTTL
    }

    func invalidate() {
        lastFetchTime = nil
    }

    func updateCache(_ files: [TrackedFile]) {
        cachedFiles = files
        lastFetchTime = Date()
    }
}

// MARK: - Extension to WitnessdBridge for listing tracked files

extension WitnessdBridge {
    func listTrackedFiles(forceRefresh: Bool = false) async -> [TrackedFile] {
        // Check cache on main actor
        let cacheResult = await MainActor.run { () -> (isValid: Bool, files: [TrackedFile]) in
            let cache = TrackedFilesCache.shared
            return (cache.isCacheValid, cache.files)
        }

        // Return cached data if valid and not forcing refresh
        if !forceRefresh && cacheResult.isValid {
            return cacheResult.files
        }

        // Read tracked files directly from the SQLite database
        // since the Go CLI doesn't have a 'list' command
        let files: [TrackedFile] = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                var files: [TrackedFile] = []

                // Get the database path from Application Support
                guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
                    continuation.resume(returning: files)
                    return
                }

                let dbPath = appSupport.appendingPathComponent("Witnessd/events.db").path

                // Check if database exists
                guard FileManager.default.fileExists(atPath: dbPath) else {
                    continuation.resume(returning: files)
                    return
                }

                // Use sqlite3 command to query the database
                // Optimized query with LIMIT for pagination potential
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
                process.arguments = [
                    "-separator", "\t",  // Use tab as separator to avoid pipe conflicts
                    dbPath,
                    "SELECT file_path, COUNT(*) as event_count, MAX(timestamp_ns) as last_modified FROM secure_events GROUP BY file_path ORDER BY last_modified DESC LIMIT 500;"
                ]

                let outputPipe = Pipe()
                process.standardOutput = outputPipe
                process.standardError = FileHandle.nullDevice

                // Set up timeout
                let timeoutWorkItem = DispatchWorkItem {
                    if process.isRunning {
                        process.terminate()
                    }
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + 5.0, execute: timeoutWorkItem)

                do {
                    try process.run()
                    process.waitUntilExit()
                    timeoutWorkItem.cancel()

                    // Check exit status
                    guard process.terminationStatus == 0 else {
                        continuation.resume(returning: files)
                        return
                    }

                    let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                    guard let output = String(data: outputData, encoding: .utf8), !output.isEmpty else {
                        continuation.resume(returning: files)
                        return
                    }

                    // Parse the output - format is: file_path\tevent_count\ttimestamp_ns
                    // Pre-allocate array capacity for better performance
                    let lines = output.components(separatedBy: "\n")
                    files.reserveCapacity(lines.count)

                    for line in lines {
                        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !trimmed.isEmpty else { continue }

                        let parts = trimmed.components(separatedBy: "\t")
                        // Validate we have expected number of columns
                        guard parts.count >= 2 else { continue }

                        let path = parts[0]
                        guard !path.isEmpty else { continue }

                        let events = Int(parts[1]) ?? 0

                        // Parse timestamp (nanoseconds since epoch)
                        var lastModified: Date? = nil
                        if parts.count >= 3, !parts[2].isEmpty, let timestampNs = Int64(parts[2]) {
                            lastModified = Date(timeIntervalSince1970: Double(timestampNs) / 1_000_000_000.0)
                        }

                        let url = URL(fileURLWithPath: path)

                        files.append(TrackedFile(
                            id: path,
                            path: path,
                            name: url.lastPathComponent,
                            events: events,
                            lastModified: lastModified
                        ))
                    }
                } catch {
                    // Log error for debugging (in production, use os.log)
                    #if DEBUG
                    print("listTrackedFiles error: \(error.localizedDescription)")
                    #endif
                }

                continuation.resume(returning: files)
            }
        }

        // Update cache on main actor
        await MainActor.run {
            TrackedFilesCache.shared.updateCache(files)
        }

        return files
    }
}
