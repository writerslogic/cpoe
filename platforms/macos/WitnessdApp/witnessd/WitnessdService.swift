import Foundation
import SwiftUI
import Combine
import os.log

// MARK: - Session Model

/// Represents a tracked writing session
struct WritingSession: Identifiable, Hashable, Sendable {
    let id: String
    let documentPath: String
    let documentName: String
    var keystrokeCount: Int
    var checkpointCount: Int
    var startTime: Date
    var endTime: Date?
    var duration: TimeInterval
    var verificationStatus: VerificationStatus

    enum VerificationStatus: String, Sendable {
        case verified = "verified"
        case pending = "pending"
        case failed = "failed"
        case unknown = "unknown"
    }

    var formattedDuration: String {
        let hours = Int(duration) / 3600
        let minutes = Int(duration) / 60 % 60
        let seconds = Int(duration) % 60

        if hours > 0 {
            return String(format: "%d:%02d:%02d", hours, minutes, seconds)
        } else {
            return String(format: "%d:%02d", minutes, seconds)
        }
    }

    var isActive: Bool {
        endTime == nil
    }
}

// MARK: - Watch Path Model

/// Represents a configured watch path
struct WatchPath: Identifiable, Hashable, Codable {
    let id: UUID
    var path: String
    var isEnabled: Bool

    init(path: String, isEnabled: Bool = true) {
        self.id = UUID()
        self.path = path
        self.isEnabled = isEnabled
    }

    var displayName: String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    var exists: Bool {
        FileManager.default.fileExists(atPath: path)
    }
}

// MARK: - Settings Model

/// Application settings stored in UserDefaults
@Observable
final class WitnessdSettings {
    // MARK: - Watch Paths
    var watchPaths: [WatchPath] = [] {
        didSet { saveWatchPaths() }
    }

    // MARK: - Include Patterns
    var includePatterns: [String] = [".txt", ".md", ".rtf", ".doc", ".docx"] {
        didSet { UserDefaults.standard.set(includePatterns, forKey: "includePatterns") }
    }

    // MARK: - Debounce
    var debounceIntervalMs: Int = 500 {
        didSet { UserDefaults.standard.set(debounceIntervalMs, forKey: "debounceIntervalMs") }
    }

    // MARK: - Signing Key
    var signingKeyPath: String = "" {
        didSet { UserDefaults.standard.set(signingKeyPath, forKey: "signingKeyPath") }
    }

    // MARK: - TPM
    var tpmAttestationEnabled: Bool = false {
        didSet { UserDefaults.standard.set(tpmAttestationEnabled, forKey: "tpmAttestationEnabled") }
    }

    // MARK: - Checkpoint
    var autoCheckpoint: Bool = false {
        didSet { UserDefaults.standard.set(autoCheckpoint, forKey: "autoCheckpoint") }
    }

    var checkpointIntervalMinutes: Int = 30 {
        didSet { UserDefaults.standard.set(checkpointIntervalMinutes, forKey: "checkpointIntervalMinutes") }
    }

    // MARK: - Export
    var defaultExportFormat: String = "json" {
        didSet { UserDefaults.standard.set(defaultExportFormat, forKey: "defaultExportFormat") }
    }

    var defaultExportTier: String = "standard" {
        didSet { UserDefaults.standard.set(defaultExportTier, forKey: "defaultExportTier") }
    }

    // MARK: - Launch
    var openAtLogin: Bool = false {
        didSet {
            UserDefaults.standard.set(openAtLogin, forKey: "openAtLogin")
            LaunchAtLogin.isEnabled = openAtLogin
        }
    }

    // MARK: - Notifications
    var showNotifications: Bool = true {
        didSet { UserDefaults.standard.set(showNotifications, forKey: "showNotifications") }
    }

    init() {
        loadFromUserDefaults()
    }

    private func loadFromUserDefaults() {
        let defaults = UserDefaults.standard

        // Load watch paths with corruption recovery
        if let data = defaults.data(forKey: "watchPaths") {
            do {
                let decoded = try JSONDecoder().decode([WatchPath].self, from: data)
                // Validate decoded paths - remove any with empty paths
                watchPaths = decoded.filter { !$0.path.isEmpty }
            } catch {
                // Data is corrupted - log, clear it, and start fresh
                #if DEBUG
                print("Failed to decode watchPaths (data corrupted): \(error)")
                #endif
                defaults.removeObject(forKey: "watchPaths")
                watchPaths = []
            }
        }

        // Load include patterns with validation
        if let patterns = defaults.array(forKey: "includePatterns") as? [String] {
            // Filter out any empty or invalid patterns
            includePatterns = patterns.filter { !$0.isEmpty }
            if includePatterns.isEmpty {
                // Reset to defaults if all patterns were invalid
                includePatterns = [".txt", ".md", ".rtf", ".doc", ".docx"]
            }
        }

        // Load numeric values with bounds checking
        debounceIntervalMs = defaults.integer(forKey: "debounceIntervalMs")
        if debounceIntervalMs < 100 || debounceIntervalMs > 5000 {
            debounceIntervalMs = 500 // Reset to default if out of range
        }

        signingKeyPath = defaults.string(forKey: "signingKeyPath") ?? ""
        // Validate signing key path exists if specified
        if !signingKeyPath.isEmpty && !FileManager.default.fileExists(atPath: signingKeyPath) {
            #if DEBUG
            print("Signing key path no longer exists: \(signingKeyPath)")
            #endif
            // Don't clear it - user might remount drive, etc.
        }

        tpmAttestationEnabled = defaults.bool(forKey: "tpmAttestationEnabled")
        autoCheckpoint = defaults.bool(forKey: "autoCheckpoint")

        checkpointIntervalMinutes = defaults.integer(forKey: "checkpointIntervalMinutes")
        if checkpointIntervalMinutes < 1 || checkpointIntervalMinutes > 1440 {
            checkpointIntervalMinutes = 30 // Reset to default if out of range (1 min to 24 hours)
        }

        // Validate export format
        let format = defaults.string(forKey: "defaultExportFormat") ?? "json"
        defaultExportFormat = ["json", "cbor", "yaml"].contains(format) ? format : "json"

        // Validate export tier
        let tier = defaults.string(forKey: "defaultExportTier") ?? "standard"
        defaultExportTier = ["basic", "standard", "enhanced", "maximum"].contains(tier) ? tier : "standard"

        openAtLogin = defaults.bool(forKey: "openAtLogin")
        showNotifications = defaults.bool(forKey: "showNotifications")
    }

    private func saveWatchPaths() {
        do {
            let data = try JSONEncoder().encode(watchPaths)
            UserDefaults.standard.set(data, forKey: "watchPaths")
        } catch {
            #if DEBUG
            print("Failed to encode watchPaths: \(error)")
            #endif
        }
    }

    func addWatchPath(_ path: String) {
        guard !watchPaths.contains(where: { $0.path == path }) else { return }
        watchPaths.append(WatchPath(path: path))
    }

    func removeWatchPath(_ id: UUID) {
        watchPaths.removeAll { $0.id == id }
    }

    func toggleWatchPath(_ id: UUID) {
        if let index = watchPaths.firstIndex(where: { $0.id == id }) {
            watchPaths[index].isEnabled.toggle()
        }
    }

    func addIncludePattern(_ pattern: String) {
        let normalized = pattern.hasPrefix(".") ? pattern : ".\(pattern)"
        guard !includePatterns.contains(normalized) else { return }
        includePatterns.append(normalized)
    }

    func removeIncludePattern(_ pattern: String) {
        includePatterns.removeAll { $0 == pattern }
    }
}

// MARK: - Error State

/// Structured error information for display in the UI
struct ServiceError: Identifiable {
    let id = UUID()
    let title: String
    let message: String
    let suggestion: String?
    let isRetryable: Bool
    let retryAction: (@Sendable () async -> Void)?
    let timestamp: Date

    init(
        title: String,
        message: String,
        suggestion: String? = nil,
        isRetryable: Bool = false,
        retryAction: (@Sendable () async -> Void)? = nil
    ) {
        self.title = title
        self.message = message
        self.suggestion = suggestion
        self.isRetryable = isRetryable
        self.retryAction = retryAction
        self.timestamp = Date()
    }

    /// Create from a CommandResult
    static func from(result: CommandResult, context: String, retryAction: (@Sendable () async -> Void)? = nil) -> ServiceError {
        let title = "\(context) Failed"
        let message = result.userFriendlyMessage
        let suggestion = result.recoverySuggestion
        let isRetryable = result.isRetryable && retryAction != nil

        return ServiceError(
            title: title,
            message: message,
            suggestion: suggestion,
            isRetryable: isRetryable,
            retryAction: retryAction
        )
    }
}

// MARK: - Main Service

/// Central service managing all Witnessd state and communication
@MainActor
@Observable
final class WitnessdService {
    // MARK: - Singleton
    static let shared = WitnessdService()

    // MARK: - Dependencies
    let bridge: WitnessdBridge
    let settings: WitnessdSettings

    // MARK: - Status State
    var status: WitnessStatus = WitnessStatus()
    var isLoading: Bool = false
    var loadingMessage: String = ""
    var lastError: String? = nil

    // MARK: - Enhanced Error State
    var currentError: ServiceError? = nil
    var errorHistory: [ServiceError] = []
    private let maxErrorHistory = 10

    // MARK: - Session State
    var sessions: [WritingSession] = []
    var currentSession: WritingSession? = nil

    // MARK: - Sentinel State
    var sentinelStatus: SentinelStatus = SentinelStatus()

    // MARK: - CLI Availability
    var isCliAvailable: Bool { bridge.isCliAvailable }
    var cliError: WitnessdError? { bridge.cliAvailabilityError }

    // MARK: - Computed Properties
    var isInitialized: Bool { status.isInitialized }
    var isTracking: Bool { status.isTracking }
    var keystrokeCount: Int { status.keystrokeCount }
    var trackingDuration: String { status.trackingDuration }
    var trackingDocument: String? { status.trackingDocument }
    var vdfCalibrated: Bool { status.vdfCalibrated }
    var tpmAvailable: Bool { status.tpmAvailable }

    // MARK: - Private
    private let logger = Logger(subsystem: "com.witnessd.app", category: "service")
    private var statusTimer: Timer?
    private var keystrokeAnimationValue: Int = 0

    // MARK: - Animation State (for keystroke counter)
    var displayedKeystrokeCount: Int = 0
    var keystrokePulse: Bool = false

    // MARK: - Initialization

    private init() {
        self.bridge = WitnessdBridge()
        self.settings = WitnessdSettings()

        // Start status polling
        startStatusPolling()
    }

    // MARK: - Status Polling

    /// Polling intervals - faster when tracking, slower when idle
    private static let trackingPollInterval: TimeInterval = 5.0
    private static let idlePollInterval: TimeInterval = 15.0

    /// Tracks whether a status update is in progress
    private var isRefreshing = false

    private func startStatusPolling() {
        // Initial fetch
        Task {
            await refreshStatus()
        }

        // Set up timer for regular updates - use idle interval initially
        statusTimer = Timer.scheduledTimer(withTimeInterval: Self.idlePollInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshStatus()
            }
        }
    }

    /// Reschedules status timer with appropriate interval based on tracking state
    private func rescheduleStatusTimer() {
        statusTimer?.invalidate()
        let interval = status.isTracking ? Self.trackingPollInterval : Self.idlePollInterval
        statusTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshStatus()
            }
        }
    }

    func refreshStatus() async {
        // Prevent overlapping refresh calls
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }

        let previousStatus = status
        let newStatus = await bridge.getStatus()

        // Animate keystroke count changes
        let previousCount = status.keystrokeCount
        status = newStatus

        if newStatus.keystrokeCount > previousCount {
            // Trigger pulse animation
            keystrokePulse = true

            // Animate count up
            animateKeystrokeCount(from: previousCount, to: newStatus.keystrokeCount)
        } else {
            displayedKeystrokeCount = newStatus.keystrokeCount
        }

        // Update current session if tracking
        if newStatus.isTracking, let doc = newStatus.trackingDocument {
            if currentSession?.documentPath != doc {
                // New session started
                currentSession = WritingSession(
                    id: UUID().uuidString,
                    documentPath: doc,
                    documentName: URL(fileURLWithPath: doc).lastPathComponent,
                    keystrokeCount: newStatus.keystrokeCount,
                    checkpointCount: 0,
                    startTime: Date(),
                    endTime: nil,
                    duration: 0,
                    verificationStatus: .pending
                )
            } else {
                // Update existing session
                currentSession?.keystrokeCount = newStatus.keystrokeCount
            }
        } else if currentSession != nil && !newStatus.isTracking {
            // Session ended
            currentSession?.endTime = Date()
            if let session = currentSession {
                sessions.insert(session, at: 0)
            }
            currentSession = nil
        }

        // Adjust polling interval if tracking state changed
        if previousStatus.isTracking != newStatus.isTracking {
            rescheduleStatusTimer()
        }

        // Also refresh sentinel status
        sentinelStatus = await bridge.getSentinelStatus()

        // Reset pulse after animation
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            self.keystrokePulse = false
        }
    }

    private func animateKeystrokeCount(from: Int, to: Int) {
        let steps = min(10, to - from)
        let stepDelay = 0.03

        for i in 0..<steps {
            let progress = Double(i + 1) / Double(steps)
            let value = from + Int(Double(to - from) * progress)

            DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * stepDelay) {
                self.displayedKeystrokeCount = value
            }
        }
    }

    // MARK: - Actions

    func initialize() async -> CommandResult {
        setLoading(true, message: "Creating keys...")
        let result = await bridge.initialize()
        setLoading(false)

        if result.success {
            clearError()
            await refreshStatus()
        } else {
            setError(result: result, context: "Initialization") { [weak self] in
                _ = await self?.initialize()
            }
        }

        return result
    }

    func calibrate() async -> CommandResult {
        setLoading(true, message: "Calibrating VDF...")
        let result = await bridge.calibrate()
        setLoading(false)

        if result.success {
            clearError()
            await refreshStatus()
        } else {
            setError(result: result, context: "Calibration") { [weak self] in
                _ = await self?.calibrate()
            }
        }

        return result
    }

    func startTracking(documentPath: String) async -> CommandResult {
        // Validate file exists before attempting
        if !FileManager.default.fileExists(atPath: documentPath) {
            let error = WitnessdError.fileNotFound(path: documentPath)
            let result = CommandResult(
                success: false,
                message: error.localizedDescription,
                exitCode: -1,
                error: error
            )
            setError(result: result, context: "Start Tracking", retryAction: nil)
            return result
        }

        setLoading(true, message: "Starting tracking...")
        let result = await bridge.startTracking(documentPath: documentPath)
        setLoading(false)

        if result.success {
            clearError()
            await refreshStatus()
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: documentPath).lastPathComponent
                NotificationManager.shared.notifyTrackingStarted(document: docName)
            }
        } else {
            setError(result: result, context: "Start Tracking") { [weak self] in
                _ = await self?.startTracking(documentPath: documentPath)
            }
        }

        return result
    }

    func stopTracking() async -> CommandResult {
        setLoading(true, message: "Stopping tracking...")

        // Create final checkpoint if tracking
        if let doc = status.trackingDocument {
            let commitResult = await bridge.commit(filePath: doc, message: "Session ended")
            if !commitResult.success {
                logger.warning("Failed to create final checkpoint: \(commitResult.message)")
                // Continue with stop even if checkpoint fails
            }
        }

        let result = await bridge.stopTracking()
        setLoading(false)

        if result.success {
            clearError()
            if settings.showNotifications {
                NotificationManager.shared.notifyTrackingStopped(
                    keystrokes: status.keystrokeCount,
                    duration: status.trackingDuration
                )
            }
            await refreshStatus()
        } else {
            setError(result: result, context: "Stop Tracking") { [weak self] in
                _ = await self?.stopTracking()
            }
        }

        return result
    }

    func createCheckpoint(message: String = "") async -> CommandResult {
        guard let doc = status.trackingDocument else {
            let error = WitnessdError.noActiveSession
            let result = CommandResult(
                success: false,
                message: error.localizedDescription,
                exitCode: 1,
                error: error
            )
            setError(result: result, context: "Create Checkpoint", retryAction: nil)
            return result
        }

        setLoading(true, message: "Creating checkpoint...")
        let result = await bridge.commit(filePath: doc, message: message)
        setLoading(false)

        if result.success {
            clearError()
            currentSession?.checkpointCount += 1
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: doc).lastPathComponent
                NotificationManager.shared.notifyCheckpointCreated(
                    document: docName,
                    number: currentSession?.checkpointCount ?? 1
                )
            }
        } else {
            setError(result: result, context: "Create Checkpoint") { [weak self] in
                _ = await self?.createCheckpoint(message: message)
            }
        }

        return result
    }

    func export(filePath: String, tier: String, outputPath: String) async -> CommandResult {
        // Validate input file exists
        if !FileManager.default.fileExists(atPath: filePath) {
            let error = WitnessdError.fileNotFound(path: filePath)
            let result = CommandResult(
                success: false,
                message: error.localizedDescription,
                exitCode: -1,
                error: error
            )
            setError(result: result, context: "Export", retryAction: nil)
            return result
        }

        // Validate output directory is writable
        let outputDir = (outputPath as NSString).deletingLastPathComponent
        if !FileManager.default.isWritableFile(atPath: outputDir) {
            let error = WitnessdError.directoryNotWritable(path: outputDir)
            let result = CommandResult(
                success: false,
                message: error.localizedDescription,
                exitCode: -1,
                error: error
            )
            setError(result: result, context: "Export", retryAction: nil)
            return result
        }

        setLoading(true, message: "Exporting evidence...")
        let result = await bridge.export(filePath: filePath, tier: tier, outputPath: outputPath)
        setLoading(false)

        if result.success {
            clearError()
            if settings.showNotifications {
                NotificationManager.shared.notifyEvidenceExported(path: outputPath)
            }
        } else {
            setError(result: result, context: "Export") { [weak self] in
                _ = await self?.export(filePath: filePath, tier: tier, outputPath: outputPath)
            }
        }

        return result
    }

    func verify(filePath: String) async -> CommandResult {
        // Validate file exists
        if !FileManager.default.fileExists(atPath: filePath) {
            let error = WitnessdError.fileNotFound(path: filePath)
            let result = CommandResult(
                success: false,
                message: error.localizedDescription,
                exitCode: -1,
                error: error
            )
            setError(result: result, context: "Verification", retryAction: nil)
            return result
        }

        setLoading(true, message: "Verifying evidence...")
        let result = await bridge.verify(filePath: filePath)
        setLoading(false)

        if result.success {
            clearError()
            // Update verification status for matching session
            if let index = sessions.firstIndex(where: { $0.documentPath == filePath }) {
                sessions[index].verificationStatus = .verified
            }
            if settings.showNotifications {
                let docName = URL(fileURLWithPath: filePath).lastPathComponent
                NotificationManager.shared.notifyVerificationResult(passed: true, document: docName)
            }
        } else {
            if let index = sessions.firstIndex(where: { $0.documentPath == filePath }) {
                sessions[index].verificationStatus = .failed
            }
            setError(result: result, context: "Verification") { [weak self] in
                _ = await self?.verify(filePath: filePath)
            }
        }

        return result
    }

    func log(filePath: String) async -> CommandResult {
        return await bridge.log(filePath: filePath)
    }

    func listTrackedFiles() async -> [TrackedFile] {
        return await bridge.listTrackedFiles()
    }

    // MARK: - Sentinel Management

    func startSentinel() async -> CommandResult {
        setLoading(true, message: "Starting sentinel...")
        let result = await bridge.sentinelStart()
        setLoading(false)

        if result.success {
            clearError()
            await refreshStatus()
        } else {
            // Special handling for accessibility permission error
            if result.error == .accessibilityPermissionRequired {
                setError(
                    title: "Accessibility Permission Required",
                    message: "The sentinel needs accessibility permissions to track document focus.",
                    suggestion: "Go to System Settings > Privacy & Security > Accessibility and add Witnessd.",
                    isRetryable: true
                ) { [weak self] in
                    _ = await self?.startSentinel()
                }
            } else {
                setError(result: result, context: "Start Sentinel") { [weak self] in
                    _ = await self?.startSentinel()
                }
            }
        }

        return result
    }

    func stopSentinel() async -> CommandResult {
        setLoading(true, message: "Stopping sentinel...")
        let result = await bridge.sentinelStop()
        setLoading(false)

        if result.success {
            clearError()
            await refreshStatus()
        } else {
            setError(result: result, context: "Stop Sentinel") { [weak self] in
                _ = await self?.stopSentinel()
            }
        }

        return result
    }

    // MARK: - History Management

    func loadSessions() async {
        let files = await bridge.listTrackedFiles()

        // Convert TrackedFile to WritingSession
        sessions = files.map { file in
            WritingSession(
                id: file.id,
                documentPath: file.path,
                documentName: file.name,
                keystrokeCount: file.events,
                checkpointCount: 0,
                startTime: file.lastModified ?? Date(),
                endTime: file.lastModified,
                duration: 0,
                verificationStatus: .unknown
            )
        }
    }

    func filterSessions(searchText: String) -> [WritingSession] {
        guard !searchText.isEmpty else { return sessions }

        let lowercasedSearch = searchText.lowercased()
        return sessions.filter { session in
            session.documentName.lowercased().contains(lowercasedSearch) ||
            session.documentPath.lowercased().contains(lowercasedSearch)
        }
    }

    // MARK: - Private Helpers

    private func setLoading(_ loading: Bool, message: String = "") {
        isLoading = loading
        loadingMessage = loading ? message : ""
    }

    // MARK: - Error Management

    /// Set error from a CommandResult
    private func setError(result: CommandResult, context: String, retryAction: (@Sendable () async -> Void)?) {
        lastError = result.userFriendlyMessage

        let error = ServiceError.from(
            result: result,
            context: context,
            retryAction: result.isRetryable ? retryAction : nil
        )
        addError(error)
    }

    /// Set a custom error
    private func setError(
        title: String,
        message: String,
        suggestion: String? = nil,
        isRetryable: Bool = false,
        retryAction: (@Sendable () async -> Void)? = nil
    ) {
        lastError = message

        let error = ServiceError(
            title: title,
            message: message,
            suggestion: suggestion,
            isRetryable: isRetryable,
            retryAction: retryAction
        )
        addError(error)
    }

    /// Add error to current and history
    private func addError(_ error: ServiceError) {
        currentError = error

        // Add to history
        errorHistory.insert(error, at: 0)

        // Trim history if needed
        if errorHistory.count > maxErrorHistory {
            errorHistory = Array(errorHistory.prefix(maxErrorHistory))
        }

        logger.error("Error: \(error.title) - \(error.message)")
    }

    /// Clear current error
    func clearError() {
        lastError = nil
        currentError = nil
    }

    /// Dismiss current error (keeps in history)
    func dismissError() {
        currentError = nil
    }

    /// Retry the current error's action if available
    func retryCurrentError() async {
        guard let error = currentError, let retryAction = error.retryAction else { return }
        dismissError()
        await retryAction()
    }

    /// Clear all error history
    func clearErrorHistory() {
        errorHistory.removeAll()
    }
}

// MARK: - Environment Key
// Note: WitnessdService.shared is the canonical way to access the service.
// This environment key is provided for SwiftUI convenience but the singleton
// pattern ensures thread-safe access via @MainActor isolation.

private struct WitnessdServiceKey: EnvironmentKey {
    // Use assumeIsolated to safely access MainActor-isolated singleton
    static var defaultValue: WitnessdService {
        MainActor.assumeIsolated { WitnessdService.shared }
    }
}

extension EnvironmentValues {
    var witnessdService: WitnessdService {
        get { self[WitnessdServiceKey.self] }
        set { self[WitnessdServiceKey.self] = newValue }
    }
}
