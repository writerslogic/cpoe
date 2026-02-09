import Foundation
import os.log

private let logger = Logger(subsystem: "com.witnessd.app", category: "bridge")

// MARK: - Error Types

/// Detailed error types for witnessd operations
enum WitnessdError: Error, LocalizedError, Sendable, Equatable {
    case cliNotFound(path: String)
    case cliNotExecutable(path: String)
    case permissionDenied(path: String)
    case fileNotFound(path: String)
    case fileNotReadable(path: String)
    case directoryNotWritable(path: String)
    case processLaunchFailed(underlyingError: String)
    case processTimeout(seconds: Int)
    case commandFailed(exitCode: Int32, stderr: String)
    case networkUnavailable
    case notInitialized
    case alreadyTracking
    case noActiveSession
    case corruptedData(details: String)
    case accessibilityPermissionRequired
    case unknownError(message: String)

    var errorDescription: String? {
        switch self {
        case .cliNotFound(let path):
            return "Witnessd CLI not found at \(path)"
        case .cliNotExecutable(let path):
            return "Witnessd CLI is not executable at \(path)"
        case .permissionDenied(let path):
            return "Permission denied accessing \(path)"
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .fileNotReadable(let path):
            return "Cannot read file: \(path)"
        case .directoryNotWritable(let path):
            return "Cannot write to directory: \(path)"
        case .processLaunchFailed(let error):
            return "Failed to launch witnessd: \(error)"
        case .processTimeout(let seconds):
            return "Command timed out after \(seconds) seconds"
        case .commandFailed(let exitCode, let stderr):
            return "Command failed (exit code \(exitCode)): \(stderr)"
        case .networkUnavailable:
            return "Network connection unavailable"
        case .notInitialized:
            return "Witnessd has not been initialized"
        case .alreadyTracking:
            return "A tracking session is already active"
        case .noActiveSession:
            return "No active tracking session"
        case .corruptedData(let details):
            return "Data corruption detected: \(details)"
        case .accessibilityPermissionRequired:
            return "Accessibility permission is required"
        case .unknownError(let message):
            return message
        }
    }

    var recoverySuggestion: String? {
        switch self {
        case .cliNotFound:
            return "Try reinstalling the application."
        case .cliNotExecutable:
            return "Try reinstalling the application or check file permissions."
        case .permissionDenied:
            return "Check your file permissions in System Settings > Privacy & Security."
        case .fileNotFound:
            return "Make sure the file exists and hasn't been moved or deleted."
        case .fileNotReadable:
            return "Check that you have permission to read this file."
        case .directoryNotWritable:
            return "Check that you have write permission for this directory."
        case .processLaunchFailed:
            return "Try restarting the application or reinstalling."
        case .processTimeout:
            return "The operation took too long. Try again or check if the system is busy."
        case .commandFailed:
            return "Check the error message for details on what went wrong."
        case .networkUnavailable:
            return "Check your internet connection and try again."
        case .notInitialized:
            return "Click 'Get Started' to initialize Witnessd."
        case .alreadyTracking:
            return "Stop the current tracking session before starting a new one."
        case .noActiveSession:
            return "Start tracking a document first."
        case .corruptedData:
            return "Try reinitializing or contact support if the problem persists."
        case .accessibilityPermissionRequired:
            return "Go to System Settings > Privacy & Security > Accessibility and add Witnessd."
        case .unknownError:
            return "Try again or restart the application."
        }
    }

    var isRetryable: Bool {
        switch self {
        case .processTimeout, .networkUnavailable, .processLaunchFailed:
            return true
        default:
            return false
        }
    }
}

/// Result from a witnessd command
struct CommandResult: Sendable {
    let success: Bool
    let message: String
    let exitCode: Int32
    let error: WitnessdError?

    init(success: Bool, message: String, exitCode: Int32, error: WitnessdError? = nil) {
        self.success = success
        self.message = message
        self.exitCode = exitCode
        self.error = error
    }

    /// User-friendly error message for display
    var userFriendlyMessage: String {
        if success {
            return message
        }

        if let error = error {
            return error.localizedDescription
        }

        // Parse common error patterns from CLI output
        return CommandResult.parseUserFriendlyMessage(from: message, exitCode: exitCode)
    }

    /// Recovery suggestion for the error
    var recoverySuggestion: String? {
        error?.recoverySuggestion
    }

    /// Whether this error can be retried
    var isRetryable: Bool {
        error?.isRetryable ?? false
    }

    /// Parse CLI error messages into user-friendly text
    static func parseUserFriendlyMessage(from message: String, exitCode: Int32) -> String {
        let lowercased = message.lowercased()

        // Check for common error patterns
        if lowercased.contains("permission denied") {
            return "Permission denied. Check your file access permissions."
        }
        if lowercased.contains("no such file") || lowercased.contains("not found") {
            return "The file or resource could not be found."
        }
        if lowercased.contains("not initialized") || lowercased.contains("run init first") {
            return "Witnessd needs to be set up first."
        }
        if lowercased.contains("already tracking") || lowercased.contains("session active") {
            return "A tracking session is already in progress."
        }
        if lowercased.contains("no active") || lowercased.contains("not tracking") {
            return "No document is currently being tracked."
        }
        if lowercased.contains("corrupt") || lowercased.contains("invalid") {
            return "The data appears to be corrupted or invalid."
        }
        if lowercased.contains("timeout") || lowercased.contains("timed out") {
            return "The operation took too long to complete."
        }
        if lowercased.contains("network") || lowercased.contains("connection") {
            return "A network error occurred. Check your connection."
        }
        if lowercased.contains("accessibility") {
            return "Accessibility permission is required for this feature."
        }

        // Return cleaned-up original message if no pattern matched
        if message.isEmpty {
            return "An unknown error occurred (exit code \(exitCode))."
        }

        return message
    }
}

/// Status information from witnessd
struct WitnessStatus: Sendable {
    var isInitialized: Bool = false
    var isTracking: Bool = false
    var trackingDocument: String? = nil
    var keystrokeCount: Int = 0
    var trackingDuration: String = ""
    var vdfCalibrated: Bool = false
    var vdfIterPerSec: String = ""
    var tpmAvailable: Bool = false
    var tpmInfo: String = ""
    var databaseEvents: Int = 0
    var databaseFiles: Int = 0
}

/// Sentinel status information
struct SentinelStatus: Sendable {
    var isRunning: Bool = false
    var pid: Int = 0
    var uptime: String = ""
    var trackedDocuments: Int = 0
}

/// Strip ANSI escape codes from a string (free function for Sendable compatibility)
private func stripANSICodes(_ string: String) -> String {
    let pattern = #"\x1B\[[0-9;]*[a-zA-Z]"#
    return string.replacingOccurrences(of: pattern, with: "", options: .regularExpression)
}

/// Bridge to communicate with the bundled witnessd CLI
/// Note: This class is Sendable because all properties are immutable (let constants)
/// and runCommand creates a new Process each time without shared mutable state.
final class WitnessdBridge: @unchecked Sendable {
    private let witnessdPath: String
    private let dataDirectory: String
    private let commandTimeout: TimeInterval = 30.0 // 30 second default timeout
    private let maxRetries: Int = 3
    private let retryDelay: TimeInterval = 1.0

    // MARK: - Status Caching

    /// Cache for CLI availability check to avoid repeated file system checks
    private var cachedCliAvailable: Bool?
    private var cachedCliError: WitnessdError?
    private var cliCheckTime: Date?
    private let cliCacheTTL: TimeInterval = 60.0 // Cache CLI check for 60 seconds

    /// Whether the CLI binary exists and is executable
    var isCliAvailable: Bool {
        if let cached = cachedCliAvailable,
           let checkTime = cliCheckTime,
           Date().timeIntervalSince(checkTime) < cliCacheTTL {
            return cached
        }

        let fm = FileManager.default
        let available = fm.fileExists(atPath: witnessdPath) && fm.isExecutableFile(atPath: witnessdPath)
        cachedCliAvailable = available
        cliCheckTime = Date()
        return available
    }

    /// Error if CLI is not available
    var cliAvailabilityError: WitnessdError? {
        if let cached = cachedCliError,
           let checkTime = cliCheckTime,
           Date().timeIntervalSince(checkTime) < cliCacheTTL {
            return cached
        }

        let fm = FileManager.default
        var error: WitnessdError? = nil
        if !fm.fileExists(atPath: witnessdPath) {
            error = .cliNotFound(path: witnessdPath)
        } else if !fm.isExecutableFile(atPath: witnessdPath) {
            error = .cliNotExecutable(path: witnessdPath)
        }
        cachedCliError = error
        cliCheckTime = Date()
        return error
    }

    /// Invalidate CLI availability cache (call after install/update operations)
    func invalidateCliCache() {
        cachedCliAvailable = nil
        cachedCliError = nil
        cliCheckTime = nil
    }

    init() {
        // Find witnessd in the app bundle
        if let bundlePath = Bundle.main.path(forResource: "witnessd", ofType: nil) {
            self.witnessdPath = bundlePath
        } else {
            // Fallback: look for witnessd in PATH (for development)
            self.witnessdPath = "/usr/local/bin/witnessd"
        }

        // Determine data directory for sandboxed container
        // In a sandboxed app, Application Support is within the container
        if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            self.dataDirectory = appSupport.appendingPathComponent("Witnessd").path
        } else {
            // Fallback to traditional location
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.dataDirectory = "\(home)/.witnessd"
        }

        // Ensure directory exists
        do {
            try FileManager.default.createDirectory(
                atPath: dataDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            logger.error("Failed to create data directory at \(self.dataDirectory): \(error.localizedDescription)")
        }
    }

    // MARK: - Validation Helpers

    /// Validates that a file exists and is readable
    func validateFileExists(_ path: String) -> WitnessdError? {
        let fm = FileManager.default
        if !fm.fileExists(atPath: path) {
            return .fileNotFound(path: path)
        }
        if !fm.isReadableFile(atPath: path) {
            return .fileNotReadable(path: path)
        }
        return nil
    }

    /// Validates that a directory is writable
    func validateDirectoryWritable(_ path: String) -> WitnessdError? {
        let fm = FileManager.default
        let directory = (path as NSString).deletingLastPathComponent
        if !fm.isWritableFile(atPath: directory) {
            return .directoryNotWritable(path: directory)
        }
        return nil
    }

    /// Returns the data directory path for display in UI
    var dataDirectoryPath: String {
        return dataDirectory
    }

    // MARK: - Commands

    func initialize() async -> CommandResult {
        // Check CLI availability first
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommandWithRetry(["init"])
    }

    func calibrate() async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        // Calibration can take longer, use extended timeout
        return await runCommandWithRetry(["calibrate"], timeout: 120.0)
    }

    func commit(filePath: String, message: String) async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }

        // Validate the file exists
        if let error = validateFileExists(filePath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }

        var args = ["commit", filePath]
        if !message.isEmpty {
            args.append(contentsOf: ["-m", message])
        }
        return await runCommandWithRetry(args)
    }

    func log(filePath: String) async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        if let error = validateFileExists(filePath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommand(["log", filePath])
    }

    func export(filePath: String, tier: String, outputPath: String) async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        if let error = validateFileExists(filePath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        if let error = validateDirectoryWritable(outputPath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommandWithRetry(["export", filePath, "-tier", tier, "-o", outputPath])
    }

    func verify(filePath: String) async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        if let error = validateFileExists(filePath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommand(["verify", filePath])
    }

    func list() async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommand(["list"])
    }

    /// List all tracked files with their event counts
    func listTrackedFiles() async -> [TrackedFile] {
        let result = await list()
        guard result.success else {
            return []
        }

        var files: [TrackedFile] = []
        let lines = result.message.components(separatedBy: "\n")

        // Parse output format: "path/to/file.txt - 123 events - Last modified: 2024-01-15"
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Try to parse the line
            let components = trimmed.components(separatedBy: " - ")
            guard components.count >= 1 else { continue }

            let path = components[0].trimmingCharacters(in: .whitespaces)
            guard !path.isEmpty else { continue }

            var events = 0
            var lastModified: Date? = nil

            // Parse events count
            if components.count >= 2 {
                let eventsStr = components[1]
                    .replacingOccurrences(of: " events", with: "")
                    .trimmingCharacters(in: .whitespaces)
                events = Int(eventsStr) ?? 0
            }

            // Parse last modified date
            if components.count >= 3 {
                let dateStr = components[2]
                    .replacingOccurrences(of: "Last modified: ", with: "")
                    .trimmingCharacters(in: .whitespaces)

                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withFullDate]
                lastModified = formatter.date(from: dateStr)
            }

            let file = TrackedFile(
                id: path,
                path: path,
                name: URL(fileURLWithPath: path).lastPathComponent,
                events: events,
                lastModified: lastModified
            )
            files.append(file)
        }

        return files
    }

    // MARK: - Sentinel Commands

    func sentinelStart() async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        let result = await runCommand(["sentinel", "start"])

        // Check for accessibility permission error
        if !result.success && result.message.lowercased().contains("accessibility") {
            return CommandResult(
                success: false,
                message: result.message,
                exitCode: result.exitCode,
                error: .accessibilityPermissionRequired
            )
        }
        return result
    }

    func sentinelStop() async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        return await runCommand(["sentinel", "stop"])
    }

    func getSentinelStatus() async -> SentinelStatus {
        var status = SentinelStatus()

        let result = await runCommand(["sentinel", "status"])
        if result.success {
            let output = result.message

            // Check if running
            if output.contains("RUNNING") {
                status.isRunning = true

                // Parse PID
                if let match = output.range(of: #"PID (\d+)"#, options: .regularExpression) {
                    let pidStr = output[match].components(separatedBy: " ").last ?? "0"
                    status.pid = Int(pidStr) ?? 0
                }

                // Parse uptime
                if let match = output.range(of: #"Uptime: (.+)"#, options: .regularExpression) {
                    let line = String(output[match])
                    status.uptime = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces) ?? ""
                }
            }
        }

        // Get database stats for tracked documents count
        let statusResult = await runCommand(["status"])
        if statusResult.success {
            if let match = statusResult.message.range(of: #"Files tracked: (\d+)"#, options: .regularExpression) {
                let value = statusResult.message[match].components(separatedBy: ": ").last ?? "0"
                status.trackedDocuments = Int(value) ?? 0
            }
        }

        return status
    }

    func startTracking(documentPath: String) async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        if let error = validateFileExists(documentPath) {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        let result = await runCommand(["track", "start", documentPath])

        // Check for "already tracking" error
        if !result.success && (result.message.lowercased().contains("already") || result.message.lowercased().contains("active")) {
            return CommandResult(
                success: false,
                message: result.message,
                exitCode: result.exitCode,
                error: .alreadyTracking
            )
        }
        return result
    }

    func stopTracking() async -> CommandResult {
        if let error = cliAvailabilityError {
            return CommandResult(success: false, message: error.localizedDescription, exitCode: -1, error: error)
        }
        let result = await runCommand(["track", "stop"])

        // Check for "no active session" error
        if !result.success && (result.message.lowercased().contains("no active") || result.message.lowercased().contains("not tracking")) {
            return CommandResult(
                success: false,
                message: result.message,
                exitCode: result.exitCode,
                error: .noActiveSession
            )
        }
        return result
    }

    func getStatus() async -> WitnessStatus {
        var status = WitnessStatus()

        // Check if initialized by running status command
        let result = await runCommand(["status"])

        if result.success {
            let output = result.message

            // Parse the output to extract status information
            status.isInitialized = output.contains("Data directory:")

            // Check VDF calibration
            if let match = output.range(of: #"VDF iterations/sec: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? ""
                status.vdfIterPerSec = value
                status.vdfCalibrated = true
            }

            // Check TPM
            if output.contains("TPM: available") {
                status.tpmAvailable = true
                if let match = output.range(of: #"TPM: available \(([^)]+)\)"#, options: .regularExpression) {
                    status.tpmInfo = String(output[match])
                        .replacingOccurrences(of: "TPM: available (", with: "")
                        .replacingOccurrences(of: ")", with: "")
                }
            }

            // Check database stats
            if let match = output.range(of: #"Events: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? "0"
                status.databaseEvents = Int(value) ?? 0
            }

            if let match = output.range(of: #"Files tracked: (\d+)"#, options: .regularExpression) {
                let value = output[match].components(separatedBy: ": ").last ?? "0"
                status.databaseFiles = Int(value) ?? 0
            }
        }

        // Check tracking status separately
        let trackResult = await runCommand(["track", "status"])
        if trackResult.success && trackResult.message.contains("Active Tracking Session") {
            status.isTracking = true

            // Parse tracking info
            if let match = trackResult.message.range(of: #"Document: (.+)"#, options: .regularExpression) {
                let line = String(trackResult.message[match])
                status.trackingDocument = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces)
            }

            if let match = trackResult.message.range(of: #"Keystrokes: (\d+)"#, options: .regularExpression) {
                let value = trackResult.message[match].components(separatedBy: ": ").last ?? "0"
                status.keystrokeCount = Int(value) ?? 0
            }

            if let match = trackResult.message.range(of: #"Duration: (.+)"#, options: .regularExpression) {
                let line = String(trackResult.message[match])
                status.trackingDuration = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces) ?? ""
            }
        }

        return status
    }

    // MARK: - Private

    /// Run a command with retry logic for transient failures
    private func runCommandWithRetry(_ arguments: [String], timeout: TimeInterval? = nil, retries: Int? = nil) async -> CommandResult {
        let maxAttempts = retries ?? maxRetries
        var lastResult: CommandResult?

        for attempt in 1...maxAttempts {
            let result = await runCommand(arguments, timeout: timeout)

            // Success - return immediately
            if result.success {
                return result
            }

            // Check if error is retryable
            if let error = result.error, !error.isRetryable {
                return result
            }

            // Check for non-retryable conditions based on exit code/message
            let message = result.message.lowercased()
            if message.contains("permission denied") ||
               message.contains("not found") ||
               message.contains("not initialized") ||
               message.contains("already tracking") ||
               message.contains("no active") {
                return result
            }

            lastResult = result

            // Don't sleep after the last attempt
            if attempt < maxAttempts {
                logger.info("Command failed (attempt \(attempt)/\(maxAttempts)), retrying in \(self.retryDelay)s...")
                try? await Task.sleep(nanoseconds: UInt64(retryDelay * 1_000_000_000))
            }
        }

        logger.error("Command failed after \(maxAttempts) attempts")
        return lastResult ?? CommandResult(
            success: false,
            message: "Command failed after \(maxAttempts) attempts",
            exitCode: -1,
            error: .unknownError(message: "Maximum retry attempts exceeded")
        )
    }

    private func runCommand(_ arguments: [String], timeout: TimeInterval? = nil) async -> CommandResult {
        let path = self.witnessdPath
        let dataDir = self.dataDirectory
        let timeoutSeconds = timeout ?? commandTimeout

        return await Task.detached {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments

            // Set environment variable for sandboxed data directory
            var environment = ProcessInfo.processInfo.environment
            environment["WITNESSD_DATA_DIR"] = dataDir
            process.environment = environment

            // Capture output
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            // Hide from user - no terminal window
            process.standardInput = FileHandle.nullDevice

            do {
                try process.run()

                // Wait with timeout
                let didComplete = self.waitForProcess(process, timeout: timeoutSeconds)

                if !didComplete {
                    process.terminate()
                    return CommandResult(
                        success: false,
                        message: "Command timed out after \(Int(timeoutSeconds)) seconds",
                        exitCode: -1,
                        error: .processTimeout(seconds: Int(timeoutSeconds))
                    )
                }

                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()

                let output = String(data: outputData, encoding: .utf8) ?? ""
                let errorOutput = String(data: errorData, encoding: .utf8) ?? ""

                let exitCode = process.terminationStatus
                let success = exitCode == 0

                // Combine output, strip ANSI codes for cleaner display
                var message = output
                if !success && !errorOutput.isEmpty {
                    message = errorOutput
                }
                message = stripANSICodes(message)
                message = message.trimmingCharacters(in: .whitespacesAndNewlines)

                // Create appropriate error for failed commands
                var error: WitnessdError? = nil
                if !success {
                    error = self.categorizeError(message: message, exitCode: exitCode)
                }

                return CommandResult(
                    success: success,
                    message: message,
                    exitCode: exitCode,
                    error: error
                )
            } catch let launchError as NSError {
                // Handle specific launch errors
                let error: WitnessdError
                if launchError.domain == NSCocoaErrorDomain {
                    switch launchError.code {
                    case NSFileNoSuchFileError, NSFileReadNoSuchFileError:
                        error = .cliNotFound(path: path)
                    case NSFileReadNoPermissionError:
                        error = .cliNotExecutable(path: path)
                    default:
                        error = .processLaunchFailed(underlyingError: launchError.localizedDescription)
                    }
                } else {
                    error = .processLaunchFailed(underlyingError: launchError.localizedDescription)
                }

                return CommandResult(
                    success: false,
                    message: error.localizedDescription,
                    exitCode: -1,
                    error: error
                )
            } catch {
                let witnessdError = WitnessdError.processLaunchFailed(underlyingError: error.localizedDescription)
                return CommandResult(
                    success: false,
                    message: "Failed to run witnessd: \(error.localizedDescription)",
                    exitCode: -1,
                    error: witnessdError
                )
            }
        }.value
    }

    /// Wait for process with timeout
    private func waitForProcess(_ process: Process, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)

        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }

        return !process.isRunning
    }

    /// Categorize an error based on the message content
    private func categorizeError(message: String, exitCode: Int32) -> WitnessdError {
        let lowercased = message.lowercased()

        if lowercased.contains("permission denied") {
            return .permissionDenied(path: "")
        }
        if lowercased.contains("no such file") || lowercased.contains("not found") {
            return .fileNotFound(path: "")
        }
        if lowercased.contains("not initialized") || lowercased.contains("run init first") {
            return .notInitialized
        }
        if lowercased.contains("already tracking") || lowercased.contains("session active") {
            return .alreadyTracking
        }
        if lowercased.contains("no active") || lowercased.contains("not tracking") {
            return .noActiveSession
        }
        if lowercased.contains("corrupt") || lowercased.contains("invalid data") {
            return .corruptedData(details: message)
        }
        if lowercased.contains("accessibility") {
            return .accessibilityPermissionRequired
        }
        if lowercased.contains("network") || lowercased.contains("connection") {
            return .networkUnavailable
        }

        return .commandFailed(exitCode: exitCode, stderr: message)
    }
}
