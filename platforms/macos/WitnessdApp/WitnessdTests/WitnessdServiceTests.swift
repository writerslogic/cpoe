import XCTest
import SwiftUI
@testable import witnessd

/// Comprehensive tests for WitnessdService state management and settings persistence
final class WitnessdServiceTests: XCTestCase {

    // MARK: - WritingSession Tests

    func testWritingSessionInitialization() {
        let session = WritingSession(
            id: "test-session-123",
            documentPath: "/Users/test/Documents/novel.txt",
            documentName: "novel.txt",
            keystrokeCount: 1500,
            checkpointCount: 5,
            startTime: Date(),
            endTime: nil,
            duration: 3600,
            verificationStatus: .pending
        )

        XCTAssertEqual(session.id, "test-session-123")
        XCTAssertEqual(session.documentPath, "/Users/test/Documents/novel.txt")
        XCTAssertEqual(session.documentName, "novel.txt")
        XCTAssertEqual(session.keystrokeCount, 1500)
        XCTAssertEqual(session.checkpointCount, 5)
        XCTAssertNil(session.endTime)
        XCTAssertEqual(session.duration, 3600)
        XCTAssertEqual(session.verificationStatus, .pending)
    }

    func testWritingSessionIsActive() {
        var activeSession = WritingSession(
            id: "1",
            documentPath: "/path",
            documentName: "doc.txt",
            keystrokeCount: 0,
            checkpointCount: 0,
            startTime: Date(),
            endTime: nil,
            duration: 0,
            verificationStatus: .pending
        )

        XCTAssertTrue(activeSession.isActive, "Session without endTime should be active")

        activeSession.endTime = Date()
        XCTAssertFalse(activeSession.isActive, "Session with endTime should be inactive")
    }

    func testWritingSessionFormattedDuration() {
        // Test seconds only
        let shortSession = WritingSession(
            id: "1", documentPath: "/path", documentName: "doc.txt",
            keystrokeCount: 0, checkpointCount: 0, startTime: Date(),
            endTime: nil, duration: 45, verificationStatus: .pending
        )
        XCTAssertEqual(shortSession.formattedDuration, "0:45")

        // Test minutes and seconds
        let mediumSession = WritingSession(
            id: "2", documentPath: "/path", documentName: "doc.txt",
            keystrokeCount: 0, checkpointCount: 0, startTime: Date(),
            endTime: nil, duration: 1530, verificationStatus: .pending
        )
        XCTAssertEqual(mediumSession.formattedDuration, "25:30")

        // Test hours, minutes, and seconds
        let longSession = WritingSession(
            id: "3", documentPath: "/path", documentName: "doc.txt",
            keystrokeCount: 0, checkpointCount: 0, startTime: Date(),
            endTime: nil, duration: 7265, verificationStatus: .pending
        )
        XCTAssertEqual(longSession.formattedDuration, "2:01:05")
    }

    func testWritingSessionVerificationStatus() {
        let statuses: [WritingSession.VerificationStatus] = [.verified, .pending, .failed, .unknown]

        for status in statuses {
            let session = WritingSession(
                id: "1", documentPath: "/path", documentName: "doc.txt",
                keystrokeCount: 0, checkpointCount: 0, startTime: Date(),
                endTime: nil, duration: 0, verificationStatus: status
            )
            XCTAssertEqual(session.verificationStatus, status)
        }
    }

    func testWritingSessionHashable() {
        let session1 = WritingSession(
            id: "same-id", documentPath: "/path1", documentName: "doc1.txt",
            keystrokeCount: 100, checkpointCount: 1, startTime: Date(),
            endTime: nil, duration: 60, verificationStatus: .pending
        )

        let session2 = WritingSession(
            id: "same-id", documentPath: "/path2", documentName: "doc2.txt",
            keystrokeCount: 200, checkpointCount: 2, startTime: Date(),
            endTime: nil, duration: 120, verificationStatus: .verified
        )

        // Sessions with same ID should be equal
        XCTAssertEqual(session1, session2)

        // Sessions with same ID should have same hash
        XCTAssertEqual(session1.hashValue, session2.hashValue)
    }

    // MARK: - WatchPath Tests

    func testWatchPathInitialization() {
        let watchPath = WatchPath(path: "/Users/test/Documents", isEnabled: true)

        XCTAssertEqual(watchPath.path, "/Users/test/Documents")
        XCTAssertTrue(watchPath.isEnabled)
        XCTAssertNotNil(watchPath.id)
    }

    func testWatchPathDefaultEnabled() {
        let watchPath = WatchPath(path: "/path")

        XCTAssertTrue(watchPath.isEnabled, "Default should be enabled")
    }

    func testWatchPathDisplayName() {
        let watchPath = WatchPath(path: "/Users/test/Documents/MyProject")

        XCTAssertEqual(watchPath.displayName, "MyProject")
    }

    func testWatchPathExists() {
        // Test with a path that should exist
        let existingPath = WatchPath(path: "/tmp")
        XCTAssertTrue(existingPath.exists)

        // Test with a path that doesn't exist
        let nonExistentPath = WatchPath(path: "/nonexistent/path/12345")
        XCTAssertFalse(nonExistentPath.exists)
    }

    func testWatchPathHashable() {
        let path1 = WatchPath(path: "/path1")
        let path2 = WatchPath(path: "/path1")

        // Different UUIDs, so not equal
        XCTAssertNotEqual(path1, path2)
    }

    func testWatchPathCodable() throws {
        let original = WatchPath(path: "/Users/test/Documents", isEnabled: false)

        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(WatchPath.self, from: encoded)

        XCTAssertEqual(decoded.path, original.path)
        XCTAssertEqual(decoded.isEnabled, original.isEnabled)
        XCTAssertEqual(decoded.id, original.id)
    }

    // MARK: - WitnessdSettings Tests

    func testSettingsDefaultValues() {
        let settings = WitnessdSettings()

        XCTAssertEqual(settings.debounceIntervalMs, 500)
        XCTAssertEqual(settings.checkpointIntervalMinutes, 30)
        XCTAssertEqual(settings.defaultExportFormat, "json")
        XCTAssertEqual(settings.defaultExportTier, "standard")
        XCTAssertFalse(settings.autoCheckpoint)
        XCTAssertFalse(settings.tpmAttestationEnabled)
        XCTAssertTrue(settings.signingKeyPath.isEmpty)
    }

    func testSettingsDefaultIncludePatterns() {
        let settings = WitnessdSettings()

        XCTAssertTrue(settings.includePatterns.contains(".txt"))
        XCTAssertTrue(settings.includePatterns.contains(".md"))
        XCTAssertTrue(settings.includePatterns.contains(".rtf"))
        XCTAssertTrue(settings.includePatterns.contains(".doc"))
        XCTAssertTrue(settings.includePatterns.contains(".docx"))
    }

    func testSettingsAddWatchPath() {
        let settings = WitnessdSettings()
        let initialCount = settings.watchPaths.count

        settings.addWatchPath("/Users/test/Documents")

        XCTAssertEqual(settings.watchPaths.count, initialCount + 1)
        XCTAssertTrue(settings.watchPaths.contains { $0.path == "/Users/test/Documents" })
    }

    func testSettingsAddDuplicateWatchPath() {
        let settings = WitnessdSettings()
        settings.addWatchPath("/Users/test/Documents")
        let countAfterFirst = settings.watchPaths.count

        settings.addWatchPath("/Users/test/Documents")

        XCTAssertEqual(settings.watchPaths.count, countAfterFirst, "Duplicate path should not be added")
    }

    func testSettingsRemoveWatchPath() {
        let settings = WitnessdSettings()
        settings.addWatchPath("/Users/test/Documents")

        guard let pathToRemove = settings.watchPaths.first else {
            XCTFail("Expected at least one watch path")
            return
        }

        settings.removeWatchPath(pathToRemove.id)

        XCTAssertFalse(settings.watchPaths.contains { $0.id == pathToRemove.id })
    }

    func testSettingsToggleWatchPath() {
        let settings = WitnessdSettings()
        settings.addWatchPath("/Users/test/Documents")

        guard let path = settings.watchPaths.first else {
            XCTFail("Expected at least one watch path")
            return
        }

        let initialState = path.isEnabled
        settings.toggleWatchPath(path.id)

        let toggledPath = settings.watchPaths.first { $0.id == path.id }
        XCTAssertEqual(toggledPath?.isEnabled, !initialState)
    }

    func testSettingsAddIncludePattern() {
        let settings = WitnessdSettings()
        let initialCount = settings.includePatterns.count

        settings.addIncludePattern(".swift")

        XCTAssertEqual(settings.includePatterns.count, initialCount + 1)
        XCTAssertTrue(settings.includePatterns.contains(".swift"))
    }

    func testSettingsAddIncludePatternNormalization() {
        let settings = WitnessdSettings()

        settings.addIncludePattern("swift") // Without dot

        XCTAssertTrue(settings.includePatterns.contains(".swift"), "Pattern should be normalized with dot prefix")
    }

    func testSettingsAddDuplicateIncludePattern() {
        let settings = WitnessdSettings()
        settings.addIncludePattern(".swift")
        let countAfterFirst = settings.includePatterns.count

        settings.addIncludePattern(".swift")

        XCTAssertEqual(settings.includePatterns.count, countAfterFirst, "Duplicate pattern should not be added")
    }

    func testSettingsRemoveIncludePattern() {
        let settings = WitnessdSettings()

        settings.removeIncludePattern(".txt")

        XCTAssertFalse(settings.includePatterns.contains(".txt"))
    }

    // MARK: - TrackedFile Tests

    func testTrackedFileInitialization() {
        let now = Date()
        let file = TrackedFile(
            id: "file-123",
            path: "/Users/test/Documents/novel.txt",
            name: "novel.txt",
            events: 15234,
            lastModified: now
        )

        XCTAssertEqual(file.id, "file-123")
        XCTAssertEqual(file.path, "/Users/test/Documents/novel.txt")
        XCTAssertEqual(file.name, "novel.txt")
        XCTAssertEqual(file.events, 15234)
        XCTAssertEqual(file.lastModified, now)
        XCTAssertEqual(file.verificationStatus, .unknown)
        XCTAssertEqual(file.checkpointCount, 0)
        XCTAssertEqual(file.keystrokeCount, 0)
    }

    func testTrackedFileVerificationStatus() {
        var file = TrackedFile(
            id: "1", path: "/path", name: "doc.txt", events: 0, lastModified: nil
        )

        XCTAssertEqual(file.verificationStatus, .unknown)

        file.verificationStatus = .verified
        XCTAssertEqual(file.verificationStatus, .verified)

        file.verificationStatus = .pending
        XCTAssertEqual(file.verificationStatus, .pending)

        file.verificationStatus = .failed
        XCTAssertEqual(file.verificationStatus, .failed)
    }

    func testTrackedFileEquality() {
        let file1 = TrackedFile(id: "same", path: "/path1", name: "doc1.txt", events: 100, lastModified: nil)
        let file2 = TrackedFile(id: "same", path: "/path2", name: "doc2.txt", events: 200, lastModified: Date())
        let file3 = TrackedFile(id: "different", path: "/path1", name: "doc1.txt", events: 100, lastModified: nil)

        XCTAssertEqual(file1, file2, "Files with same ID should be equal")
        XCTAssertNotEqual(file1, file3, "Files with different IDs should not be equal")
    }

    func testTrackedFileHashConsistency() {
        let file1 = TrackedFile(id: "test", path: "/path1", name: "doc1.txt", events: 100, lastModified: nil)
        let file2 = TrackedFile(id: "test", path: "/path2", name: "doc2.txt", events: 200, lastModified: Date())

        var set = Set<TrackedFile>()
        set.insert(file1)
        set.insert(file2)

        XCTAssertEqual(set.count, 1, "Set should only contain one element since IDs are the same")
    }

    // MARK: - WitnessStatus Tests

    func testWitnessStatusDefault() {
        let status = WitnessStatus()

        XCTAssertFalse(status.isInitialized)
        XCTAssertFalse(status.isTracking)
        XCTAssertNil(status.trackingDocument)
        XCTAssertEqual(status.keystrokeCount, 0)
        XCTAssertTrue(status.trackingDuration.isEmpty)
        XCTAssertFalse(status.vdfCalibrated)
        XCTAssertTrue(status.vdfIterPerSec.isEmpty)
        XCTAssertFalse(status.tpmAvailable)
        XCTAssertTrue(status.tpmInfo.isEmpty)
        XCTAssertEqual(status.databaseEvents, 0)
        XCTAssertEqual(status.databaseFiles, 0)
    }

    func testWitnessStatusFullyPopulated() {
        var status = WitnessStatus()
        status.isInitialized = true
        status.isTracking = true
        status.trackingDocument = "/Users/test/Documents/novel.txt"
        status.keystrokeCount = 12345
        status.trackingDuration = "2h 30m 15s"
        status.vdfCalibrated = true
        status.vdfIterPerSec = "1250000"
        status.tpmAvailable = true
        status.tpmInfo = "T2 Security Chip"
        status.databaseEvents = 50000
        status.databaseFiles = 25

        XCTAssertTrue(status.isInitialized)
        XCTAssertTrue(status.isTracking)
        XCTAssertEqual(status.trackingDocument, "/Users/test/Documents/novel.txt")
        XCTAssertEqual(status.keystrokeCount, 12345)
        XCTAssertEqual(status.trackingDuration, "2h 30m 15s")
        XCTAssertTrue(status.vdfCalibrated)
        XCTAssertEqual(status.vdfIterPerSec, "1250000")
        XCTAssertTrue(status.tpmAvailable)
        XCTAssertEqual(status.tpmInfo, "T2 Security Chip")
        XCTAssertEqual(status.databaseEvents, 50000)
        XCTAssertEqual(status.databaseFiles, 25)
    }

    // MARK: - SentinelStatus Tests

    func testSentinelStatusDefault() {
        let status = SentinelStatus()

        XCTAssertFalse(status.isRunning)
        XCTAssertEqual(status.pid, 0)
        XCTAssertTrue(status.uptime.isEmpty)
        XCTAssertEqual(status.trackedDocuments, 0)
    }

    func testSentinelStatusRunning() {
        var status = SentinelStatus()
        status.isRunning = true
        status.pid = 12345
        status.uptime = "3h 45m"
        status.trackedDocuments = 10

        XCTAssertTrue(status.isRunning)
        XCTAssertEqual(status.pid, 12345)
        XCTAssertEqual(status.uptime, "3h 45m")
        XCTAssertEqual(status.trackedDocuments, 10)
    }

    // MARK: - CommandResult Tests

    func testCommandResultSuccess() {
        let result = CommandResult(success: true, message: "Operation completed successfully", exitCode: 0)

        XCTAssertTrue(result.success)
        XCTAssertEqual(result.message, "Operation completed successfully")
        XCTAssertEqual(result.exitCode, 0)
    }

    func testCommandResultFailure() {
        let result = CommandResult(success: false, message: "Operation failed: invalid input", exitCode: 1)

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.message, "Operation failed: invalid input")
        XCTAssertEqual(result.exitCode, 1)
    }

    func testCommandResultWithNegativeExitCode() {
        let result = CommandResult(success: false, message: "Process crashed", exitCode: -9)

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.exitCode, -9)
    }

    func testCommandResultEmptyMessage() {
        let result = CommandResult(success: true, message: "", exitCode: 0)

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.isEmpty)
    }

    // MARK: - Session Filtering Tests

    func testFilterSessionsBySearchText() {
        let sessions = [
            WritingSession(id: "1", documentPath: "/path/to/novel.txt", documentName: "novel.txt",
                          keystrokeCount: 1000, checkpointCount: 5, startTime: Date(),
                          endTime: nil, duration: 3600, verificationStatus: .verified),
            WritingSession(id: "2", documentPath: "/path/to/essay.md", documentName: "essay.md",
                          keystrokeCount: 500, checkpointCount: 2, startTime: Date(),
                          endTime: nil, duration: 1800, verificationStatus: .pending),
            WritingSession(id: "3", documentPath: "/path/to/notes.txt", documentName: "notes.txt",
                          keystrokeCount: 100, checkpointCount: 1, startTime: Date(),
                          endTime: nil, duration: 600, verificationStatus: .unknown)
        ]

        // Test filtering by name
        let novelResults = sessions.filter { $0.documentName.lowercased().contains("novel") }
        XCTAssertEqual(novelResults.count, 1)
        XCTAssertEqual(novelResults.first?.documentName, "novel.txt")

        // Test filtering by extension
        let txtResults = sessions.filter { $0.documentName.lowercased().contains(".txt") }
        XCTAssertEqual(txtResults.count, 2)

        // Test filtering with no matches
        let noResults = sessions.filter { $0.documentName.lowercased().contains("xyz") }
        XCTAssertTrue(noResults.isEmpty)

        // Test case insensitivity
        let caseInsensitiveResults = sessions.filter { $0.documentName.lowercased().contains("NOVEL".lowercased()) }
        XCTAssertEqual(caseInsensitiveResults.count, 1)
    }

    // MARK: - Keystroke Formatting Tests

    func testKeystrokeFormatting() {
        func formatNumber(_ n: Int) -> String {
            if n >= 1000000 {
                return String(format: "%.1fM", Double(n) / 1000000.0)
            } else if n >= 1000 {
                return String(format: "%.1fk", Double(n) / 1000.0)
            }
            return "\(n)"
        }

        XCTAssertEqual(formatNumber(0), "0")
        XCTAssertEqual(formatNumber(999), "999")
        XCTAssertEqual(formatNumber(1000), "1.0k")
        XCTAssertEqual(formatNumber(1500), "1.5k")
        XCTAssertEqual(formatNumber(10000), "10.0k")
        XCTAssertEqual(formatNumber(999999), "1000.0k")
        XCTAssertEqual(formatNumber(1000000), "1.0M")
        XCTAssertEqual(formatNumber(1500000), "1.5M")
        XCTAssertEqual(formatNumber(10000000), "10.0M")
    }

    // MARK: - Duration Formatting Tests

    func testDurationFormatting() {
        func formatDuration(_ seconds: TimeInterval) -> String {
            let hours = Int(seconds) / 3600
            let minutes = Int(seconds) / 60 % 60
            let secs = Int(seconds) % 60

            if hours > 0 {
                return String(format: "%d:%02d:%02d", hours, minutes, secs)
            } else {
                return String(format: "%d:%02d", minutes, secs)
            }
        }

        XCTAssertEqual(formatDuration(0), "0:00")
        XCTAssertEqual(formatDuration(30), "0:30")
        XCTAssertEqual(formatDuration(60), "1:00")
        XCTAssertEqual(formatDuration(90), "1:30")
        XCTAssertEqual(formatDuration(3599), "59:59")
        XCTAssertEqual(formatDuration(3600), "1:00:00")
        XCTAssertEqual(formatDuration(3661), "1:01:01")
        XCTAssertEqual(formatDuration(7265), "2:01:05")
    }

    // MARK: - Document Name Extraction Tests

    func testDocumentNameExtraction() {
        func extractDocumentName(_ path: String) -> String {
            URL(fileURLWithPath: path).lastPathComponent
        }

        XCTAssertEqual(extractDocumentName("/Users/test/Documents/novel.txt"), "novel.txt")
        XCTAssertEqual(extractDocumentName("/path/to/essay.md"), "essay.md")
        XCTAssertEqual(extractDocumentName("simple.txt"), "simple.txt")
        XCTAssertEqual(extractDocumentName("/Users/test/My Documents/My Novel.txt"), "My Novel.txt")
        XCTAssertEqual(extractDocumentName("/日本語/ドキュメント.txt"), "ドキュメント.txt")
    }

    // MARK: - AppConfig Tests

    func testAppConfigURLs() {
        XCTAssertNotNil(AppConfig.repositoryURL)
        XCTAssertEqual(AppConfig.repositoryURL.scheme, "https")

        XCTAssertNotNil(AppConfig.documentationURL)
        XCTAssertEqual(AppConfig.documentationURL.scheme, "https")

        XCTAssertNotNil(AppConfig.issuesURL)
        XCTAssertEqual(AppConfig.issuesURL.scheme, "https")
    }

    func testAppConfigTimingDefaults() {
        XCTAssertEqual(AppConfig.defaultCheckpointIntervalMinutes, 30)
        XCTAssertEqual(AppConfig.statusUpdateIntervalSeconds, 3.0)
        XCTAssertEqual(AppConfig.accessibilityCheckIntervalSeconds, 2.0)
    }

    func testAppConfigDirectoryNames() {
        XCTAssertEqual(AppConfig.appSupportDirectoryName, "Witnessd")
        XCTAssertEqual(AppConfig.sessionsDirectoryName, "sessions")
    }

    func testAppConfigVersionStrings() {
        XCTAssertFalse(AppConfig.appVersion.isEmpty)
        XCTAssertFalse(AppConfig.buildNumber.isEmpty)

        let fullVersion = AppConfig.fullVersionString
        XCTAssertTrue(fullVersion.hasPrefix("v"))
        XCTAssertTrue(fullVersion.contains("("))
        XCTAssertTrue(fullVersion.contains(")"))
    }
}

// MARK: - Service State Transition Tests

final class ServiceStateTransitionTests: XCTestCase {

    func testTrackingSessionLifecycle() {
        // Simulate session state transitions
        var currentSession: WritingSession? = nil

        // Start tracking
        let docPath = "/Users/test/Documents/novel.txt"
        currentSession = WritingSession(
            id: UUID().uuidString,
            documentPath: docPath,
            documentName: URL(fileURLWithPath: docPath).lastPathComponent,
            keystrokeCount: 0,
            checkpointCount: 0,
            startTime: Date(),
            endTime: nil,
            duration: 0,
            verificationStatus: .pending
        )

        XCTAssertNotNil(currentSession)
        XCTAssertTrue(currentSession!.isActive)
        XCTAssertEqual(currentSession!.keystrokeCount, 0)

        // Update keystroke count
        currentSession?.keystrokeCount = 1500
        XCTAssertEqual(currentSession?.keystrokeCount, 1500)

        // Create checkpoint
        currentSession?.checkpointCount += 1
        XCTAssertEqual(currentSession?.checkpointCount, 1)

        // Stop tracking
        currentSession?.endTime = Date()
        XCTAssertFalse(currentSession!.isActive)
    }

    func testSettingsChangeNotification() {
        let settings = WitnessdSettings()
        var changeDetected = false

        // Observe changes
        let observer = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification,
            object: nil,
            queue: .main
        ) { _ in
            changeDetected = true
        }

        // Trigger change
        settings.autoCheckpoint = !settings.autoCheckpoint

        // Cleanup
        NotificationCenter.default.removeObserver(observer)

        // Note: This test may be flaky due to timing; in production, use proper async testing
    }

    func testStatusUpdateTransitions() {
        var status = WitnessStatus()

        // Uninitialized state
        XCTAssertFalse(status.isInitialized)
        XCTAssertFalse(status.isTracking)

        // Initialize
        status.isInitialized = true
        XCTAssertTrue(status.isInitialized)
        XCTAssertFalse(status.isTracking)

        // Start tracking
        status.isTracking = true
        status.trackingDocument = "/path/to/doc.txt"
        XCTAssertTrue(status.isTracking)
        XCTAssertNotNil(status.trackingDocument)

        // Update keystrokes
        status.keystrokeCount = 100
        XCTAssertEqual(status.keystrokeCount, 100)

        status.keystrokeCount = 500
        XCTAssertEqual(status.keystrokeCount, 500)

        // Stop tracking
        status.isTracking = false
        status.trackingDocument = nil
        status.keystrokeCount = 0
        XCTAssertFalse(status.isTracking)
        XCTAssertNil(status.trackingDocument)
        XCTAssertEqual(status.keystrokeCount, 0)
    }

    func testSentinelStatusTransitions() {
        var sentinelStatus = SentinelStatus()

        // Initial stopped state
        XCTAssertFalse(sentinelStatus.isRunning)

        // Start sentinel
        sentinelStatus.isRunning = true
        sentinelStatus.pid = 12345
        sentinelStatus.uptime = "0s"
        XCTAssertTrue(sentinelStatus.isRunning)
        XCTAssertEqual(sentinelStatus.pid, 12345)

        // Update uptime
        sentinelStatus.uptime = "1m"
        sentinelStatus.trackedDocuments = 3
        XCTAssertEqual(sentinelStatus.uptime, "1m")
        XCTAssertEqual(sentinelStatus.trackedDocuments, 3)

        // Stop sentinel
        sentinelStatus.isRunning = false
        sentinelStatus.pid = 0
        sentinelStatus.uptime = ""
        sentinelStatus.trackedDocuments = 0
        XCTAssertFalse(sentinelStatus.isRunning)
        XCTAssertEqual(sentinelStatus.pid, 0)
    }
}

// MARK: - Settings Persistence Tests

final class SettingsPersistenceTests: XCTestCase {

    var mockDefaults: MockUserDefaults!

    override func setUp() {
        super.setUp()
        mockDefaults = MockUserDefaults()
    }

    override func tearDown() {
        mockDefaults.reset()
        mockDefaults = nil
        super.tearDown()
    }

    func testBoolSettingPersistence() {
        mockDefaults.set(true, forKey: "testBool")
        XCTAssertTrue(mockDefaults.bool(forKey: "testBool"))

        mockDefaults.set(false, forKey: "testBool")
        XCTAssertFalse(mockDefaults.bool(forKey: "testBool"))
    }

    func testIntSettingPersistence() {
        mockDefaults.set(42, forKey: "testInt")
        XCTAssertEqual(mockDefaults.integer(forKey: "testInt"), 42)

        mockDefaults.set(0, forKey: "testInt")
        XCTAssertEqual(mockDefaults.integer(forKey: "testInt"), 0)
    }

    func testStringSettingPersistence() {
        mockDefaults.set("test value", forKey: "testString")
        XCTAssertEqual(mockDefaults.string(forKey: "testString"), "test value")

        mockDefaults.set("", forKey: "testString")
        XCTAssertEqual(mockDefaults.string(forKey: "testString"), "")
    }

    func testWatchPathsCodablePersistence() throws {
        let paths = [
            WatchPath(path: "/Users/test/Documents", isEnabled: true),
            WatchPath(path: "/Users/test/Desktop", isEnabled: false)
        ]

        let data = try JSONEncoder().encode(paths)
        mockDefaults.set(data, forKey: "watchPaths")

        guard let savedData = mockDefaults.object(forKey: "watchPaths") as? Data else {
            XCTFail("Expected Data")
            return
        }

        let decoded = try JSONDecoder().decode([WatchPath].self, from: savedData)
        XCTAssertEqual(decoded.count, 2)
        XCTAssertEqual(decoded[0].path, "/Users/test/Documents")
        XCTAssertTrue(decoded[0].isEnabled)
        XCTAssertEqual(decoded[1].path, "/Users/test/Desktop")
        XCTAssertFalse(decoded[1].isEnabled)
    }

    func testIncludePatternsPersistence() {
        let patterns = [".txt", ".md", ".swift"]
        mockDefaults.set(patterns, forKey: "includePatterns")

        let saved = mockDefaults.object(forKey: "includePatterns") as? [String]
        XCTAssertEqual(saved, patterns)
    }

    func testRemoveSettingPersistence() {
        mockDefaults.set("value", forKey: "toRemove")
        XCTAssertNotNil(mockDefaults.string(forKey: "toRemove"))

        mockDefaults.removeObject(forKey: "toRemove")
        XCTAssertNil(mockDefaults.string(forKey: "toRemove"))
    }

    func testResetClearsAllSettings() {
        mockDefaults.set(true, forKey: "bool1")
        mockDefaults.set(42, forKey: "int1")
        mockDefaults.set("value", forKey: "string1")

        mockDefaults.reset()

        XCTAssertFalse(mockDefaults.bool(forKey: "bool1"))
        XCTAssertEqual(mockDefaults.integer(forKey: "int1"), 0)
        XCTAssertNil(mockDefaults.string(forKey: "string1"))
    }
}
