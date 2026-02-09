import XCTest
@testable import witnessd

/// Comprehensive unit tests for WitnessdBridge command execution and output parsing
final class WitnessdBridgeTests: XCTestCase {

    var mockBridge: MockWitnessdBridge!

    @MainActor
    override func setUp() {
        super.setUp()
        mockBridge = MockWitnessdBridge()
    }

    @MainActor
    override func tearDown() {
        mockBridge.reset()
        mockBridge = nil
        super.tearDown()
    }

    // MARK: - Initialize Command Tests

    @MainActor
    func testInitializeCommandSuccess() async {
        mockBridge.initializeResult = CommandResult(
            success: true,
            message: "Initialized witnessd data directory at /Users/test/.witnessd\nGenerated signing key pair",
            exitCode: 0
        )

        let result = await mockBridge.initialize()

        XCTAssertTrue(mockBridge.initializeCalled, "Initialize should be called")
        XCTAssertTrue(result.success, "Initialization should succeed")
        XCTAssertEqual(result.exitCode, 0, "Exit code should be 0 for success")
        XCTAssertTrue(result.message.contains("Initialized"), "Message should indicate initialization")
    }

    @MainActor
    func testInitializeCommandAlreadyInitialized() async {
        mockBridge.initializeResult = CommandResult(
            success: false,
            message: "Data directory already exists. Use --force to reinitialize.",
            exitCode: 1
        )

        let result = await mockBridge.initialize()

        XCTAssertTrue(mockBridge.initializeCalled)
        XCTAssertFalse(result.success)
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertTrue(result.message.contains("already exists"))
    }

    @MainActor
    func testInitializeCommandPermissionDenied() async {
        mockBridge.initializeResult = CommandResult(
            success: false,
            message: "Permission denied: cannot create directory",
            exitCode: 1
        )

        let result = await mockBridge.initialize()

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.lowercased().contains("permission"))
    }

    // MARK: - Calibrate Command Tests

    @MainActor
    func testCalibrateCommandSuccess() async {
        mockBridge.calibrateResult = CommandResult(
            success: true,
            message: "VDF calibration complete\nIterations per second: 1250000\nCalibration saved to configuration",
            exitCode: 0
        )

        let result = await mockBridge.calibrate()

        XCTAssertTrue(mockBridge.calibrateCalled, "Calibrate should be called")
        XCTAssertTrue(result.success, "Calibration should succeed")
        XCTAssertTrue(result.message.contains("1250000"), "Message should contain iterations count")
    }

    @MainActor
    func testCalibrateCommandNotInitialized() async {
        mockBridge.calibrateResult = CommandResult(
            success: false,
            message: "Witnessd not initialized. Run 'witnessd init' first.",
            exitCode: 1
        )

        let result = await mockBridge.calibrate()

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("not initialized"))
    }

    @MainActor
    func testCalibrateCommandTimeout() async {
        mockBridge.calibrateResult = CommandResult(
            success: false,
            message: "Calibration timed out after 30 seconds",
            exitCode: 1
        )

        let result = await mockBridge.calibrate()

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.lowercased().contains("timeout"))
    }

    // MARK: - Start Tracking Tests

    @MainActor
    func testStartTrackingSuccess() async {
        let documentPath = "/Users/test/Documents/novel.txt"
        mockBridge.startTrackingResult = CommandResult(
            success: true,
            message: "Tracking started for: novel.txt\nSession ID: abc123",
            exitCode: 0
        )

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertTrue(mockBridge.startTrackingCalled)
        XCTAssertEqual(mockBridge.startTrackingPath, documentPath)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("Tracking started"))
    }

    @MainActor
    func testStartTrackingFileNotFound() async {
        let documentPath = "/nonexistent/path/document.txt"
        mockBridge.startTrackingResult = CommandResult(
            success: false,
            message: "File not found: /nonexistent/path/document.txt",
            exitCode: 1
        )

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("not found"))
    }

    @MainActor
    func testStartTrackingAlreadyTracking() async {
        mockBridge.startTrackingResult = CommandResult(
            success: false,
            message: "Already tracking a session. Stop current session first.",
            exitCode: 1
        )

        let result = await mockBridge.startTracking(documentPath: "/any/path.txt")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("Already tracking"))
    }

    @MainActor
    func testStartTrackingWithSpacesInPath() async {
        let documentPath = "/Users/test/My Documents/My Novel.txt"
        mockBridge.startTrackingResult = CommandResult(success: true, message: "Tracking started", exitCode: 0)

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertEqual(mockBridge.startTrackingPath, documentPath)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testStartTrackingWithUnicodePath() async {
        let documentPath = "/Users/test/Documents/日本語/ドキュメント.txt"
        mockBridge.startTrackingResult = CommandResult(success: true, message: "Tracking started", exitCode: 0)

        let result = await mockBridge.startTracking(documentPath: documentPath)

        XCTAssertEqual(mockBridge.startTrackingPath, documentPath)
        XCTAssertTrue(result.success)
    }

    // MARK: - Stop Tracking Tests

    @MainActor
    func testStopTrackingSuccess() async {
        mockBridge.stopTrackingResult = CommandResult(
            success: true,
            message: "Tracking stopped\nSession duration: 1h 45m 30s\nKeystrokes recorded: 15234\nFinal checkpoint created",
            exitCode: 0
        )

        let result = await mockBridge.stopTracking()

        XCTAssertTrue(mockBridge.stopTrackingCalled)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("stopped"))
        XCTAssertTrue(result.message.contains("15234"))
    }

    @MainActor
    func testStopTrackingNoActiveSession() async {
        mockBridge.stopTrackingResult = CommandResult(
            success: false,
            message: "No active tracking session",
            exitCode: 1
        )

        let result = await mockBridge.stopTracking()

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("No active"))
    }

    // MARK: - Commit Command Tests

    @MainActor
    func testCommitWithMessage() async {
        let filePath = "/Users/test/Documents/chapter1.txt"
        let message = "Completed first draft of Chapter 1"
        mockBridge.commitResult = CommandResult(
            success: true,
            message: "Checkpoint created\nHash: abc123def456\nTimestamp: 2024-01-15T10:30:00Z",
            exitCode: 0
        )

        let result = await mockBridge.commit(filePath: filePath, message: message)

        XCTAssertTrue(mockBridge.commitCalled)
        XCTAssertEqual(mockBridge.commitPath, filePath)
        XCTAssertEqual(mockBridge.commitMessage, message)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("Checkpoint created"))
    }

    @MainActor
    func testCommitWithEmptyMessage() async {
        let filePath = "/Users/test/Documents/document.txt"
        mockBridge.commitResult = CommandResult(
            success: true,
            message: "Checkpoint created",
            exitCode: 0
        )

        let result = await mockBridge.commit(filePath: filePath, message: "")

        XCTAssertTrue(mockBridge.commitCalled)
        XCTAssertEqual(mockBridge.commitMessage, "")
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testCommitWithSpecialCharactersInMessage() async {
        let message = "Chapter \"1\" complete! 100% done & ready for review 🎉"
        mockBridge.commitResult = CommandResult(success: true, message: "Checkpoint created", exitCode: 0)

        let result = await mockBridge.commit(filePath: "/doc.txt", message: message)

        XCTAssertEqual(mockBridge.commitMessage, message)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testCommitNoChanges() async {
        mockBridge.commitResult = CommandResult(
            success: false,
            message: "No changes since last checkpoint",
            exitCode: 1
        )

        let result = await mockBridge.commit(filePath: "/doc.txt", message: "Test")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("No changes"))
    }

    @MainActor
    func testCommitFileNotTracked() async {
        mockBridge.commitResult = CommandResult(
            success: false,
            message: "File is not being tracked. Start tracking first.",
            exitCode: 1
        )

        let result = await mockBridge.commit(filePath: "/untracked.txt", message: "Test")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("not being tracked"))
    }

    // MARK: - Export Command Tests

    @MainActor
    func testExportBasicTier() async {
        let filePath = "/Users/test/Documents/novel.txt"
        let outputPath = "/Users/test/Documents/novel.evidence.json"
        mockBridge.exportResult = CommandResult(
            success: true,
            message: "Evidence exported to: novel.evidence.json\nTier: basic\nCheckpoints: 15",
            exitCode: 0
        )

        let result = await mockBridge.export(filePath: filePath, tier: "basic", outputPath: outputPath)

        XCTAssertTrue(mockBridge.exportCalled)
        XCTAssertEqual(mockBridge.exportPath, filePath)
        XCTAssertEqual(mockBridge.exportTier, "basic")
        XCTAssertEqual(mockBridge.exportOutputPath, outputPath)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testExportStandardTier() async {
        mockBridge.exportResult = CommandResult(
            success: true,
            message: "Evidence exported with keystroke data",
            exitCode: 0
        )

        let result = await mockBridge.export(filePath: "/doc.txt", tier: "standard", outputPath: "/out.json")

        XCTAssertEqual(mockBridge.exportTier, "standard")
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testExportEnhancedTier() async {
        mockBridge.exportResult = CommandResult(
            success: true,
            message: "Evidence exported with TPM attestation",
            exitCode: 0
        )

        let result = await mockBridge.export(filePath: "/doc.txt", tier: "enhanced", outputPath: "/out.json")

        XCTAssertEqual(mockBridge.exportTier, "enhanced")
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testExportMaximumTier() async {
        mockBridge.exportResult = CommandResult(
            success: true,
            message: "Evidence exported with all available data",
            exitCode: 0
        )

        let result = await mockBridge.export(filePath: "/doc.txt", tier: "maximum", outputPath: "/out.json")

        XCTAssertEqual(mockBridge.exportTier, "maximum")
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testExportNoEvidence() async {
        mockBridge.exportResult = CommandResult(
            success: false,
            message: "No evidence found for this file. Track and create checkpoints first.",
            exitCode: 1
        )

        let result = await mockBridge.export(filePath: "/untracked.txt", tier: "standard", outputPath: "/out.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("No evidence"))
    }

    @MainActor
    func testExportInvalidOutputPath() async {
        mockBridge.exportResult = CommandResult(
            success: false,
            message: "Cannot write to output path: permission denied",
            exitCode: 1
        )

        let result = await mockBridge.export(filePath: "/doc.txt", tier: "basic", outputPath: "/root/out.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.lowercased().contains("permission"))
    }

    // MARK: - Verify Command Tests

    @MainActor
    func testVerifySuccess() async {
        let filePath = "/Users/test/Documents/novel.evidence.json"
        mockBridge.verifyResult = CommandResult(
            success: true,
            message: """
            Verification Report
            ==================
            All signatures valid: YES
            VDF proofs valid: YES
            Chain integrity: VALID
            Checkpoints verified: 15/15
            """,
            exitCode: 0
        )

        let result = await mockBridge.verify(filePath: filePath)

        XCTAssertTrue(mockBridge.verifyCalled)
        XCTAssertEqual(mockBridge.verifyPath, filePath)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("VALID"))
    }

    @MainActor
    func testVerifyInvalidSignature() async {
        mockBridge.verifyResult = CommandResult(
            success: false,
            message: "Verification failed: Invalid signature at checkpoint 7",
            exitCode: 1
        )

        let result = await mockBridge.verify(filePath: "/tampered.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("Invalid signature"))
    }

    @MainActor
    func testVerifyBrokenChain() async {
        mockBridge.verifyResult = CommandResult(
            success: false,
            message: "Verification failed: Chain integrity compromised - hash mismatch at checkpoint 3",
            exitCode: 1
        )

        let result = await mockBridge.verify(filePath: "/broken.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("Chain integrity"))
    }

    @MainActor
    func testVerifyInvalidVDFProof() async {
        mockBridge.verifyResult = CommandResult(
            success: false,
            message: "Verification failed: VDF proof invalid - time interval impossible",
            exitCode: 1
        )

        let result = await mockBridge.verify(filePath: "/invalid-vdf.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("VDF"))
    }

    @MainActor
    func testVerifyCorruptedFile() async {
        mockBridge.verifyResult = CommandResult(
            success: false,
            message: "Failed to parse evidence file: invalid JSON",
            exitCode: 1
        )

        let result = await mockBridge.verify(filePath: "/corrupted.json")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.contains("invalid JSON") || result.message.contains("parse"))
    }

    // MARK: - Log Command Tests

    @MainActor
    func testLogSuccess() async {
        let filePath = "/Users/test/Documents/novel.txt"
        mockBridge.logResult = CommandResult(
            success: true,
            message: """
            Event Log for: novel.txt
            =========================
            2024-01-15 10:00:00 - Session started
            2024-01-15 10:30:00 - Checkpoint: "Chapter 1 start"
            2024-01-15 11:45:00 - Checkpoint: "Chapter 1 complete"
            2024-01-15 11:45:30 - Session ended (keystrokes: 4523)
            """,
            exitCode: 0
        )

        let result = await mockBridge.log(filePath: filePath)

        XCTAssertTrue(mockBridge.logCalled)
        XCTAssertEqual(mockBridge.logPath, filePath)
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("Event Log"))
    }

    @MainActor
    func testLogEmptyHistory() async {
        mockBridge.logResult = CommandResult(
            success: true,
            message: "No events recorded for this file",
            exitCode: 0
        )

        let result = await mockBridge.log(filePath: "/empty.txt")

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("No events"))
    }

    @MainActor
    func testLogFileNotTracked() async {
        mockBridge.logResult = CommandResult(
            success: false,
            message: "File not found in tracking database",
            exitCode: 1
        )

        let result = await mockBridge.log(filePath: "/untracked.txt")

        XCTAssertFalse(result.success)
    }

    // MARK: - List Command Tests

    @MainActor
    func testListSuccess() async {
        mockBridge.listResult = CommandResult(
            success: true,
            message: """
            Tracked Documents:
            - /Users/test/Documents/novel.txt (15234 events, last: 2024-01-15)
            - /Users/test/Documents/essay.md (3421 events, last: 2024-01-14)
            - /Users/test/Documents/notes.txt (892 events, last: 2024-01-10)
            """,
            exitCode: 0
        )

        let result = await mockBridge.list()

        XCTAssertTrue(mockBridge.listCalled)
        XCTAssertTrue(result.success)
    }

    @MainActor
    func testListEmpty() async {
        mockBridge.listResult = CommandResult(
            success: true,
            message: "No documents currently tracked",
            exitCode: 0
        )

        let result = await mockBridge.list()

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.message.contains("No documents"))
    }

    @MainActor
    func testListTrackedFilesParsingSuccess() async {
        mockBridge.listResult = CommandResult(
            success: true,
            message: "/Users/test/novel.txt\n/Users/test/essay.md\n/Users/test/notes.txt",
            exitCode: 0
        )

        let files = await mockBridge.listTrackedFiles()

        XCTAssertEqual(files.count, 3)
        XCTAssertEqual(files[0].path, "/Users/test/novel.txt")
        XCTAssertEqual(files[0].name, "novel.txt")
        XCTAssertEqual(files[1].path, "/Users/test/essay.md")
        XCTAssertEqual(files[2].path, "/Users/test/notes.txt")
    }

    @MainActor
    func testListTrackedFilesParsingEmpty() async {
        mockBridge.listResult = CommandResult(success: true, message: "", exitCode: 0)

        let files = await mockBridge.listTrackedFiles()

        XCTAssertEqual(files.count, 0)
    }

    @MainActor
    func testListTrackedFilesWithWhitespace() async {
        mockBridge.listResult = CommandResult(
            success: true,
            message: "  /path/to/file1.txt  \n\n/path/to/file2.txt\n  ",
            exitCode: 0
        )

        let files = await mockBridge.listTrackedFiles()

        XCTAssertEqual(files.count, 2)
    }

    // MARK: - Status Parsing Tests

    @MainActor
    func testGetStatusInitialized() async {
        var status = WitnessStatus()
        status.isInitialized = true
        status.vdfCalibrated = true
        status.vdfIterPerSec = "1250000"
        status.tpmAvailable = true
        status.tpmInfo = "T2 Security Chip"
        status.databaseEvents = 50000
        status.databaseFiles = 15
        mockBridge.mockStatus = status

        let result = await mockBridge.getStatus()

        XCTAssertTrue(result.isInitialized)
        XCTAssertTrue(result.vdfCalibrated)
        XCTAssertEqual(result.vdfIterPerSec, "1250000")
        XCTAssertTrue(result.tpmAvailable)
        XCTAssertEqual(result.tpmInfo, "T2 Security Chip")
        XCTAssertEqual(result.databaseEvents, 50000)
        XCTAssertEqual(result.databaseFiles, 15)
    }

    @MainActor
    func testGetStatusTracking() async {
        var status = WitnessStatus()
        status.isInitialized = true
        status.isTracking = true
        status.trackingDocument = "/Users/test/Documents/current.txt"
        status.keystrokeCount = 7523
        status.trackingDuration = "2h 15m 30s"
        mockBridge.mockStatus = status

        let result = await mockBridge.getStatus()

        XCTAssertTrue(result.isTracking)
        XCTAssertEqual(result.trackingDocument, "/Users/test/Documents/current.txt")
        XCTAssertEqual(result.keystrokeCount, 7523)
        XCTAssertEqual(result.trackingDuration, "2h 15m 30s")
    }

    @MainActor
    func testGetStatusUninitialized() async {
        mockBridge.mockStatus = WitnessStatus()

        let result = await mockBridge.getStatus()

        XCTAssertFalse(result.isInitialized)
        XCTAssertFalse(result.isTracking)
        XCTAssertNil(result.trackingDocument)
        XCTAssertEqual(result.keystrokeCount, 0)
        XCTAssertFalse(result.vdfCalibrated)
        XCTAssertFalse(result.tpmAvailable)
    }

    // MARK: - Sentinel Status Tests

    @MainActor
    func testSentinelStatusRunning() async {
        var sentinelStatus = SentinelStatus()
        sentinelStatus.isRunning = true
        sentinelStatus.pid = 12345
        sentinelStatus.uptime = "3h 45m"
        sentinelStatus.trackedDocuments = 5
        mockBridge.mockSentinelStatus = sentinelStatus

        let result = await mockBridge.getSentinelStatus()

        XCTAssertTrue(result.isRunning)
        XCTAssertEqual(result.pid, 12345)
        XCTAssertEqual(result.uptime, "3h 45m")
        XCTAssertEqual(result.trackedDocuments, 5)
    }

    @MainActor
    func testSentinelStatusStopped() async {
        mockBridge.mockSentinelStatus = SentinelStatus()

        let result = await mockBridge.getSentinelStatus()

        XCTAssertFalse(result.isRunning)
        XCTAssertEqual(result.pid, 0)
        XCTAssertTrue(result.uptime.isEmpty)
    }

    // MARK: - Error Handling Tests

    @MainActor
    func testHandleProcessNotFound() async {
        mockBridge.initializeResult = CommandResult(
            success: false,
            message: "Failed to run witnessd: The operation couldn't be completed. No such file or directory",
            exitCode: -1
        )

        let result = await mockBridge.initialize()

        XCTAssertFalse(result.success)
        XCTAssertEqual(result.exitCode, -1)
    }

    @MainActor
    func testHandleProcessCrash() async {
        mockBridge.calibrateResult = CommandResult(
            success: false,
            message: "Process terminated unexpectedly",
            exitCode: -9
        )

        let result = await mockBridge.calibrate()

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.exitCode < 0)
    }

    @MainActor
    func testHandleAccessibilityPermissionDenied() async {
        mockBridge.startTrackingResult = CommandResult(
            success: false,
            message: "Accessibility permission denied. Please grant permission in System Settings.",
            exitCode: 1
        )

        let result = await mockBridge.startTracking(documentPath: "/test.txt")

        XCTAssertFalse(result.success)
        XCTAssertTrue(result.message.lowercased().contains("accessibility") || result.message.lowercased().contains("permission"))
    }

    // MARK: - Data Directory Tests

    @MainActor
    func testDataDirectoryPath() {
        XCTAssertEqual(mockBridge.dataDirectoryPath, "/tmp/witnessd-test")
    }

    // MARK: - Reset Tests

    @MainActor
    func testResetClearsAllState() async {
        // Perform various operations
        _ = await mockBridge.initialize()
        _ = await mockBridge.calibrate()
        _ = await mockBridge.startTracking(documentPath: "/test.txt")
        _ = await mockBridge.commit(filePath: "/test.txt", message: "Test")
        _ = await mockBridge.export(filePath: "/test.txt", tier: "basic", outputPath: "/out.json")
        _ = await mockBridge.verify(filePath: "/out.json")
        _ = await mockBridge.log(filePath: "/test.txt")
        _ = await mockBridge.list()

        XCTAssertTrue(mockBridge.initializeCalled)
        XCTAssertTrue(mockBridge.calibrateCalled)
        XCTAssertTrue(mockBridge.startTrackingCalled)
        XCTAssertTrue(mockBridge.commitCalled)
        XCTAssertTrue(mockBridge.exportCalled)
        XCTAssertTrue(mockBridge.verifyCalled)
        XCTAssertTrue(mockBridge.logCalled)
        XCTAssertTrue(mockBridge.listCalled)

        mockBridge.reset()

        XCTAssertFalse(mockBridge.initializeCalled)
        XCTAssertFalse(mockBridge.calibrateCalled)
        XCTAssertFalse(mockBridge.startTrackingCalled)
        XCTAssertFalse(mockBridge.commitCalled)
        XCTAssertFalse(mockBridge.exportCalled)
        XCTAssertFalse(mockBridge.verifyCalled)
        XCTAssertFalse(mockBridge.logCalled)
        XCTAssertFalse(mockBridge.listCalled)
        XCTAssertNil(mockBridge.startTrackingPath)
        XCTAssertNil(mockBridge.commitPath)
        XCTAssertNil(mockBridge.commitMessage)
        XCTAssertNil(mockBridge.exportPath)
        XCTAssertNil(mockBridge.exportTier)
        XCTAssertNil(mockBridge.exportOutputPath)
        XCTAssertNil(mockBridge.verifyPath)
        XCTAssertNil(mockBridge.logPath)
    }

    // MARK: - Concurrent Access Tests

    @MainActor
    func testConcurrentStatusCalls() async {
        mockBridge.mockStatus = TestData.sampleStatus

        async let status1 = mockBridge.getStatus()
        async let status2 = mockBridge.getStatus()
        async let status3 = mockBridge.getStatus()

        let results = await [status1, status2, status3]

        for status in results {
            XCTAssertTrue(status.isInitialized)
            XCTAssertTrue(status.vdfCalibrated)
        }
    }

    @MainActor
    func testConcurrentCommands() async {
        mockBridge.initializeResult = CommandResult(success: true, message: "OK", exitCode: 0)
        mockBridge.calibrateResult = CommandResult(success: true, message: "OK", exitCode: 0)
        mockBridge.listResult = CommandResult(success: true, message: "", exitCode: 0)

        async let r1 = mockBridge.initialize()
        async let r2 = mockBridge.calibrate()
        async let r3 = mockBridge.list()

        let results = await [r1, r2, r3]

        XCTAssertTrue(results.allSatisfy { $0.success })
    }
}

// MARK: - Mock Sentinel Status Extension

extension MockWitnessdBridge {
    var mockSentinelStatus: SentinelStatus {
        get { _mockSentinelStatus }
        set { _mockSentinelStatus = newValue }
    }

    private static var _mockSentinelStatusStorage: [ObjectIdentifier: SentinelStatus] = [:]

    private var _mockSentinelStatus: SentinelStatus {
        get { MockWitnessdBridge._mockSentinelStatusStorage[ObjectIdentifier(self)] ?? SentinelStatus() }
        set { MockWitnessdBridge._mockSentinelStatusStorage[ObjectIdentifier(self)] = newValue }
    }

    func getSentinelStatus() async -> SentinelStatus {
        return mockSentinelStatus
    }
}

// MARK: - Output Parsing Tests

final class OutputParsingTests: XCTestCase {

    func testStripANSICodes() {
        let input = "\u{001B}[32mSuccess!\u{001B}[0m Operation completed"
        let expected = "Success! Operation completed"

        // Test the stripping function
        let pattern = #"\x1B\[[0-9;]*[a-zA-Z]"#
        let result = input.replacingOccurrences(of: pattern, with: "", options: .regularExpression)

        XCTAssertEqual(result, expected)
    }

    func testStripComplexANSICodes() {
        let input = "\u{001B}[1;31mError:\u{001B}[0m \u{001B}[33mWarning\u{001B}[0m message"
        let expected = "Error: Warning message"

        let pattern = #"\x1B\[[0-9;]*[a-zA-Z]"#
        let result = input.replacingOccurrences(of: pattern, with: "", options: .regularExpression)

        XCTAssertEqual(result, expected)
    }

    func testParseVDFIterationsFromOutput() {
        let output = "VDF iterations/sec: 1250000"

        if let match = output.range(of: #"VDF iterations/sec: (\d+)"#, options: .regularExpression) {
            let value = output[match].components(separatedBy: ": ").last ?? ""
            XCTAssertEqual(value, "1250000")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseTPMInfoFromOutput() {
        let output = "TPM: available (T2 Security Chip)"

        XCTAssertTrue(output.contains("TPM: available"))

        if let match = output.range(of: #"TPM: available \(([^)]+)\)"#, options: .regularExpression) {
            let info = String(output[match])
                .replacingOccurrences(of: "TPM: available (", with: "")
                .replacingOccurrences(of: ")", with: "")
            XCTAssertEqual(info, "T2 Security Chip")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseEventsCountFromOutput() {
        let output = "Database statistics:\nEvents: 12500\nFiles tracked: 25"

        if let match = output.range(of: #"Events: (\d+)"#, options: .regularExpression) {
            let value = output[match].components(separatedBy: ": ").last ?? "0"
            XCTAssertEqual(value, "12500")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseFilesTrackedFromOutput() {
        let output = "Database statistics:\nEvents: 12500\nFiles tracked: 25"

        if let match = output.range(of: #"Files tracked: (\d+)"#, options: .regularExpression) {
            let value = output[match].components(separatedBy: ": ").last ?? "0"
            XCTAssertEqual(value, "25")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseTrackingDocumentFromOutput() {
        let output = "Active Tracking Session\nDocument: /Users/test/Documents/novel.txt\nKeystrokes: 4523\nDuration: 1h 30m"

        if let match = output.range(of: #"Document: (.+)"#, options: .regularExpression) {
            let line = String(output[match])
            let document = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces)
            XCTAssertEqual(document, "/Users/test/Documents/novel.txt")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseKeystrokeCountFromOutput() {
        let output = "Keystrokes: 4523"

        if let match = output.range(of: #"Keystrokes: (\d+)"#, options: .regularExpression) {
            let value = output[match].components(separatedBy: ": ").last ?? "0"
            XCTAssertEqual(Int(value), 4523)
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseDurationFromOutput() {
        let output = "Duration: 2h 15m 30s"

        if let match = output.range(of: #"Duration: (.+)"#, options: .regularExpression) {
            let line = String(output[match])
            let duration = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces)
            XCTAssertEqual(duration, "2h 15m 30s")
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseSentinelPIDFromOutput() {
        let output = "Sentinel RUNNING (PID 12345)"

        if let match = output.range(of: #"PID (\d+)"#, options: .regularExpression) {
            let pidStr = output[match].components(separatedBy: " ").last ?? "0"
            XCTAssertEqual(Int(pidStr), 12345)
        } else {
            XCTFail("Pattern not matched")
        }
    }

    func testParseSentinelUptimeFromOutput() {
        let output = "Status: RUNNING\nUptime: 3h 45m 12s\nTracked: 5 documents"

        if let match = output.range(of: #"Uptime: (.+)"#, options: .regularExpression) {
            let line = String(output[match])
            let uptime = line.components(separatedBy: ": ").last?.trimmingCharacters(in: .whitespaces)
            XCTAssertEqual(uptime, "3h 45m 12s")
        } else {
            XCTFail("Pattern not matched")
        }
    }
}
