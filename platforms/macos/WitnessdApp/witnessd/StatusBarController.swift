import Cocoa
import SwiftUI

@MainActor
final class StatusBarController: NSObject, NSPopoverDelegate {
	private let statusItem: NSStatusItem
	private let popover: NSPopover
	private let bridge: WitnessdBridge

	private var statusTimer: Timer?
	private var globalMonitor: Any?
	private var localMonitor: Any?
	private var currentStatus = WitnessStatus()
	private var sentinelStatus = SentinelStatus()

	// Auto-checkpoint
	private var autoCheckpointTimer: Timer?
	private var settingsObserver: NSObjectProtocol?
	private var wasTrackingPreviously = false

	// Read auto-checkpoint settings from UserDefaults
	private var autoCheckpointEnabled: Bool {
		UserDefaults.standard.bool(forKey: "autoCheckpoint")
	}

	private var checkpointIntervalMinutes: Int {
		let value = UserDefaults.standard.integer(forKey: "checkpointIntervalMinutes")
		return value > 0 ? value : 30  // Default to 30 if not set
	}

	init(bridge: WitnessdBridge) {
		self.bridge = bridge
		self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
		self.popover = NSPopover()
		super.init()

		setupPopover()
		setupStatusBarButton()
		setupEventMonitors()
		setupSettingsObserver()
		startStatusUpdates()
	}

	private func setupSettingsObserver() {
		settingsObserver = NotificationCenter.default.addObserver(
			forName: UserDefaults.didChangeNotification,
			object: nil,
			queue: .main
		) { [weak self] _ in
			Task { @MainActor in
				self?.updateAutoCheckpointTimer()
			}
		}
	}

	// MARK: - Setup

	private func setupPopover() {
		popover.contentSize = NSSize(width: Design.Layout.popoverWidth,
									 height: Design.Layout.popoverHeight)
		popover.behavior = .transient
		popover.animates = true
		popover.delegate = self

		let contentView = PopoverContentView(
			bridge: bridge,
			closeAction: { [weak self] in self?.popover.performClose(nil) }
		)
		popover.contentViewController = NSHostingController(rootView: contentView)
	}

	private func setupStatusBarButton() {
		guard let button = statusItem.button else { return }

		updateIcon(isWatching: false, isInitialized: false)
		button.action = #selector(handleClick)
		button.target = self
		button.sendAction(on: [.leftMouseUp, .rightMouseUp])

		// Accessibility
		button.setAccessibilityLabel("Witnessd")
		button.setAccessibilityRole(.popUpButton)
		button.setAccessibilityValue("Not Initialized")
	}

	private func setupEventMonitors() {
		// Global monitor catches clicks outside the app
		globalMonitor = NSEvent.addGlobalMonitorForEvents(
			matching: [.leftMouseDown, .rightMouseDown]
		) { [weak self] _ in
			Task { @MainActor in
				guard let self else { return }
				if self.popover.isShown { self.popover.performClose(nil) }
			}
		}

		// Local monitor catches clicks inside the app that don't go through the popover
		localMonitor = NSEvent.addLocalMonitorForEvents(
			matching: [.leftMouseDown, .rightMouseDown]
		) { [weak self] event in
			guard let self else { return event }
			if self.popover.isShown, let button = self.statusItem.button {
				// If click is not on the status item button, close the popover
				let clickPoint = NSEvent.mouseLocation
				let buttonFrame = button.window?.convertToScreen(button.convert(button.bounds, to: nil)) ?? .zero
				if !buttonFrame.contains(clickPoint) {
					self.popover.performClose(nil)
				}
			}
			return event
		}
	}

	// MARK: - Status Bar Icon

	private func updateIcon(isWatching: Bool, isInitialized: Bool) {
		guard let button = statusItem.button else { return }

		let symbolName: String
		let tintColor: NSColor

		if isWatching {
			symbolName = "eye.circle.fill"
			tintColor = .systemGreen
		} else if isInitialized {
			symbolName = "eye.circle"
			tintColor = .labelColor
		} else {
			symbolName = "eye.slash.circle"
			tintColor = .secondaryLabelColor
		}

		let config = NSImage.SymbolConfiguration(pointSize: 16, weight: .medium)
		if let image = NSImage(systemSymbolName: symbolName, accessibilityDescription: "Witnessd") {
			button.image = image.withSymbolConfiguration(config)
			button.contentTintColor = tintColor
		}

		let tooltipStatus = isWatching ? "Watching Active" : (isInitialized ? "Ready" : "Not Initialized")
		button.toolTip = "Witnessd — \(tooltipStatus)"
		button.setAccessibilityValue(tooltipStatus)
	}

	// MARK: - Status Updates

	/// Polling intervals - faster when tracking, slower when idle
	private static let trackingPollInterval: TimeInterval = 5.0  // Increased from 3s to reduce CPU usage
	private static let idlePollInterval: TimeInterval = 15.0     // Increased from 10s to reduce CPU usage

	/// Cached status to avoid redundant UI updates
	private var lastIconState: (isWatching: Bool, isInitialized: Bool)?

	/// Tracks whether a status update is in progress to prevent overlapping calls
	private var isUpdatingStatus = false

	private func startStatusUpdates() {
		Task { @MainActor [weak self] in
			await self?.updateStatus()
		}

		scheduleStatusTimer(isTracking: false)
	}

	private func scheduleStatusTimer(isTracking: Bool) {
		statusTimer?.invalidate()
		let interval = isTracking ? Self.trackingPollInterval : Self.idlePollInterval
		statusTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
			Task { @MainActor in
				await self?.updateStatus()
			}
		}
	}

	/// Call this to immediately refresh status after an action
	private func triggerImmediateStatusUpdate() {
		Task { @MainActor in
			await updateStatus()
		}
	}

	private func updateStatus() async {
		// Prevent overlapping status updates
		guard !isUpdatingStatus else { return }
		isUpdatingStatus = true
		defer { isUpdatingStatus = false }

		let status = await bridge.getStatus()
		currentStatus = status
		sentinelStatus = await bridge.getSentinelStatus()

		// Only update icon if state actually changed
		let newIconState = (isWatching: sentinelStatus.isRunning, isInitialized: status.isInitialized)
		if lastIconState?.isWatching != newIconState.isWatching ||
		   lastIconState?.isInitialized != newIconState.isInitialized {
			updateIcon(isWatching: newIconState.isWatching, isInitialized: newIconState.isInitialized)
			lastIconState = newIconState
		}

		// Check if tracking state changed
		if status.isTracking != wasTrackingPreviously {
			wasTrackingPreviously = status.isTracking
			updateAutoCheckpointTimer()
			// Adjust polling interval based on tracking state
			scheduleStatusTimer(isTracking: status.isTracking)
		}
	}

	// MARK: - Auto-Checkpoint

	private func updateAutoCheckpointTimer() {
		// Invalidate any existing timer
		autoCheckpointTimer?.invalidate()
		autoCheckpointTimer = nil

		// Only start timer if auto-checkpoint is enabled AND we're currently tracking
		guard autoCheckpointEnabled, currentStatus.isTracking else {
			return
		}

		// Create timer with interval from settings (converted to seconds)
		let intervalSeconds = TimeInterval(checkpointIntervalMinutes * 60)
		autoCheckpointTimer = Timer.scheduledTimer(withTimeInterval: intervalSeconds, repeats: true) { [weak self] _ in
			Task { @MainActor in
				await self?.performAutoCheckpoint()
			}
		}
	}

	private func performAutoCheckpoint() async {
		// Guard that tracking is still active
		guard currentStatus.isTracking,
			  let trackingDocument = currentStatus.trackingDocument else {
			return
		}

		// Create timestamp for commit message
		let formatter = DateFormatter()
		formatter.dateFormat = "HH:mm"
		let timeString = formatter.string(from: Date())

		// Perform the commit
		let result = await bridge.commit(filePath: trackingDocument, message: "Auto-checkpoint at \(timeString)")

		// Send notification on success
		if result.success {
			let documentName = URL(fileURLWithPath: trackingDocument).lastPathComponent
			NotificationManager.shared.notifyAutoCheckpointCreated(document: documentName)
		}
	}

	// MARK: - Click Handling

	@objc private func handleClick(_ sender: AnyObject?) {
		// Always show the menu on any click (left or right)
		// This makes it immediately obvious how to start/stop tracking
		showContextMenu()
	}

	private func togglePopover(_ sender: AnyObject?) {
		if popover.isShown {
			popover.performClose(sender)
			return
		}
		guard let button = statusItem.button else { return }
		popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
		NSApp.activate(ignoringOtherApps: true)
	}

	private func showContextMenu() {
		let menu = NSMenu()

		// Status header showing sentinel status
		let header = NSMenuItem()
		if sentinelStatus.isRunning {
			let docCount = sentinelStatus.trackedDocuments
			header.title = "● Sentinel Active • \(docCount) document\(docCount == 1 ? "" : "s") tracked"
		} else if currentStatus.isInitialized {
			header.title = "○ Sentinel Stopped"
		} else {
			header.title = "○ Not Initialized"
		}
		header.isEnabled = false
		menu.addItem(header)
		menu.addItem(.separator())

		if sentinelStatus.isRunning {
			// Show stop option when running
			menu.addItem(makeMenuItem(
				title: "Stop Sentinel",
				systemImage: "stop.fill",
				action: #selector(stopSentinel),
				keyEquivalent: ""
			))
		} else if currentStatus.isInitialized {
			// Show start option when stopped
			menu.addItem(makeMenuItem(
				title: "▶ Start Sentinel",
				systemImage: "play.fill",
				action: #selector(startSentinel),
				keyEquivalent: "g"
			))
		}

		menu.addItem(.separator())

		menu.addItem(makeMenuItem(
			title: "View Details…",
			systemImage: "info.circle",
			action: #selector(showDetails),
			keyEquivalent: ""
		))

		menu.addItem(makeMenuItem(
			title: "Settings…",
			systemImage: "gear",
			action: #selector(openSettings),
			keyEquivalent: ","
		))

		menu.addItem(.separator())

		menu.addItem(makeMenuItem(
			title: "Quit Witnessd",
			systemImage: nil,
			action: #selector(quit),
			keyEquivalent: "q"
		))

		statusItem.menu = menu
		statusItem.button?.performClick(nil)
		statusItem.menu = nil
	}

	private func makeMenuItem(title: String,
							  systemImage: String?,
							  action: Selector,
							  keyEquivalent: String) -> NSMenuItem {
		let item = NSMenuItem(title: title, action: action, keyEquivalent: keyEquivalent)
		item.target = self
		if let systemImage {
			item.image = NSImage(systemSymbolName: systemImage, accessibilityDescription: title)
		}
		// Set accessibility help for the menu item
		item.setAccessibilityHelp("Activates \(title)")
		return item
	}

	// MARK: - Quick Actions

	@objc private func stopSentinel() {
		Task { @MainActor in
			AccessibilityAnnouncer.shared.announceLoading("Stopping sentinel")
			let result = await bridge.sentinelStop()
			if result.success {
				await updateStatus()
				AccessibilityAnnouncer.shared.announceStateChange("Sentinel stopped", context: "Document tracking is now inactive")
				NotificationManager.shared.send(
					title: "Sentinel Stopped",
					body: "Automatic document tracking has been stopped."
				)
			} else {
				AccessibilityAnnouncer.shared.announce("Failed to stop sentinel: \(result.message)", highPriority: true)
				showError(title: "Failed to Stop", message: result.message)
			}
		}
	}

	@objc private func startSentinel() {
		Task { @MainActor in
			AccessibilityAnnouncer.shared.announceLoading("Starting sentinel")
			let result = await bridge.sentinelStart()
			if result.success {
				await updateStatus()
				AccessibilityAnnouncer.shared.announceStateChange("Sentinel started", context: "Document tracking is now active")
				NotificationManager.shared.send(
					title: "Sentinel Started",
					body: "Automatic document tracking is now active."
				)
			} else {
				// Check if it's a permissions issue
				if result.message.contains("accessibility") || result.message.contains("failed to start") {
					AccessibilityAnnouncer.shared.announce("Accessibility permission required to start sentinel", highPriority: true)
					showError(title: "Accessibility Required",
							  message: "The sentinel needs accessibility permissions to track document focus.\n\nGo to System Settings → Privacy & Security → Accessibility and add Witnessd.")
				} else {
					AccessibilityAnnouncer.shared.announce("Failed to start sentinel: \(result.message)", highPriority: true)
					showError(title: "Failed to Start", message: result.message)
				}
			}
		}
	}

	private func showError(title: String, message: String) {
		let alert = NSAlert()
		alert.messageText = title
		alert.informativeText = message
		alert.alertStyle = .warning
		alert.addButton(withTitle: "OK")
		alert.runModal()
	}

	@objc private func showDetails() {
		togglePopover(nil)
	}

	@objc private func openSettings() {
		if #available(macOS 14.0, *) {
			NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
		} else {
			NSApp.sendAction(Selector(("showPreferencesWindow:")), to: nil, from: nil)
		}
		NSApp.activate(ignoringOtherApps: true)
	}

	@objc private func quit() {
		// Clean up and terminate immediately
		// Don't wait for async operations - CLI handles its own cleanup
		shutdown()
		NSApp.terminate(nil)
	}
	
	@MainActor
	func shutdown() {
		if let globalMonitor { NSEvent.removeMonitor(globalMonitor) }
		if let localMonitor { NSEvent.removeMonitor(localMonitor) }
		globalMonitor = nil
		localMonitor = nil

		statusTimer?.invalidate()
		statusTimer = nil

		// Clean up auto-checkpoint timer
		autoCheckpointTimer?.invalidate()
		autoCheckpointTimer = nil

		// Remove settings observer
		if let observer = settingsObserver {
			NotificationCenter.default.removeObserver(observer)
			settingsObserver = nil
		}
	}


}
