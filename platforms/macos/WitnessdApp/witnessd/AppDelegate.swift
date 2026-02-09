import Cocoa
import SwiftUI
import ApplicationServices
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

	// MARK: - Core Objects

	private var statusBarController: StatusBarController?
	private let witnessdBridge = WitnessdBridge()
	private var windowCheckWorkItem: DispatchWorkItem?

	// MARK: - Application Lifecycle

	func applicationDidFinishLaunching(_ notification: Notification) {
		// Menu bar–only app
		NSApp.setActivationPolicy(.accessory)

		statusBarController = StatusBarController(bridge: witnessdBridge)

		// Monitor when all windows are closed to return to accessory mode
		NotificationCenter.default.addObserver(
			self,
			selector: #selector(windowWillClose),
			name: NSWindow.willCloseNotification,
			object: nil
		)

		// Auto-initialize on first launch
		Task {
			await autoInitializeIfNeeded()
			await checkAccessibilityPermission()
		}
	}

	@objc private func windowWillClose(_ notification: Notification) {
		// Cancel any pending check to debounce rapid window closes
		windowCheckWorkItem?.cancel()

		// Create new work item for checking windows
		let workItem = DispatchWorkItem { [weak self] in
			guard self != nil else { return }

			// Check for any visible standard windows
			// Exclude status bar, panels, and other special windows
			let visibleWindows = NSApp.windows.filter { window in
				window.isVisible &&
				window.level == .normal &&
				!window.className.contains("StatusBar") &&
				window.styleMask.contains(.titled)
			}

			if visibleWindows.isEmpty {
				NSApp.setActivationPolicy(.accessory)
			}
		}

		windowCheckWorkItem = workItem
		// Delay to allow for window transition animations and debounce
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.3, execute: workItem)
	}

	func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
		// Clean up observers
		NotificationCenter.default.removeObserver(self)
		windowCheckWorkItem?.cancel()
		windowCheckWorkItem = nil

		// Shutdown status bar controller
		statusBarController?.shutdown()

		// Allow immediate termination - CLI handles its own cleanup
		return .terminateNow
	}

	deinit {
		NotificationCenter.default.removeObserver(self)
	}

	// MARK: - Auto-Initialization

	private func autoInitializeIfNeeded() async {
		let defaults = UserDefaults.standard
		let hasInitialized = defaults.bool(forKey: "hasAutoInitialized")

		guard !hasInitialized else { return }

		// Initialize witnessd (creates signing key and database)
		let initResult = await witnessdBridge.initialize()
		if initResult.success {
			defaults.set(true, forKey: "hasAutoInitialized")

			// Also calibrate VDF in background
			Task {
				_ = await witnessdBridge.calibrate()
			}
		}
	}

	// MARK: - Accessibility Permission

	private func checkAccessibilityPermission() async {
		// Check if we already have accessibility permission
		let trusted = AXIsProcessTrusted()

		if !trusted {
			// Request notification permission first
			await requestNotificationPermission()

			// Show notification about accessibility
			showAccessibilityNotification()

			// Open System Settings → Privacy & Security → Accessibility
			// This also adds the app to the Accessibility list
			openAccessibilitySettings()
		}
	}

	private func requestNotificationPermission() async {
		let center = UNUserNotificationCenter.current()
		do {
			try await center.requestAuthorization(options: [.alert, .sound])
		} catch {
			// Notification permission denied, continue anyway
		}
	}

	private func showAccessibilityNotification() {
		let center = UNUserNotificationCenter.current()

		let content = UNMutableNotificationContent()
		content.title = "Enable Accessibility for Witnessd"
		content.body = "Witnessd needs Accessibility access to track keystrokes. Please toggle ON the switch next to Witnessd in System Settings."
		content.sound = .default

		let request = UNNotificationRequest(
			identifier: "accessibility-prompt",
			content: content,
			trigger: nil // Deliver immediately
		)

		center.add(request)
	}

	private func openAccessibilitySettings() {
		// This URL opens System Settings → Privacy & Security → Accessibility
		// AND adds the app to the list automatically
		// Use string key directly to avoid concurrency warning with kAXTrustedCheckOptionPrompt
		let promptKey = "AXTrustedCheckOptionPrompt" as CFString
		let options: CFDictionary = [promptKey: true] as CFDictionary
		AXIsProcessTrustedWithOptions(options)

		// Also open the settings pane directly for visibility
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
			if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") {
				NSWorkspace.shared.open(url)
			}
		}
	}
}

