import SwiftUI

@main
struct WitnessApp: App {
	@NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

	var body: some Scene {
		Settings {
			SettingsView()
		}
		.commands {
			// Remove unused menu items (menu bar app)
			CommandGroup(replacing: .newItem) { }
			CommandGroup(replacing: .undoRedo) { }
			CommandGroup(replacing: .pasteboard) { }

			CommandMenu("Witnessd") {
				Button("Show Settings") {
					openSettings()
				}
				.keyboardShortcut(",", modifiers: [.command])

				Divider()

				Button("Quit Witnessd") {
					NSApp.terminate(nil)
				}
				.keyboardShortcut("q", modifiers: [.command])
			}
		}
	}

	private func openSettings() {
		// For menu bar apps (.accessory policy), temporarily become regular app
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
