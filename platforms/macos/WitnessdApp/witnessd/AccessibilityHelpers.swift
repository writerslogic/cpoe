import SwiftUI

// MARK: - Accessibility Environment Values

extension EnvironmentValues {
    /// Convenience accessor for reduced motion preference
    var prefersReducedMotion: Bool {
        accessibilityReduceMotion
    }

    /// Convenience accessor for differentiate without color
    var differentiateWithoutColor: Bool {
        accessibilityDifferentiateWithoutColor
    }

    /// Convenience accessor for increased contrast
    var increasedContrast: Bool {
        accessibilityDisplayShouldIncreaseContrast
    }
}

// Helper to check if increased contrast is enabled
private extension EnvironmentValues {
    var accessibilityDisplayShouldIncreaseContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    /// Convenience accessor for VoiceOver running
    var isVoiceOverRunning: Bool {
        accessibilityVoiceOverEnabled
    }
}

// MARK: - Accessible Animation

/// Animation that respects reduced motion preference
enum AccessibleAnimation {
    /// Returns animation appropriate for accessibility settings
    static func standard(duration: Double = 0.2) -> Animation? {
        if NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            return nil
        }
        return .easeInOut(duration: duration)
    }

    /// Performs animation respecting accessibility preferences
    static func withAccessibleAnimation<Result>(
        _ animation: Animation? = .easeInOut(duration: 0.2),
        _ body: () throws -> Result
    ) rethrows -> Result {
        if NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            return try body()
        }
        return try withAnimation(animation, body)
    }
}

// MARK: - Accessible Status Indicator

/// A status indicator that works without color alone
struct AccessibleStatusIndicator: View {
    let isActive: Bool
    let activeLabel: String
    let inactiveLabel: String

    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    var body: some View {
        HStack(spacing: 4) {
            if differentiateWithoutColor {
                // Use icons instead of/alongside color
                Image(systemName: isActive ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(isActive ? .green : .secondary)
                    .font(.system(size: 10))
            } else {
                Circle()
                    .fill(isActive ? Color.green : Color.gray.opacity(0.3))
                    .frame(width: 8, height: 8)
            }

            // Always provide text label for screen readers
            Text(isActive ? activeLabel : inactiveLabel)
                .font(.caption2)
                .foregroundColor(.secondary)
                .accessibilityHidden(true) // The whole component has its own label
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(isActive ? activeLabel : inactiveLabel)
        .accessibilityValue(isActive ? "Active" : "Inactive")
    }
}

// MARK: - View Extensions for Accessibility

extension View {
    /// Adds comprehensive accessibility information to a button
    func accessibleButton(
        label: String,
        hint: String? = nil,
        identifier: String? = nil
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityHint(hint ?? "")
            .accessibilityAddTraits(.isButton)
            .accessibilityIdentifier(identifier ?? label.lowercased().replacingOccurrences(of: " ", with: "-"))
    }

    /// Adds accessibility for a header element
    func accessibleHeader(_ label: String) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityAddTraits(.isHeader)
    }

    /// Adds accessibility for a static text element
    func accessibleText(_ description: String? = nil) -> some View {
        self
            .accessibilityLabel(description ?? "")
            .accessibilityAddTraits(.isStaticText)
    }

    /// Adds accessibility for an image with description
    func accessibleImage(_ description: String) -> some View {
        self
            .accessibilityLabel(description)
            .accessibilityAddTraits(.isImage)
    }

    /// Groups elements for VoiceOver navigation
    func accessibleGroup(label: String, hint: String? = nil) -> some View {
        self
            .accessibilityElement(children: .combine)
            .accessibilityLabel(label)
            .accessibilityHint(hint ?? "")
    }

    /// Makes element a landmark for navigation
    func accessibleLandmark(_ label: String) -> some View {
        self
            .accessibilityElement(children: .contain)
            .accessibilityLabel(label)
    }

    /// Animation that respects reduced motion
    func accessibleAnimation<V: Equatable>(
        _ animation: Animation? = .easeInOut,
        value: V
    ) -> some View {
        self.modifier(AccessibleAnimationModifier(animation: animation, value: value))
    }
}

struct AccessibleAnimationModifier<V: Equatable>: ViewModifier {
    let animation: Animation?
    let value: V

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        if reduceMotion {
            content
        } else {
            content.animation(animation, value: value)
        }
    }
}

// MARK: - Accessibility Announcements

@MainActor
final class AccessibilityAnnouncer {
    static let shared = AccessibilityAnnouncer()

    private init() {}

    /// Announces a message to VoiceOver users
    func announce(_ message: String, highPriority: Bool = false) {
        let priority: Int = highPriority ? 1 : 0
        NSAccessibility.post(
            element: NSApp as Any,
            notification: .announcementRequested,
            userInfo: [
                NSAccessibility.NotificationUserInfoKey.announcement: message,
                NSAccessibility.NotificationUserInfoKey.priority: NSNumber(value: priority)
            ]
        )
    }

    /// Announces completion of an action
    func announceCompletion(_ action: String, success: Bool) {
        let message = success ? "\(action) completed successfully" : "\(action) failed"
        announce(message, highPriority: !success)
    }

    /// Announces a state change (e.g., tracking started/stopped)
    func announceStateChange(_ state: String, context: String? = nil) {
        var message = state
        if let context = context {
            message += ". \(context)"
        }
        announce(message, highPriority: true)
    }

    /// Announces loading progress
    func announceLoading(_ activity: String) {
        announce("\(activity), please wait")
    }

    /// Announces navigation to a new section
    func announceNavigation(to section: String) {
        announce("Navigated to \(section)")
    }
}

// MARK: - Focus Management

extension View {
    /// Manages focus for keyboard navigation
    @ViewBuilder
    func focusableElement(
        isFocused: FocusState<Bool>.Binding,
        onFocus: (() -> Void)? = nil
    ) -> some View {
        self
            .focusable()
            .focused(isFocused)
            .onChange(of: isFocused.wrappedValue) { _, focused in
                if focused {
                    onFocus?()
                }
            }
    }
}

// MARK: - High Contrast Support

extension Color {
    /// Returns a color adjusted for increased contrast if needed
    static func adaptiveColor(
        normal: Color,
        highContrast: Color
    ) -> Color {
        if NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast {
            return highContrast
        }
        return normal
    }
}

// MARK: - Semantic Colors for Accessibility

extension Color {
    /// Accessible success color with sufficient contrast
    static var accessibleSuccess: Color {
        Color.adaptiveColor(
            normal: .green,
            highContrast: Color(red: 0.0, green: 0.6, blue: 0.0)
        )
    }

    /// Accessible warning color with sufficient contrast
    static var accessibleWarning: Color {
        Color.adaptiveColor(
            normal: .orange,
            highContrast: Color(red: 0.8, green: 0.4, blue: 0.0)
        )
    }

    /// Accessible error color with sufficient contrast
    static var accessibleError: Color {
        Color.adaptiveColor(
            normal: .red,
            highContrast: Color(red: 0.8, green: 0.0, blue: 0.0)
        )
    }
}

// MARK: - Keyboard Navigation Support

/// Protocol for views that support keyboard navigation
protocol KeyboardNavigable {
    associatedtype FocusField: Hashable
    var focusedField: FocusField? { get set }
}

/// View modifier for consistent keyboard shortcut handling
struct KeyboardShortcutModifier: ViewModifier {
    let key: KeyEquivalent
    let modifiers: EventModifiers
    let action: () -> Void

    func body(content: Content) -> some View {
        content
            .keyboardShortcut(key, modifiers: modifiers)
            .onKeyPress(key) {
                action()
                return .handled
            }
    }
}

extension View {
    /// Adds a keyboard shortcut with action
    func accessibleKeyboardShortcut(
        _ key: KeyEquivalent,
        modifiers: EventModifiers = .command,
        action: @escaping () -> Void
    ) -> some View {
        self.modifier(KeyboardShortcutModifier(key: key, modifiers: modifiers, action: action))
    }

    /// Makes a view focusable with keyboard and provides visual focus ring
    func accessibleFocusable(
        identifier: String? = nil
    ) -> some View {
        self
            .focusable()
            .focusEffectDisabled(false)
            .accessibilityIdentifier(identifier ?? "")
    }

    /// Adds rotor support for quick navigation
    func accessibleRotorEntry(
        _ label: String,
        id: String
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityIdentifier(id)
    }
}

// MARK: - Dynamic Type Support

extension View {
    /// Scales font size based on Dynamic Type settings while maintaining hierarchy
    @ViewBuilder
    func dynamicTypeSize(
        minimum: DynamicTypeSize = .xSmall,
        maximum: DynamicTypeSize = .accessibility3
    ) -> some View {
        self.dynamicTypeSize(minimum...maximum)
    }

    /// Ensures text remains readable at all Dynamic Type sizes
    func accessibleTextContainer() -> some View {
        self
            .lineLimit(nil)
            .fixedSize(horizontal: false, vertical: true)
            .minimumScaleFactor(0.8)
    }
}

// MARK: - Accessibility Traits Helpers

extension View {
    /// Marks view as a section with proper semantics
    func accessibleSection(
        _ title: String,
        hint: String? = nil
    ) -> some View {
        self
            .accessibilityElement(children: .contain)
            .accessibilityLabel(title)
            .accessibilityHint(hint ?? "")
            .accessibilityAddTraits(.isHeader)
    }

    /// Marks view as loading with proper announcement
    func accessibleLoading(
        _ isLoading: Bool,
        message: String = "Loading"
    ) -> some View {
        self
            .accessibilityLabel(isLoading ? message : "")
            .accessibilityAddTraits(isLoading ? .updatesFrequently : [])
            .onChange(of: isLoading) { _, loading in
                if loading {
                    Task { @MainActor in
                        AccessibilityAnnouncer.shared.announceLoading(message)
                    }
                }
            }
    }

    /// Marks view as containing live-updating content
    func accessibleLiveRegion(
        _ polite: Bool = true
    ) -> some View {
        self.accessibilityAddTraits(.updatesFrequently)
    }

    /// Adds a custom accessibility action
    func accessibleAction(
        named name: String,
        action: @escaping () -> Void
    ) -> some View {
        self.accessibilityAction(named: name, action)
    }

    /// Groups multiple accessibility actions
    func accessibleActions(
        _ actions: [(name: String, action: () -> Void)]
    ) -> some View {
        var view = self
        for (name, action) in actions {
            view = AnyView(view.accessibilityAction(named: name, action)) as! Self
        }
        return view
    }
}

// MARK: - Form Accessibility

extension View {
    /// Makes a form field accessible with proper label and value
    func accessibleFormField(
        label: String,
        value: String,
        hint: String? = nil
    ) -> some View {
        self
            .accessibilityElement(children: .combine)
            .accessibilityLabel(label)
            .accessibilityValue(value)
            .accessibilityHint(hint ?? "")
    }

    /// Makes a toggle accessible with current state
    func accessibleToggle(
        label: String,
        isOn: Bool,
        hint: String? = nil
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityValue(isOn ? "On" : "Off")
            .accessibilityHint(hint ?? "Double-tap to toggle")
            .accessibilityAddTraits(.isButton)
    }

    /// Makes a picker accessible with current selection
    func accessiblePicker(
        label: String,
        selection: String,
        hint: String? = nil
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityValue(selection)
            .accessibilityHint(hint ?? "Double-tap to change selection")
    }

    /// Makes a slider accessible with current value
    func accessibleSlider(
        label: String,
        value: String,
        hint: String? = nil
    ) -> some View {
        self
            .accessibilityLabel(label)
            .accessibilityValue(value)
            .accessibilityHint(hint ?? "Swipe up or down to adjust")
    }
}

// MARK: - Error and Alert Accessibility

extension View {
    /// Announces an error to VoiceOver users
    func accessibleError(
        _ error: String?,
        isPresented: Bool
    ) -> some View {
        self.onChange(of: isPresented) { _, presented in
            if presented, let error = error {
                Task { @MainActor in
                    AccessibilityAnnouncer.shared.announce("Error: \(error)", highPriority: true)
                }
            }
        }
    }

    /// Announces a success message to VoiceOver users
    func accessibleSuccess(
        _ message: String?,
        isPresented: Bool
    ) -> some View {
        self.onChange(of: isPresented) { _, presented in
            if presented, let message = message {
                Task { @MainActor in
                    AccessibilityAnnouncer.shared.announce(message)
                }
            }
        }
    }
}

// MARK: - macOS Accessibility Settings

/// Utility class to observe macOS accessibility settings
@MainActor
final class AccessibilitySettingsObserver: ObservableObject {
    static let shared = AccessibilitySettingsObserver()

    @Published var reduceMotion: Bool
    @Published var increaseContrast: Bool
    @Published var differentiateWithoutColor: Bool
    @Published var reduceTransparency: Bool
    @Published var isVoiceOverRunning: Bool

    private var observers: [NSObjectProtocol] = []

    private init() {
        let workspace = NSWorkspace.shared
        self.reduceMotion = workspace.accessibilityDisplayShouldReduceMotion
        self.increaseContrast = workspace.accessibilityDisplayShouldIncreaseContrast
        self.differentiateWithoutColor = workspace.accessibilityDisplayShouldDifferentiateWithoutColor
        self.reduceTransparency = workspace.accessibilityDisplayShouldReduceTransparency
        self.isVoiceOverRunning = NSWorkspace.shared.isVoiceOverEnabled

        // Observe for changes
        setupObservers()
    }

    private func setupObservers() {
        // Observe accessibility settings changes via distributed notification center
        let dnc = DistributedNotificationCenter.default()

        observers.append(dnc.addObserver(
            forName: NSNotification.Name("com.apple.accessibility.api.accessibilitySettingsChanged"),
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.refreshSettings()
        })

        // Also observe workspace notifications
        observers.append(NotificationCenter.default.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.refreshSettings()
        })
    }

    private func refreshSettings() {
        let workspace = NSWorkspace.shared
        reduceMotion = workspace.accessibilityDisplayShouldReduceMotion
        increaseContrast = workspace.accessibilityDisplayShouldIncreaseContrast
        differentiateWithoutColor = workspace.accessibilityDisplayShouldDifferentiateWithoutColor
        reduceTransparency = workspace.accessibilityDisplayShouldReduceTransparency
        isVoiceOverRunning = workspace.isVoiceOverEnabled
    }

    deinit {
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
            DistributedNotificationCenter.default().removeObserver(observer)
        }
    }
}

// MARK: - Scalable Typography for macOS

extension Font {
    /// Creates a font that scales with system text size preferences
    static func scalable(
        size: CGFloat,
        weight: Font.Weight = .regular,
        design: Font.Design = .default
    ) -> Font {
        // On macOS, use the system font which respects text size settings
        return .system(size: size, weight: weight, design: design)
    }

    /// Creates a scaled font based on a text style (body, headline, etc.)
    /// This provides better accessibility as it uses semantic text styles
    static func accessibleStyle(_ style: Font.TextStyle, weight: Font.Weight = .regular) -> Font {
        return .system(style, weight: weight)
    }
}

// MARK: - Accessibility Focus State

/// A focus state wrapper that announces focus changes
struct AccessibleFocusState<Value: Hashable>: DynamicProperty {
    @FocusState var wrappedValue: Value?

    func announce(for value: Value, label: String) {
        if wrappedValue == value {
            Task { @MainActor in
                AccessibilityAnnouncer.shared.announce("Focus on \(label)")
            }
        }
    }
}

// MARK: - Accessibility Rotor Support

extension View {
    /// Adds custom rotor for quick navigation within a view
    func accessibleRotor<Content: View>(
        _ label: String,
        entries: [String],
        @ViewBuilder entryView: @escaping (String) -> Content
    ) -> some View {
        self.accessibilityRotor(label) {
            ForEach(entries, id: \.self) { entry in
                AccessibilityRotorEntry(entry, id: entry) {
                    entryView(entry)
                }
            }
        }
    }
}

// MARK: - Tab Navigation Support

extension View {
    /// Makes an element part of tab navigation order
    func accessibleTabStop(order: Int) -> some View {
        self
            .focusable()
            .accessibilityIdentifier("tab-stop-\(order)")
    }

    /// Adds keyboard shortcuts for common actions
    func accessibleShortcuts(
        escape: (() -> Void)? = nil,
        enter: (() -> Void)? = nil
    ) -> some View {
        var view = self
        if let escape = escape {
            view = AnyView(view.onKeyPress(.escape) {
                escape()
                return .handled
            }) as! Self
        }
        if let enter = enter {
            view = AnyView(view.onKeyPress(.return) {
                enter()
                return .handled
            }) as! Self
        }
        return view
    }
}
