import SwiftUI

// MARK: - Design Tokens

/// Centralized design system for consistent styling across the app
enum Design {
    // MARK: - Spacing Scale (4px base unit)
    enum Spacing {
        static let xxxs: CGFloat = 2
        static let xxs: CGFloat = 4
        static let xs: CGFloat = 6
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 16
        static let xl: CGFloat = 20
        static let xxl: CGFloat = 24
        static let xxxl: CGFloat = 32
        static let xxxxl: CGFloat = 40
    }

    // MARK: - Corner Radius
    enum Radius {
        static let xs: CGFloat = 4
        static let sm: CGFloat = 6
        static let md: CGFloat = 8
        static let lg: CGFloat = 12
        static let xl: CGFloat = 16
        static let full: CGFloat = 9999
    }

    // MARK: - Icon Sizes
    enum IconSize {
        static let xs: CGFloat = 12
        static let sm: CGFloat = 14
        static let md: CGFloat = 16
        static let lg: CGFloat = 20
        static let xl: CGFloat = 24
        static let xxl: CGFloat = 32
        static let hero: CGFloat = 48
        static let display: CGFloat = 64
    }

    // MARK: - Typography
    enum Typography {
        static let displayLarge = Font.system(size: 34, weight: .bold, design: .default)
        static let displayMedium = Font.system(size: 28, weight: .bold, design: .default)
        static let displaySmall = Font.system(size: 22, weight: .bold, design: .default)

        static let headlineLarge = Font.system(size: 17, weight: .semibold, design: .default)
        static let headlineMedium = Font.system(size: 15, weight: .semibold, design: .default)
        static let headlineSmall = Font.system(size: 13, weight: .semibold, design: .default)

        static let bodyLarge = Font.system(size: 15, weight: .regular, design: .default)
        static let bodyMedium = Font.system(size: 13, weight: .regular, design: .default)
        static let bodySmall = Font.system(size: 11, weight: .regular, design: .default)

        static let labelLarge = Font.system(size: 13, weight: .medium, design: .default)
        static let labelMedium = Font.system(size: 11, weight: .medium, design: .default)
        static let labelSmall = Font.system(size: 10, weight: .medium, design: .default)

        static let mono = Font.system(size: 12, weight: .regular, design: .monospaced)
        static let monoSmall = Font.system(size: 11, weight: .regular, design: .monospaced)

        static let statValue = Font.system(size: 15, weight: .semibold, design: .rounded)
        static let statLabel = Font.system(size: 10, weight: .medium, design: .default)
    }

    // MARK: - Semantic Colors
    enum Colors {
        // Status colors
        static let success = Color.green
        static let warning = Color.orange
        static let error = Color.red
        static let info = Color.blue

        // UI colors
        static let primaryText = Color(nsColor: .labelColor)
        static let secondaryText = Color(nsColor: .secondaryLabelColor)
        static let tertiaryText = Color(nsColor: .tertiaryLabelColor)

        static let background = Color(nsColor: .windowBackgroundColor)
        static let secondaryBackground = Color(nsColor: .controlBackgroundColor)
        static let tertiaryBackground = Color(nsColor: .underPageBackgroundColor)

        static let separator = Color(nsColor: .separatorColor)
        static let border = Color(nsColor: .separatorColor)

        // Interactive states
        static let hover = Color(nsColor: .controlAccentColor).opacity(0.1)
        static let pressed = Color(nsColor: .controlAccentColor).opacity(0.2)

        // Brand gradient
        static let brandGradient = LinearGradient(
            colors: [.blue, .purple],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    // MARK: - Shadows
    enum Shadow {
        static let sm = ShadowStyle(color: .black.opacity(0.08), radius: 2, x: 0, y: 1)
        static let md = ShadowStyle(color: .black.opacity(0.1), radius: 4, x: 0, y: 2)
        static let lg = ShadowStyle(color: .black.opacity(0.12), radius: 8, x: 0, y: 4)
    }

    // MARK: - Animation
    enum Animation {
        static let fast = SwiftUI.Animation.easeOut(duration: 0.15)
        static let normal = SwiftUI.Animation.easeInOut(duration: 0.2)
        static let slow = SwiftUI.Animation.easeInOut(duration: 0.3)
        static let spring = SwiftUI.Animation.spring(response: 0.3, dampingFraction: 0.7)
        static let bouncy = SwiftUI.Animation.spring(response: 0.4, dampingFraction: 0.6)
        static let gentle = SwiftUI.Animation.spring(response: 0.5, dampingFraction: 0.8)
        static let snappy = SwiftUI.Animation.spring(response: 0.25, dampingFraction: 0.7)

        // State transition animations
        static let stateChange = SwiftUI.Animation.spring(response: 0.35, dampingFraction: 0.75)
        static let pulse = SwiftUI.Animation.easeInOut(duration: 0.6).repeatForever(autoreverses: true)
        static let shimmer = SwiftUI.Animation.linear(duration: 1.5).repeatForever(autoreverses: false)
    }

    // MARK: - Layout
    enum Layout {
        static let popoverWidth: CGFloat = 320
        static let popoverHeight: CGFloat = 440
        static let settingsWidth: CGFloat = 480
        static let settingsHeight: CGFloat = 320
        static let onboardingWidth: CGFloat = 520
        static let onboardingHeight: CGFloat = 440
        static let historyWidth: CGFloat = 720
        static let historyHeight: CGFloat = 520
    }
}

struct ShadowStyle {
    let color: Color
    let radius: CGFloat
    let x: CGFloat
    let y: CGFloat
}

// MARK: - View Extensions

extension View {
    /// Applies consistent card styling
    func cardStyle(padding: CGFloat = Design.Spacing.md) -> some View {
        self
            .padding(padding)
            .background(Design.Colors.secondaryBackground)
            .clipShape(RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous))
    }

    /// Applies consistent section header styling
    func sectionHeader() -> some View {
        self
            .font(Design.Typography.headlineSmall)
            .foregroundColor(Design.Colors.primaryText)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Applies hover effect
    func hoverEffect() -> some View {
        self.modifier(HoverEffectModifier())
    }

    /// Applies consistent button padding
    func buttonPadding() -> some View {
        self.padding(.horizontal, Design.Spacing.md)
            .padding(.vertical, Design.Spacing.sm)
    }

    /// Applies shadow style
    func shadow(_ style: ShadowStyle) -> some View {
        self.shadow(color: style.color, radius: style.radius, x: style.x, y: style.y)
    }
}

struct HoverEffectModifier: ViewModifier {
    @State private var isHovered = false

    func body(content: Content) -> some View {
        content
            .background(isHovered ? Design.Colors.hover : Color.clear)
            .clipShape(RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous))
            .onHover { hovering in
                withAnimation(Design.Animation.fast) {
                    isHovered = hovering
                }
            }
    }
}

// MARK: - Reusable Components

/// Consistent section header
struct SectionHeader: View {
    let title: String
    let action: (() -> Void)?
    let actionLabel: String?

    init(_ title: String, action: (() -> Void)? = nil, actionLabel: String? = nil) {
        self.title = title
        self.action = action
        self.actionLabel = actionLabel
    }

    var body: some View {
        HStack(alignment: .center) {
            Text(title)
                .font(Design.Typography.headlineSmall)
                .foregroundColor(Design.Colors.secondaryText)
                .textCase(.uppercase)
                .tracking(0.5)

            Spacer()

            if let action = action, let label = actionLabel {
                Button(action: action) {
                    Text(label)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(.accentColor)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(label)
                .accessibilityHint("Activates \(label.lowercased()) action for \(title) section")
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
        .accessibilityLabel("\(title) section")
    }
}

/// Consistent icon button
struct IconButton: View {
    let icon: String
    let label: String
    let hint: String?
    let size: CGFloat
    let action: () -> Void

    @State private var isHovered = false
    @State private var isPressed = false

    init(icon: String, label: String, hint: String? = nil, size: CGFloat = Design.IconSize.md, action: @escaping () -> Void) {
        self.icon = icon
        self.label = label
        self.hint = hint
        self.size = size
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: size, weight: .medium))
                .foregroundColor(isHovered ? .accentColor : Design.Colors.secondaryText)
                .frame(width: size + Design.Spacing.md, height: size + Design.Spacing.md)
                .background(
                    RoundedRectangle(cornerRadius: Design.Radius.sm, style: .continuous)
                        .fill(isPressed ? Design.Colors.pressed : (isHovered ? Design.Colors.hover : Color.clear))
                )
                .scaleEffect(isPressed ? 0.95 : 1.0)
        }
        .buttonStyle(.plain)
        .onHover { isHovered = $0 }
        .pressEvents { isPressed = true } onRelease: { isPressed = false }
        .focusable()
        .accessibilityLabel(label)
        .accessibilityHint(hint ?? "Double-tap to activate \(label.lowercased())")
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier(label.lowercased().replacingOccurrences(of: " ", with: "-"))
    }
}

/// Press events modifier
extension View {
    func pressEvents(onPress: @escaping () -> Void, onRelease: @escaping () -> Void) -> some View {
        self.simultaneousGesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in onPress() }
                .onEnded { _ in onRelease() }
        )
    }
}

/// Consistent badge/pill component
struct Badge: View {
    let text: String
    let style: BadgeStyle

    enum BadgeStyle {
        case success, warning, error, neutral

        var backgroundColor: Color {
            switch self {
            case .success: return Design.Colors.success.opacity(0.15)
            case .warning: return Design.Colors.warning.opacity(0.15)
            case .error: return Design.Colors.error.opacity(0.15)
            case .neutral: return Design.Colors.secondaryBackground
            }
        }

        var textColor: Color {
            switch self {
            case .success: return Design.Colors.success
            case .warning: return Design.Colors.warning
            case .error: return Design.Colors.error
            case .neutral: return Design.Colors.secondaryText
            }
        }

        var accessibilityDescription: String {
            switch self {
            case .success: return "success"
            case .warning: return "warning"
            case .error: return "error"
            case .neutral: return "status"
            }
        }
    }

    var body: some View {
        Text(text)
            .font(Design.Typography.labelSmall)
            .foregroundColor(style.textColor)
            .padding(.horizontal, Design.Spacing.sm)
            .padding(.vertical, Design.Spacing.xxs)
            .background(
                Capsule()
                    .fill(style.backgroundColor)
            )
            .accessibilityLabel("\(text), \(style.accessibilityDescription)")
    }
}

/// Consistent divider with optional label
struct LabeledDivider: View {
    let label: String?

    init(_ label: String? = nil) {
        self.label = label
    }

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Rectangle()
                .fill(Design.Colors.separator)
                .frame(height: 1)

            if let label = label {
                Text(label)
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.tertiaryText)

                Rectangle()
                    .fill(Design.Colors.separator)
                    .frame(height: 1)
            }
        }
    }
}

/// Loading indicator with optional label
struct LoadingView: View {
    let label: String?

    init(_ label: String? = nil) {
        self.label = label
    }

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            ProgressView()
                .scaleEffect(0.8)

            if let label = label {
                Text(label)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(label ?? "Loading")
        .accessibilityAddTraits(.updatesFrequently)
    }
}

/// Empty state view with animated appearance
struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    let action: (() -> Void)?
    let actionLabel: String?

    @State private var isAppeared = false
    @State private var iconFloat = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(
        icon: String,
        title: String,
        message: String,
        action: (() -> Void)? = nil,
        actionLabel: String? = nil
    ) {
        self.icon = icon
        self.title = title
        self.message = message
        self.action = action
        self.actionLabel = actionLabel
    }

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            ZStack {
                // Subtle background glow
                Circle()
                    .fill(Color.accentColor.opacity(0.08))
                    .frame(width: Design.IconSize.hero + 40, height: Design.IconSize.hero + 40)
                    .blur(radius: 10)
                    .scaleEffect(iconFloat ? 1.1 : 1.0)

                Image(systemName: icon)
                    .font(.system(size: Design.IconSize.hero))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Design.Colors.tertiaryText, Design.Colors.tertiaryText.opacity(0.6)],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .offset(y: iconFloat ? -3 : 3)
            }
            .opacity(isAppeared ? 1 : 0)
            .scaleEffect(isAppeared ? 1 : 0.8)

            VStack(spacing: Design.Spacing.xs) {
                Text(title)
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.primaryText)

                Text(message)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
            }
            .opacity(isAppeared ? 1 : 0)
            .offset(y: isAppeared ? 0 : 10)

            if let action = action, let label = actionLabel {
                Button(action: action) {
                    Text(label)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
                .opacity(isAppeared ? 1 : 0)
                .scaleEffect(isAppeared ? 1 : 0.9)
                .accessibilityLabel(label)
                .accessibilityHint("Double-tap to \(label.lowercased())")
            }
        }
        .padding(Design.Spacing.xxxl)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(title). \(message)")
        .onAppear {
            guard !reduceMotion else {
                isAppeared = true
                return
            }
            withAnimation(Design.Animation.stateChange.delay(0.1)) {
                isAppeared = true
            }
            withAnimation(Design.Animation.gentle.repeatForever(autoreverses: true)) {
                iconFloat = true
            }
        }
    }
}

// MARK: - Shimmer Loading Effect

struct ShimmerModifier: ViewModifier {
    @State private var phase: CGFloat = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .overlay(
                GeometryReader { geometry in
                    if !reduceMotion {
                        LinearGradient(
                            colors: [
                                Color.clear,
                                Color.white.opacity(0.3),
                                Color.clear
                            ],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                        .frame(width: geometry.size.width * 0.6)
                        .offset(x: phase * geometry.size.width * 1.6 - geometry.size.width * 0.3)
                        .mask(content)
                    }
                }
            )
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(Design.Animation.shimmer) {
                    phase = 1
                }
            }
    }
}

extension View {
    func shimmer() -> some View {
        modifier(ShimmerModifier())
    }
}

// MARK: - Pulse Animation Effect

struct PulseModifier: ViewModifier {
    let isActive: Bool
    @State private var scale: CGFloat = 1.0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .scaleEffect(scale)
            .onChange(of: isActive) { _, newValue in
                guard !reduceMotion else { return }
                if newValue {
                    withAnimation(Design.Animation.bouncy) {
                        scale = 1.15
                    }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                        withAnimation(Design.Animation.spring) {
                            scale = 1.0
                        }
                    }
                }
            }
    }
}

extension View {
    func pulse(when active: Bool) -> some View {
        modifier(PulseModifier(isActive: active))
    }
}

// MARK: - State Transition View

struct StateTransitionView<Content: View>: View {
    let content: Content
    let transitionId: AnyHashable

    @State private var isVisible = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(id: AnyHashable, @ViewBuilder content: () -> Content) {
        self.transitionId = id
        self.content = content()
    }

    var body: some View {
        content
            .opacity(isVisible ? 1 : 0)
            .scaleEffect(isVisible ? 1 : 0.95)
            .offset(y: isVisible ? 0 : 5)
            .onAppear {
                guard !reduceMotion else {
                    isVisible = true
                    return
                }
                withAnimation(Design.Animation.stateChange) {
                    isVisible = true
                }
            }
            .onChange(of: transitionId) { _, _ in
                guard !reduceMotion else { return }
                isVisible = false
                withAnimation(Design.Animation.stateChange) {
                    isVisible = true
                }
            }
    }
}

// MARK: - Status Indicator with Animation

struct AnimatedStatusIndicator: View {
    let isActive: Bool
    let activeColor: Color
    let inactiveColor: Color

    @State private var isPulsing = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(
        isActive: Bool,
        activeColor: Color = Design.Colors.success,
        inactiveColor: Color = Design.Colors.tertiaryText
    ) {
        self.isActive = isActive
        self.activeColor = activeColor
        self.inactiveColor = inactiveColor
    }

    var body: some View {
        ZStack {
            if isActive && !reduceMotion {
                Circle()
                    .fill(activeColor.opacity(0.3))
                    .frame(width: 12, height: 12)
                    .scaleEffect(isPulsing ? 1.5 : 1.0)
                    .opacity(isPulsing ? 0 : 0.5)
            }

            Circle()
                .fill(isActive ? activeColor : inactiveColor.opacity(0.5))
                .frame(width: 8, height: 8)
        }
        .frame(width: 16, height: 16)
        .onChange(of: isActive) { _, newValue in
            guard !reduceMotion else { return }
            if newValue {
                withAnimation(Design.Animation.pulse) {
                    isPulsing = true
                }
            } else {
                isPulsing = false
            }
        }
        .onAppear {
            if isActive && !reduceMotion {
                withAnimation(Design.Animation.pulse) {
                    isPulsing = true
                }
            }
        }
    }
}

// MARK: - Success Checkmark Animation

struct AnimatedCheckmark: View {
    let isShowing: Bool

    @State private var trimEnd: CGFloat = 0
    @State private var scale: CGFloat = 0.8
    @State private var opacity: Double = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            Circle()
                .fill(Design.Colors.success.opacity(0.15))
                .scaleEffect(scale)

            Circle()
                .stroke(Design.Colors.success, lineWidth: 2)
                .scaleEffect(scale)

            Path { path in
                path.move(to: CGPoint(x: 8, y: 16))
                path.addLine(to: CGPoint(x: 14, y: 22))
                path.addLine(to: CGPoint(x: 26, y: 10))
            }
            .trim(from: 0, to: trimEnd)
            .stroke(Design.Colors.success, style: StrokeStyle(lineWidth: 2.5, lineCap: .round, lineJoin: .round))
        }
        .frame(width: 32, height: 32)
        .opacity(opacity)
        .onChange(of: isShowing) { _, newValue in
            if newValue {
                animateIn()
            } else {
                animateOut()
            }
        }
        .onAppear {
            if isShowing {
                animateIn()
            }
        }
    }

    private func animateIn() {
        if reduceMotion {
            trimEnd = 1
            scale = 1
            opacity = 1
            return
        }
        withAnimation(Design.Animation.spring) {
            scale = 1
            opacity = 1
        }
        withAnimation(Design.Animation.spring.delay(0.1)) {
            trimEnd = 1
        }
    }

    private func animateOut() {
        if reduceMotion {
            trimEnd = 0
            scale = 0.8
            opacity = 0
            return
        }
        withAnimation(Design.Animation.fast) {
            trimEnd = 0
            opacity = 0
            scale = 0.8
        }
    }
}

// MARK: - Loading Skeleton View

struct SkeletonView: View {
    let width: CGFloat?
    let height: CGFloat

    @State private var isAnimating = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(width: CGFloat? = nil, height: CGFloat = 16) {
        self.width = width
        self.height = height
    }

    var body: some View {
        RoundedRectangle(cornerRadius: Design.Radius.xs)
            .fill(
                LinearGradient(
                    colors: reduceMotion
                        ? [Design.Colors.separator]
                        : [
                            Design.Colors.separator.opacity(0.5),
                            Design.Colors.separator,
                            Design.Colors.separator.opacity(0.5)
                        ],
                    startPoint: isAnimating ? .trailing : .leading,
                    endPoint: isAnimating ? .leading : .trailing
                )
            )
            .frame(width: width, height: height)
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(Design.Animation.shimmer) {
                    isAnimating = true
                }
            }
    }
}

// MARK: - Appear Animation Modifier

struct AppearAnimationModifier: ViewModifier {
    let delay: Double
    @State private var isVisible = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .opacity(isVisible ? 1 : 0)
            .offset(y: isVisible ? 0 : 8)
            .onAppear {
                guard !reduceMotion else {
                    isVisible = true
                    return
                }
                withAnimation(Design.Animation.stateChange.delay(delay)) {
                    isVisible = true
                }
            }
    }
}

extension View {
    func appearAnimation(delay: Double = 0) -> some View {
        modifier(AppearAnimationModifier(delay: delay))
    }
}

// MARK: - Error Banner

/// A banner for displaying errors with optional retry action
struct ErrorBanner: View {
    let title: String
    let message: String
    let suggestion: String?
    let isRetryable: Bool
    let onRetry: (() -> Void)?
    let onDismiss: () -> Void

    @State private var isExpanded = false
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor

    init(
        title: String,
        message: String,
        suggestion: String? = nil,
        isRetryable: Bool = false,
        onRetry: (() -> Void)? = nil,
        onDismiss: @escaping () -> Void
    ) {
        self.title = title
        self.message = message
        self.suggestion = suggestion
        self.isRetryable = isRetryable
        self.onRetry = onRetry
        self.onDismiss = onDismiss
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Design.Spacing.sm) {
            // Header row
            HStack(spacing: Design.Spacing.sm) {
                // Error icon
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: Design.IconSize.md))
                    .foregroundColor(Design.Colors.error)

                // Title
                Text(title)
                    .font(Design.Typography.headlineSmall)
                    .foregroundColor(Design.Colors.primaryText)

                Spacer()

                // Expand/collapse button if there's a suggestion
                if suggestion != nil {
                    Button(action: { withAnimation { isExpanded.toggle() } }) {
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(Design.Colors.secondaryText)
                    }
                    .buttonStyle(.plain)
                }

                // Dismiss button
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(Design.Colors.secondaryText)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Dismiss error")
            }

            // Message
            Text(message)
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.secondaryText)
                .fixedSize(horizontal: false, vertical: true)

            // Suggestion (expanded)
            if isExpanded, let suggestion = suggestion {
                HStack(spacing: Design.Spacing.xs) {
                    Image(systemName: "lightbulb")
                        .font(.system(size: Design.IconSize.xs))
                        .foregroundColor(Design.Colors.warning)
                    Text(suggestion)
                        .font(Design.Typography.labelSmall)
                        .foregroundColor(Design.Colors.tertiaryText)
                }
                .padding(Design.Spacing.sm)
                .background(Design.Colors.secondaryBackground)
                .cornerRadius(Design.Radius.sm)
            }

            // Actions
            if isRetryable && onRetry != nil {
                HStack {
                    Spacer()
                    Button(action: { onRetry?() }) {
                        HStack(spacing: Design.Spacing.xxs) {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 10))
                            Text("Try Again")
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(Design.Spacing.md)
        .background(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .fill(Design.Colors.error.opacity(0.1))
        )
        .overlay(
            RoundedRectangle(cornerRadius: Design.Radius.md, style: .continuous)
                .strokeBorder(Design.Colors.error.opacity(0.3), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Error: \(title). \(message)")
        .accessibilityHint(isRetryable ? "Double-tap to retry" : "")
    }
}

/// A compact inline error message
struct InlineError: View {
    let message: String
    let onRetry: (() -> Void)?

    init(_ message: String, onRetry: (() -> Void)? = nil) {
        self.message = message
        self.onRetry = onRetry
    }

    var body: some View {
        HStack(spacing: Design.Spacing.xs) {
            Image(systemName: "exclamationmark.circle.fill")
                .font(.system(size: Design.IconSize.xs))
                .foregroundColor(Design.Colors.error)

            Text(message)
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.error)
                .lineLimit(2)

            if let onRetry = onRetry {
                Spacer()
                Button(action: onRetry) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 10))
                }
                .buttonStyle(.plain)
                .foregroundColor(Design.Colors.error)
            }
        }
        .padding(Design.Spacing.sm)
        .background(Design.Colors.error.opacity(0.1))
        .cornerRadius(Design.Radius.sm)
    }
}

/// A warning banner (less severe than error)
struct WarningBanner: View {
    let message: String
    let action: (() -> Void)?
    let actionLabel: String?
    let onDismiss: (() -> Void)?

    init(
        _ message: String,
        action: (() -> Void)? = nil,
        actionLabel: String? = nil,
        onDismiss: (() -> Void)? = nil
    ) {
        self.message = message
        self.action = action
        self.actionLabel = actionLabel
        self.onDismiss = onDismiss
    }

    var body: some View {
        HStack(spacing: Design.Spacing.sm) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: Design.IconSize.sm))
                .foregroundColor(Design.Colors.warning)

            Text(message)
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.primaryText)

            Spacer()

            if let action = action, let label = actionLabel {
                Button(action: action) {
                    Text(label)
                        .font(Design.Typography.labelSmall)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            if let onDismiss = onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(Design.Colors.secondaryText)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(Design.Spacing.md)
        .background(Design.Colors.warning.opacity(0.1))
        .cornerRadius(Design.Radius.md)
    }
}

/// CLI not available error view
struct CliNotAvailableView: View {
    let errorMessage: String

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: Design.IconSize.hero))
                .foregroundColor(Design.Colors.error)

            VStack(spacing: Design.Spacing.sm) {
                Text("Witnessd CLI Not Available")
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.primaryText)

                Text(errorMessage)
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)

                Text("Try reinstalling the application.")
                    .font(Design.Typography.labelSmall)
                    .foregroundColor(Design.Colors.tertiaryText)
                    .padding(.top, Design.Spacing.xs)
            }
        }
        .padding(Design.Spacing.xxxl)
    }
}

/// Accessibility permission required view
struct AccessibilityPermissionView: View {
    let onOpenSettings: () -> Void
    let onDismiss: (() -> Void)?

    var body: some View {
        VStack(spacing: Design.Spacing.lg) {
            Image(systemName: "hand.raised.circle.fill")
                .font(.system(size: Design.IconSize.hero))
                .foregroundStyle(Design.Colors.brandGradient)

            VStack(spacing: Design.Spacing.sm) {
                Text("Accessibility Permission Required")
                    .font(Design.Typography.headlineMedium)
                    .foregroundColor(Design.Colors.primaryText)

                Text("The sentinel needs accessibility permissions to track which document you are working on.")
                    .font(Design.Typography.bodySmall)
                    .foregroundColor(Design.Colors.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(spacing: Design.Spacing.sm) {
                Button(action: onOpenSettings) {
                    HStack(spacing: Design.Spacing.xs) {
                        Image(systemName: "gear")
                        Text("Open System Settings")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

                if let onDismiss = onDismiss {
                    Button("Not Now", action: onDismiss)
                        .buttonStyle(.plain)
                        .foregroundColor(Design.Colors.secondaryText)
                }
            }

            // Instructions
            VStack(alignment: .leading, spacing: Design.Spacing.xs) {
                Text("How to enable:")
                    .font(Design.Typography.labelMedium)
                    .foregroundColor(Design.Colors.secondaryText)

                VStack(alignment: .leading, spacing: Design.Spacing.xxs) {
                    instructionRow(number: 1, text: "Open System Settings")
                    instructionRow(number: 2, text: "Go to Privacy & Security")
                    instructionRow(number: 3, text: "Select Accessibility")
                    instructionRow(number: 4, text: "Enable Witnessd")
                }
            }
            .padding(Design.Spacing.md)
            .background(Design.Colors.secondaryBackground)
            .cornerRadius(Design.Radius.md)
        }
        .padding(Design.Spacing.xl)
    }

    private func instructionRow(number: Int, text: String) -> some View {
        HStack(spacing: Design.Spacing.sm) {
            Text("\(number)")
                .font(Design.Typography.labelSmall)
                .foregroundColor(Design.Colors.tertiaryText)
                .frame(width: 16, height: 16)
                .background(Design.Colors.separator)
                .clipShape(Circle())

            Text(text)
                .font(Design.Typography.bodySmall)
                .foregroundColor(Design.Colors.primaryText)
        }
    }
}
