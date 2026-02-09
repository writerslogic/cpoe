import 'package:fluent_ui/fluent_ui.dart';

/// Windows 11 design language theme for Witnessd
class WindowsTheme {
  // Windows 11 accent colors
  static const Color _accentLight = Color(0xFF0078D4);
  static const Color _accentDark = Color(0xFF60CDFF);

  // Status colors
  static const Color success = Color(0xFF0F7B0F);
  static const Color successDark = Color(0xFF6CCB5F);
  static const Color warning = Color(0xFFF7630C);
  static const Color warningDark = Color(0xFFFFB900);
  static const Color error = Color(0xFFC42B1C);
  static const Color errorDark = Color(0xFFFF99A4);

  // Spacing system (Windows 11 uses 4px base unit)
  static const double spacingXXS = 2.0;
  static const double spacingXS = 4.0;
  static const double spacingSM = 8.0;
  static const double spacingMD = 12.0;
  static const double spacingLG = 16.0;
  static const double spacingXL = 24.0;
  static const double spacingXXL = 32.0;

  // Corner radius (Windows 11)
  static const double radiusXS = 2.0;
  static const double radiusSM = 4.0;
  static const double radiusMD = 8.0;
  static const double radiusLG = 12.0;
  static const double radiusXL = 16.0;

  // Icon sizes
  static const double iconXS = 12.0;
  static const double iconSM = 16.0;
  static const double iconMD = 20.0;
  static const double iconLG = 24.0;
  static const double iconXL = 32.0;
  static const double iconHero = 48.0;

  static FluentThemeData get lightTheme {
    return FluentThemeData(
      brightness: Brightness.light,
      accentColor: AccentColor.swatch({
        'normal': _accentLight,
        'dark': const Color(0xFF005A9E),
        'darker': const Color(0xFF004578),
        'darkest': const Color(0xFF003054),
        'light': const Color(0xFF2B88D8),
        'lighter': const Color(0xFF71AFE5),
        'lightest': const Color(0xFFB7D4F0),
      }),
      scaffoldBackgroundColor: const Color(0xFFF3F3F3),
      cardColor: Colors.white,
      shadowColor: Colors.black.withOpacity(0.1),
      typography: _typography,
      visualDensity: VisualDensity.standard,
    );
  }

  static FluentThemeData get darkTheme {
    return FluentThemeData(
      brightness: Brightness.dark,
      accentColor: AccentColor.swatch({
        'normal': _accentDark,
        'dark': const Color(0xFF40B8E0),
        'darker': const Color(0xFF20A4C4),
        'darkest': const Color(0xFF0090A8),
        'light': const Color(0xFF80D8F0),
        'lighter': const Color(0xFFA0E4F8),
        'lightest': const Color(0xFFC0F0FF),
      }),
      scaffoldBackgroundColor: const Color(0xFF202020),
      cardColor: const Color(0xFF2D2D2D),
      shadowColor: Colors.black.withOpacity(0.3),
      typography: _typography,
      visualDensity: VisualDensity.standard,
    );
  }

  static Typography get _typography {
    return const Typography.raw(
      display: TextStyle(
        fontSize: 68,
        fontWeight: FontWeight.w600,
        fontFamily: 'Segoe UI Variable',
      ),
      titleLarge: TextStyle(
        fontSize: 40,
        fontWeight: FontWeight.w600,
        fontFamily: 'Segoe UI Variable',
      ),
      title: TextStyle(
        fontSize: 28,
        fontWeight: FontWeight.w600,
        fontFamily: 'Segoe UI Variable',
      ),
      subtitle: TextStyle(
        fontSize: 20,
        fontWeight: FontWeight.w600,
        fontFamily: 'Segoe UI Variable',
      ),
      bodyLarge: TextStyle(
        fontSize: 18,
        fontWeight: FontWeight.w400,
        fontFamily: 'Segoe UI Variable',
      ),
      bodyStrong: TextStyle(
        fontSize: 14,
        fontWeight: FontWeight.w600,
        fontFamily: 'Segoe UI Variable',
      ),
      body: TextStyle(
        fontSize: 14,
        fontWeight: FontWeight.w400,
        fontFamily: 'Segoe UI Variable',
      ),
      caption: TextStyle(
        fontSize: 12,
        fontWeight: FontWeight.w400,
        fontFamily: 'Segoe UI Variable',
      ),
    );
  }
}

/// Extension for consistent spacing
extension SpacingExtension on BuildContext {
  double get spacingXXS => WindowsTheme.spacingXXS;
  double get spacingXS => WindowsTheme.spacingXS;
  double get spacingSM => WindowsTheme.spacingSM;
  double get spacingMD => WindowsTheme.spacingMD;
  double get spacingLG => WindowsTheme.spacingLG;
  double get spacingXL => WindowsTheme.spacingXL;
  double get spacingXXL => WindowsTheme.spacingXXL;
}
