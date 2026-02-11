import 'package:flutter/material.dart';

class WitnessdTheme {
  // Authoritative, neutral palette
  static const Color darkBackground = Color(0xFF0E1116);
  static const Color surface = Color(0xFF171B22);
  static const Color surfaceElevated = Color(0xFF1D2330);
  static const Color accentBlue = Color(0xFF1E6FFF);
  static const Color secureGreen = Color(0xFF3CCB7F);
  static const Color warningRed = Color(0xFFE35B5B);
  static const Color mutedText = Color(0xFF8C96A3);
  static const Color strongText = Color(0xFFECEFF4);

  static ThemeData get dark {
    final base = ThemeData.dark();
    const displayFont = 'SF Pro Display';
    const textFont = 'SF Pro Text';
    final textTheme = base.textTheme
        .apply(
          fontFamily: textFont,
          displayColor: strongText,
          bodyColor: strongText,
        )
        .copyWith(
          displayLarge: const TextStyle(
            color: strongText,
            fontWeight: FontWeight.w700,
            letterSpacing: -0.5,
          ),
          displayMedium: const TextStyle(
            color: strongText,
            fontWeight: FontWeight.w700,
          ),
          titleLarge: const TextStyle(
            color: strongText,
            fontWeight: FontWeight.w600,
          ),
          bodyMedium: const TextStyle(
            color: strongText,
            fontWeight: FontWeight.w500,
          ),
          bodySmall: const TextStyle(
            color: mutedText,
            fontWeight: FontWeight.w500,
          ),
        );

    return base.copyWith(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: darkBackground,
      colorScheme: const ColorScheme.dark(
        primary: accentBlue,
        surface: surface,
        onSurface: strongText,
        secondary: secureGreen,
        error: warningRed,
      ),
      textTheme: textTheme,
      appBarTheme: AppBarTheme(
        backgroundColor: surface,
        foregroundColor: strongText,
        titleTextStyle: textTheme.titleLarge,
        elevation: 0,
      ),
      cardTheme: CardThemeData(
        color: surfaceElevated,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        elevation: 0,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: surface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(14),
          borderSide: BorderSide.none,
        ),
        hintStyle: const TextStyle(color: mutedText),
        labelStyle: const TextStyle(color: mutedText),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: accentBlue,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          textStyle: const TextStyle(fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: strongText,
          side: BorderSide(color: mutedText.withOpacity(0.3)),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: accentBlue,
          textStyle: const TextStyle(fontWeight: FontWeight.w600),
        ),
      ),
      sliderTheme: base.sliderTheme.copyWith(
        activeTrackColor: accentBlue,
        inactiveTrackColor: surface,
        thumbColor: accentBlue,
      ),
      switchTheme: base.switchTheme.copyWith(
        thumbColor: WidgetStatePropertyAll(accentBlue),
        trackColor: WidgetStatePropertyAll(accentBlue.withOpacity(0.4)),
      ),
      dividerColor: surface,
    );
  }
}
