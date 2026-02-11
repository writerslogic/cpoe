import 'dart:math';
import 'package:flutter/material.dart';
import '../theme.dart';

class HeartbeatGraph extends StatefulWidget {
  final List<double> primary;
  final List<double> secondary;

  const HeartbeatGraph({
    super.key,
    this.primary = const [],
    this.secondary = const [],
  });

  @override
  State<HeartbeatGraph> createState() => _HeartbeatGraphState();
}

class _HeartbeatGraphState extends State<HeartbeatGraph>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final hasData =
        widget.primary.any((v) => v > 0) || widget.secondary.any((v) => v > 0);
    return Container(
      decoration: BoxDecoration(
        color: WitnessdTheme.darkBackground,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: WitnessdTheme.accentBlue.withOpacity(0.1)),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(24),
        child: Stack(
          children: [
            AnimatedBuilder(
              animation: _controller,
              builder: (context, child) {
                return CustomPaint(
                  painter: _PulsePainter(
                    _controller.value,
                    widget.primary,
                    widget.secondary,
                  ),
                  child: Container(),
                );
              },
            ),
            Positioned.fill(
              child: IgnorePointer(child: CustomPaint(painter: _GridPainter())),
            ),
            if (!hasData)
              const Center(
                child: Text(
                  'Waiting for activity…',
                  style: TextStyle(color: WitnessdTheme.mutedText),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _PulsePainter extends CustomPainter {
  final double animationValue;
  final List<double> primary;
  final List<double> secondary;

  _PulsePainter(this.animationValue, this.primary, this.secondary);

  @override
  void paint(Canvas canvas, Size size) {
    final background = Paint()..color = WitnessdTheme.darkBackground;
    canvas.drawRect(Offset.zero & size, background);

    _drawSeries(canvas, size, primary, WitnessdTheme.accentBlue);
    if (secondary.isNotEmpty) {
      _drawSeries(
        canvas,
        size,
        secondary,
        WitnessdTheme.secureGreen.withOpacity(0.9),
      );
    }

    final scanX = size.width * animationValue;
    final scanPaint = Paint()
      ..color = WitnessdTheme.accentBlue.withOpacity(0.18)
      ..strokeWidth = 1;

    canvas.drawLine(Offset(scanX, 0), Offset(scanX, size.height), scanPaint);
  }

  void _drawSeries(Canvas canvas, Size size, List<double> series, Color color) {
    if (series.isEmpty) return;

    final glow = Paint()
      ..color = color.withOpacity(0.15)
      ..strokeWidth = 6
      ..style = PaintingStyle.stroke
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8);

    final paint = Paint()
      ..color = color.withOpacity(0.85)
      ..strokeWidth = 2.5
      ..style = PaintingStyle.stroke;

    final maxVal = series.reduce(max);
    final minVal = series.reduce(min);
    final range = max(1.0, maxVal - minVal);

    final path = Path();
    for (int i = 0; i < series.length; i++) {
      final x = size.width * (i / max(1, series.length - 1));
      final normalized = (series[i] - minVal) / range;
      final y = size.height - (normalized * size.height);
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }

    canvas.drawPath(path, glow);
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant _PulsePainter oldDelegate) =>
      oldDelegate.primary != primary ||
      oldDelegate.secondary != secondary ||
      oldDelegate.animationValue != animationValue;
}

class _GridPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.white.withOpacity(0.03)
      ..strokeWidth = 1;

    const rows = 4;
    const cols = 6;
    for (int i = 1; i < rows; i++) {
      final y = size.height * (i / rows);
      canvas.drawLine(Offset(0, y), Offset(size.width, y), paint);
    }
    for (int i = 1; i < cols; i++) {
      final x = size.width * (i / cols);
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
    }
  }

  @override
  bool shouldRepaint(covariant _GridPainter oldDelegate) => false;
}
