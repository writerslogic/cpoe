import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

ExternalLibrary? tryLoadRustLibrary() {
  final candidates = <String>[];
  final env = Platform.environment;

  final explicit = env['WITNESSD_RUST_LIB'];
  if (explicit != null && explicit.isNotEmpty) {
    candidates.add(explicit);
  }

  final devRoot = env['WITNESSD_DEV_ROOT'];
  if (devRoot != null && devRoot.isNotEmpty) {
    candidates.add(
      '$devRoot/rust/witnessd-core/target/debug/libwitnessd_core.dylib',
    );
    candidates.add(
      '$devRoot/rust/witnessd-core/target/release/libwitnessd_core.dylib',
    );
  }

  if (Platform.isMacOS) {
    final exe = File(Platform.resolvedExecutable);
    final contentsDir = exe.parent.parent;
    candidates.add(
      '${contentsDir.path}/Frameworks/witnessd_core.framework/witnessd_core',
    );
    candidates.add(
      '${contentsDir.path}/MacOS/witnessd_core.framework/witnessd_core',
    );
  }
  if (Platform.isWindows) {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    candidates.add('$exeDir/witnessd_core.dll');
  }

  final cwd = Directory.current.path;
  candidates.add(
    '$cwd/../rust/witnessd-core/target/debug/libwitnessd_core.dylib',
  );
  candidates.add(
    '$cwd/../rust/witnessd-core/target/release/libwitnessd_core.dylib',
  );
  candidates.add('$cwd/rust/witnessd-core/target/debug/libwitnessd_core.dylib');
  candidates.add(
    '$cwd/rust/witnessd-core/target/release/libwitnessd_core.dylib',
  );
  candidates.add('$cwd/../rust/witnessd-core/target/debug/witnessd_core.dll');
  candidates.add('$cwd/../rust/witnessd-core/target/release/witnessd_core.dll');
  candidates.add('$cwd/rust/witnessd-core/target/debug/witnessd_core.dll');
  candidates.add('$cwd/rust/witnessd-core/target/release/witnessd_core.dll');

  if (kDebugMode) {
    final home = env['HOME'];
    if (home != null && home.isNotEmpty) {
      candidates.add(
        '$home/Workspace/witnessd-rust/rust/witnessd-core/target/debug/libwitnessd_core.dylib',
      );
      candidates.add(
        '$home/Workspace/witnessd-rust/rust/witnessd-core/target/debug/witnessd_core.dll',
      );
    }
  }

  for (final path in candidates) {
    if (File(path).existsSync()) {
      return ExternalLibrary.open(path);
    }
  }

  return null;
}
