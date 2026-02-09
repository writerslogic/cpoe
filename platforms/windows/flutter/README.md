# Witnessd Windows App (Flutter)

A Windows system tray application for Witnessd, built with Flutter using the Fluent UI design system to match Windows 11's design language.

## Features

- **System Tray Integration**: Runs in the system tray with quick access to sentinel controls
- **Windows 11 Design**: Uses Fluent UI for native Windows 11 look and feel
- **Sentinel Management**: Start/stop document tracking with one click
- **Status Dashboard**: View tracked documents, keystroke counts, and system status
- **Quick Actions**: Create checkpoints, export evidence, and verify files
- **Settings**: Configure auto-checkpoint intervals, file patterns, and more
- **Document History**: Browse all tracked documents with export and verify options

## Requirements

- Windows 10 (1903) or later / Windows 11
- Flutter 3.0 or later
- Visual Studio 2022 with C++ desktop development workload
- CMake 3.14 or later

## Building

### Prerequisites

1. Install Flutter: https://docs.flutter.dev/get-started/install/windows
2. Install Visual Studio 2022 with:
   - Desktop development with C++
   - Windows 10 or 11 SDK
3. Ensure `witnessd.exe` is built and available

### Build Steps

```powershell
# Navigate to this directory
cd platforms/windows/flutter

# Get dependencies
flutter pub get

# Generate JSON serialization code (if needed)
flutter pub run build_runner build

# Build the app
flutter build windows --release

# The built app will be in build/windows/runner/Release/
```

### Development

```powershell
# Run in debug mode
flutter run -d windows
```

## Project Structure

```
lib/
  app/
    app.dart              # Main app widget
  models/
    witness_status.dart   # Data models
    settings.dart         # Settings model
  screens/
    main_screen.dart      # Home screen
    settings_screen.dart  # Settings tabs
    history_screen.dart   # Document history
  services/
    witnessd_bridge.dart  # CLI communication
    witnessd_service.dart # State management
    tray_service.dart     # System tray
  theme/
    windows_theme.dart    # Windows 11 theming
  widgets/
    header_bar.dart       # App header
    sentinel_card.dart    # Sentinel controls
    quick_actions.dart    # Action buttons
    system_status.dart    # Status indicators
```

## Architecture

### CLI Bridge

The app communicates with the `witnessd` CLI executable using Dart's `Process` API. Commands are executed asynchronously and their output is parsed to update the application state.

Key operations:
- `witnessd init` - Initialize the data directory
- `witnessd calibrate` - Calibrate VDF timing proofs
- `witnessd sentinel start/stop` - Control automatic tracking
- `witnessd track start/stop` - Manual document tracking
- `witnessd commit` - Create checkpoints
- `witnessd export` - Export evidence files
- `witnessd verify` - Verify evidence integrity

### State Management

Uses Riverpod for state management with two main providers:
- `witnessdServiceProvider` - Main application state
- `trayServiceProvider` - System tray state

### System Tray

The system tray integration uses the `system_tray` Flutter package with:
- Left-click: Show/hide main window
- Right-click: Context menu with quick actions
- Tooltip: Shows current status

## Configuration

The app stores settings in Windows AppData using `shared_preferences`:

| Setting | Description | Default |
|---------|-------------|---------|
| `openAtLogin` | Start app on login | false |
| `autoCheckpoint` | Auto-create checkpoints | false |
| `checkpointIntervalMinutes` | Checkpoint interval | 30 |
| `includePatterns` | File extensions to track | .txt, .md, .rtf, .doc, .docx |
| `debounceIntervalMs` | Keystroke debounce | 500 |
| `showNotifications` | Show toast notifications | true |

## Packaging

For distribution, the app can be packaged with:

1. **MSIX Package** (Microsoft Store):
   ```powershell
   flutter pub run msix:create
   ```

2. **Portable/Installer**: Copy the build output with `witnessd.exe`

## Troubleshooting

### witnessd.exe not found

Ensure `witnessd.exe` is in one of these locations:
- Same directory as the Flutter app executable
- In system PATH
- In `%PROGRAMFILES%\Witnessd\`
- In `%LOCALAPPDATA%\Witnessd\`

### TPM not available

TPM availability depends on your hardware and Windows configuration. The app will work without TPM, but enhanced attestation features will be disabled.

### VDF calibration fails

VDF calibration requires a few seconds of CPU time. If it fails:
1. Ensure no heavy processes are running
2. Try running as administrator
3. Check `witnessd status` in a terminal

## License

See the main project LICENSE file.
