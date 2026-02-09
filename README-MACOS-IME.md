# Witnessd macOS Input Method - App Store Distribution Guide

This document provides comprehensive architecture documentation and App Store submission guidance for the Witnessd Input Method on macOS.

## Overview

Witnessd IME is a macOS Input Method that creates cryptographic proof of authorship by capturing typing patterns. Unlike the standard Witnessd app (which uses CGEventTap and requires Accessibility permissions), this version uses Apple's Input Method Kit (IMK) framework, making it suitable for Mac App Store distribution.

## Architecture

### High-Level Architecture

```
+------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |
|   User Typing    +---->+   WitnessdIME    +---->+   Witnessd       |
|                  |     |   (IME Bundle)   |     |   Daemon (XPC)   |
|                  |     |                  |     |                  |
+------------------+     +--------+---------+     +--------+---------+
                                  |                        |
                                  v                        v
                         +--------+---------+     +--------+---------+
                         |                  |     |                  |
                         |   Go Engine      |     |   Evidence       |
                         |   (libwitnessd)  |     |   Storage        |
                         |                  |     |                  |
                         +------------------+     +------------------+
```

### Component Structure

```
platforms/macos/WitnessdIME/
├── WitnessdIME.xcodeproj/          # Xcode project
│   └── project.pbxproj
├── WitnessdIME/
│   ├── objc/                        # Objective-C IMK implementation
│   │   ├── main.m                   # Entry point (IMKServer setup)
│   │   ├── WitnessdInputController.h
│   │   ├── WitnessdInputController.m
│   │   ├── WitnessdInputController+Enhanced.h
│   │   └── WitnessdInputController+Enhanced.m
│   ├── Swift/                       # Swift UI components
│   │   └── WitnessdIMEApp.swift     # Status bar, preferences, onboarding
│   ├── XPC/                         # XPC communication layer
│   │   ├── WitnessdXPCProtocol.h
│   │   ├── WitnessdXPCClient.h
│   │   └── WitnessdXPCClient.m
│   ├── Assets.xcassets/             # App icons
│   ├── Info.plist                   # Bundle configuration
│   ├── WitnessdIME.entitlements     # Sandbox entitlements
│   └── PrivacyInfo.xcprivacy        # Privacy manifest
├── WitnessdIMETests/                # Unit and integration tests
│   ├── WitnessdInputControllerTests.m
│   ├── WitnessdXPCClientTests.m
│   └── Info.plist
├── scripts/
│   └── build-go-library.sh          # Go static library build script
└── README.md                        # Project-specific readme
```

## Input Method Kit Integration

### IMKInputController

The `WitnessdInputController` class is the core of the IME implementation:

```objc
@interface WitnessdInputController : IMKInputController

// Track current client
@property (nonatomic, strong) id currentClient;
@property (nonatomic, copy) NSString* currentBundleID;
@property (nonatomic, copy) NSString* currentDocID;

// Composition state
@property (nonatomic, copy) NSString* composingText;

@end
```

### Key Methods

| Method | Purpose |
|--------|---------|
| `initWithServer:delegate:client:` | Initialize controller, start session |
| `handleEvent:client:` | Process key events, apply jitter |
| `inputText:client:` | Handle direct text input (paste) |
| `activateServer:` | Called when IME is selected |
| `deactivateServer:` | Called when IME is deselected |
| `commitComposition:` | Finalize composed text |
| `menu` | Provide menu bar dropdown menu |

### Dead Key Handling

The enhanced controller supports international keyboards:

```objc
// Dead key states
typedef NS_ENUM(NSInteger, WitnessdDeadKeyState) {
    WitnessdDeadKeyStateNone = 0,
    WitnessdDeadKeyStateGrave,       // ` -> e = e
    WitnessdDeadKeyStateAcute,       // ' -> e = e
    WitnessdDeadKeyStateCircumflex,  // ^ -> e = e
    WitnessdDeadKeyStateTilde,       // ~ -> n = n
    WitnessdDeadKeyStateDieresis,    // " -> u = u
};
```

## XPC Communication

### Protocol Definition

```objc
@protocol WitnessdXPCProtocol <NSObject>

- (void)startSessionWithBundleIdentifier:(NSString *)bundleID
                      documentIdentifier:(NSString *)docID
                              withReply:(void (^)(BOOL, NSString *))reply;

- (void)endSessionWithReply:(void (^)(BOOL, NSString *))reply;

- (void)recordKeystrokeWithKeyCode:(uint16_t)keyCode
                          charCode:(int32_t)charCode
                         timestamp:(uint64_t)timestamp
                         withReply:(void (^)(int64_t))reply;

- (void)recordTextDeletionWithCount:(int)count;
- (void)recordTextCommit:(NSString *)text;

- (void)isSessionActiveWithReply:(void (^)(BOOL))reply;
- (void)getSampleCountWithReply:(void (^)(int))reply;
- (void)pingWithReply:(void (^)(BOOL))reply;

@end
```

### XPC Client

The `WitnessdXPCClient` manages the XPC connection:

- Singleton pattern for shared access
- Automatic reconnection on interruption
- Thread-safe operation
- Error handling with fallback

## Privacy and Security

### App Sandbox

The IME runs in the macOS App Sandbox with these entitlements:

```xml
<!-- App Sandbox -->
<key>com.apple.security.app-sandbox</key>
<true/>

<!-- File access for evidence storage -->
<key>com.apple.security.files.user-selected.read-write</key>
<true/>
<key>com.apple.security.files.downloads.read-write</key>
<true/>

<!-- Network for timestamp anchoring -->
<key>com.apple.security.network.client</key>
<true/>
```

### Privacy Manifest

Required for App Store submission (Spring 2024+):

- **NSPrivacyCollectedDataTypes**: Keystroke timing data
- **NSPrivacyTracking**: false (no tracking)
- **NSPrivacyAccessedAPITypes**: File timestamps, UserDefaults, System boot time

### Data Collection

| Data Type | Collected | Purpose |
|-----------|-----------|---------|
| Keystroke Content | No | N/A |
| Keystroke Timing | Yes | Authorship evidence |
| Typing Rhythm | Yes | Biometric fingerprint |
| Application Context | Yes | Session identification |

## Building

### Prerequisites

1. **Xcode 15+** with Command Line Tools
2. **Go 1.21+** for building the engine library
3. **Apple Developer Account** (for signing)

### Build Steps

```bash
# 1. Navigate to the IME directory
cd platforms/macos/WitnessdIME

# 2. Build the Go library (done automatically by Xcode)
./scripts/build-go-library.sh

# 3. Open in Xcode
open WitnessdIME.xcodeproj

# 4. Select your development team
# Project > Signing & Capabilities > Team

# 5. Build
# Cmd+B or Product > Build
```

### Universal Binary

The build script creates a universal binary supporting both architectures:

```bash
# Build for specific architecture
ARCHS="arm64" ./scripts/build-go-library.sh

# Build universal (arm64 + x86_64)
ARCHS="arm64 x86_64" ./scripts/build-go-library.sh
```

## Installation (Development)

```bash
# Build the app
xcodebuild -project WitnessdIME.xcodeproj \
           -scheme WitnessdIME \
           -configuration Debug

# Copy to Input Methods
cp -R build/Debug/WitnessdIME.app ~/Library/Input\ Methods/

# Refresh input methods
killall -HUP SystemUIServer
```

Then enable in System Settings > Keyboard > Input Sources.

## Testing

### Unit Tests

```bash
# Run all tests
xcodebuild test -project WitnessdIME.xcodeproj \
                -scheme WitnessdIME \
                -destination 'platform=macOS'
```

### Test Coverage

| Component | Tests |
|-----------|-------|
| Zone Mapping | 10 tests |
| Dead Key Composition | 7 tests |
| XPC Mock Service | 8 tests |
| XPC Client | 3 tests |

### Manual Testing Checklist

- [ ] IME appears in Input Sources
- [ ] Switching to IME works
- [ ] Typing produces correct output
- [ ] Status bar menu shows sample count
- [ ] Session ends on IME switch
- [ ] Evidence files are created
- [ ] Dead keys work (Option+E, then vowel)
- [ ] International keyboards work
- [ ] Memory usage is stable

## App Store Submission

### Pre-Submission Checklist

- [ ] **Code Signing**
  - [ ] Set DEVELOPMENT_TEAM in project settings
  - [ ] Set CODE_SIGN_IDENTITY to "Apple Distribution"
  - [ ] Verify entitlements are correct

- [ ] **Privacy**
  - [ ] Privacy manifest (PrivacyInfo.xcprivacy) is complete
  - [ ] Privacy policy URL is ready
  - [ ] Data collection disclosures are accurate

- [ ] **App Store Connect**
  - [ ] Create App Store Connect record
  - [ ] Set bundle ID: `com.witnessd.inputmethod`
  - [ ] Upload app icon (1024x1024)
  - [ ] Prepare screenshots (at least 2)
  - [ ] Write description and keywords

- [ ] **Testing**
  - [ ] All unit tests pass
  - [ ] Manual testing complete
  - [ ] Tested on Intel and Apple Silicon
  - [ ] Tested on macOS 11, 12, 13, 14+

- [ ] **Documentation**
  - [ ] Review notes explaining IME functionality
  - [ ] Privacy policy published online
  - [ ] Support URL active

### Archive and Upload

```bash
# Create archive
xcodebuild archive -project WitnessdIME.xcodeproj \
                   -scheme WitnessdIME \
                   -archivePath build/WitnessdIME.xcarchive

# Export for App Store
xcodebuild -exportArchive \
           -archivePath build/WitnessdIME.xcarchive \
           -exportPath build/AppStore \
           -exportOptionsPlist ExportOptions.plist
```

Or use Xcode: Product > Archive, then Distribute App.

### Review Notes Template

```
Witnessd is an Input Method that creates cryptographic proof of authorship.

HOW IT WORKS:
1. User adds Witnessd to their input sources in System Settings
2. User selects Witnessd when they want to record authorship
3. As they type, Witnessd captures timing patterns (not content)
4. When done, an evidence file is saved locally

PRIVACY:
- Witnessd does NOT record what the user types
- Witnessd ONLY records WHEN keys are pressed (timing)
- No data is transmitted to any server
- All evidence is stored locally on the user's device
- Users control when recording happens by selecting the IME

TESTING INSTRUCTIONS:
1. Install the app
2. Open System Settings > Keyboard > Input Sources
3. Add "Witnessd" input method
4. Switch to Witnessd in any text editor
5. Type some text - the timing is recorded
6. Switch away from Witnessd to end the session
7. Evidence is saved to ~/Library/Application Support/Witnessd/
```

### App Store Description Template

```
Witnessd - Proof of Authorship

Create unforgeable proof that you wrote your original content.

Witnessd uses your unique typing rhythm to prove authorship of your work. As you type, Witnessd captures the timing patterns of your keystrokes - creating a cryptographic fingerprint that is nearly impossible to fake.

FEATURES:
- Creates evidence of original authorship
- Works with any text editor or application
- Completely local - your data never leaves your device
- Privacy-first: records timing, not content
- Timestamped evidence with optional blockchain anchoring

USE CASES:
- Prove you wrote that blog post
- Timestamp your creative writing
- Protect your intellectual property
- Document your coding sessions

HOW IT WORKS:
1. Select Witnessd as your input method when writing
2. Type naturally - Witnessd works in the background
3. Your typing evidence is saved automatically
4. Use the evidence to prove you authored your work

Witnessd never records WHAT you type - only WHEN and HOW you type. Your privacy is protected by design.
```

### Privacy Policy Requirements

Your privacy policy must explain:

1. **What data is collected**: Keystroke timing (intervals between key presses)
2. **What data is NOT collected**: Keystroke content, passwords, sensitive information
3. **How data is stored**: Locally on the user's device
4. **Data retention**: Until user deletes the evidence files
5. **Data sharing**: None - data is never transmitted
6. **User control**: User explicitly enables recording by selecting the IME

## Troubleshooting

### Build Issues

**"libwitnessd.a not found"**
```bash
# Verify Go is in PATH
which go

# Build library manually
cd scripts && ./build-go-library.sh
```

**"Signing failed"**
- Ensure you have a valid Apple Developer certificate
- Check that the team ID is set correctly
- Verify entitlements match certificate capabilities

### Runtime Issues

**IME not appearing**
```bash
# Refresh input methods
killall -HUP SystemUIServer

# Check Console.app for errors
log show --predicate 'subsystem == "com.witnessd.inputmethod"' --last 5m
```

**Keystrokes not recording**
- Verify IME is the active input method (check menu bar)
- Check that a session is active (status menu shows "Recording")
- Secure input fields (passwords) are never monitored

**XPC connection fails**
- Verify the daemon is running
- Check XPC service name matches
- Review Console.app for XPC errors

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01 | Initial App Store release |

## License

Copyright 2026 Witnessd. All rights reserved.

## Support

- Documentation: https://witnessd.dev/docs
- Issues: https://github.com/witnessd/witnessd/issues
- Email: support@witnessd.dev
