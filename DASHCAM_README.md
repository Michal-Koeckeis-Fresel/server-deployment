# iOS Dashcam App

A SwiftUI-based dashcam application for iOS that records video continuously, even when the app is backgrounded. Perfect for recording while driving.

## Features

✅ **Background Recording** - App continues recording when locked or switched away  
✅ **High-Quality Video** - Records at device camera quality  
✅ **Audio Included** - Captures stereo audio during recording  
✅ **Timer Display** - Shows recording duration in real-time  
✅ **Simple Controls** - One-tap start/stop recording  
✅ **Error Handling** - Clear feedback for permission/setup issues  
✅ **File Management** - Videos saved to app's Documents folder  

## Requirements

- iOS 14.0 or later
- iPhone with rear camera and microphone
- Xcode 13.0 or later

## Project Structure

```
DashcamApp/
├── DashcamApp.swift                 # Main app entry point
├── ContentView.swift                # UI for recording controls
├── CameraDashcamViewModel.swift     # Video recording logic
├── INFO_PLIST_CONFIG.md            # Required configuration
└── DASHCAM_README.md               # This file
```

## Setup Instructions

### 1. Create a New Xcode Project

```bash
# In Xcode:
# File → New → Project
# Select iOS → App template
# Choose:
#   Product Name: DashcamApp
#   Interface: SwiftUI
#   Language: Swift
#   Storage: None
```

### 2. Replace Project Files

1. **DashcamApp.swift**
   - Delete the auto-generated main app file
   - Replace with the provided `DashcamApp.swift`

2. **ContentView.swift**
   - Replace with the provided `ContentView.swift`

3. **Add CameraDashcamViewModel.swift**
   - Create new Swift file named `CameraDashcamViewModel.swift`
   - Copy the provided content

### 3. Configure Info.plist

1. Select your Xcode project in the navigator
2. Select the target "DashcamApp"
3. Go to the **Info** tab
4. Add the following keys:

```
🔐 Privacy - Camera Usage Description
Value: "This app needs camera access to record video for dashcam functionality"

🔐 Privacy - Microphone Usage Description  
Value: "This app needs microphone access to record audio with video"

Background Modes (check box)
☑ Audio
```

**Alternative (XML Method):**
- Right-click Info.plist → Open As → Source Code
- Paste the configuration from `INFO_PLIST_CONFIG.md`

### 4. Capabilities Configuration

1. Select your target in Xcode
2. Go to **Signing & Capabilities** tab
3. Click **+ Capability**
4. Add **Background Modes**
5. Check the **Audio** checkbox

### 5. Verify Build Settings

1. Go to **Build Settings** (tab)
2. Search for "Background Modes"
3. Ensure `UIBackgroundModes` contains `audio`

## Build & Run

```bash
# In Xcode:
# Select a simulator or connected device
# Press Cmd + R to build and run
```

### Testing on Real Device

1. Connect your iPhone via USB
2. Select your device in Xcode's device selector
3. Click the Run button (▶️)
4. Grant camera and microphone permissions when prompted
5. Tap **Start Recording**
6. Press home button - recording continues!
7. Return to app to stop

## Video Storage

Recorded videos are saved to:
```
📁 App Documents Folder
├── dashcam_2025_01_15_144230.mov
├── dashcam_2025_01_15_150145.mov
└── ...
```

Access via:
- **Xcode:** Device Organizer → App Container → Documents
- **Files App:** On-device under "On My iPhone" → DashcamApp
- **Finder (macOS):** Connect device → Files tab → Navigate to app

## Usage

### Starting a Recording

1. Tap **Start Recording**
2. Grant permissions if first launch
3. Recording indicator shows live timer
4. App continues in background

### Stopping a Recording

1. Return to app (or wake from lock screen)
2. Tap **Stop Recording**
3. Video saves automatically

### Checking Status

- **Red recording indicator** in status bar = Currently recording
- **Timer display** in app = Elapsed recording time

## Troubleshooting

### App keeps stopping when backgrounded
- ✓ Verify "Audio" is in Background Modes (Capabilities tab)
- ✓ Check Info.plist has `NSMicrophoneUsageDescription`
- ✓ Ensure user granted microphone permission

### No video being saved
- ✓ Check app has Documents folder write permission
- ✓ Verify sufficient storage space available
- ✓ Check console for error messages

### Permission denied error
- ✓ Go to Settings → DashcamApp
- ✓ Enable Camera and Microphone
- ✓ Restart app

### Camera not initializing
- ✓ Ensure device has working camera
- ✓ Restart the app
- ✓ Check Xcode console for specific errors

## Technical Details

### Video Recording
- **Format:** MOV (H.264 video codec)
- **Resolution:** Device camera native resolution
- **Frame Rate:** 30 FPS (device standard)
- **Quality:** AVCaptureSession preset: `.high`

### Audio Recording
- **Input:** Device microphone
- **Format:** AAC (stereo)
- **Session Settings:** 
  - Category: `.record`
  - Options: `.duckOthers`

### Background Recording
- Uses `UIBackgroundModes` with `audio` mode
- Keeps audio session active in background
- System prevents audio interruption
- Recording continues until explicitly stopped

## Limitations

- ⚠️ Requires valid developer signing certificate for real device
- ⚠️ Videos stored on-device only (implement iCloud sync if needed)
- ⚠️ Recording stops if app is force-closed
- ⚠️ Battery drain during continuous recording (normal for video)

## Future Enhancements

Potential additions:
- Video file browser/playback in app
- iCloud Drive sync for recordings
- Auto-delete old videos after X days
- GPS location tagging
- Metadata embedding (timestamp, etc.)
- Settings for video quality/bitrate

## Code Architecture

### CameraDashcamViewModel
Manages:
- AVCaptureSession setup (camera/mic input)
- Video recording lifecycle
- Recording timer updates
- Error state management
- Audio session configuration

**Key Methods:**
- `setupCamera()` - Initialize capture session
- `startRecording()` - Begin video capture
- `stopRecording()` - End recording
- `updateRecordingTime()` - Update UI timer

### ContentView
Displays:
- Recording status indicator
- Start/Stop button
- Elapsed time counter
- Error messages
- Clean dark-themed UI

## Legal & Privacy

- Users should disclose dashcam recording per local laws
- Implement privacy policy for production app
- Consider adding audio consent disclosure
- Some jurisdictions require dashboard display of recording indicator

## Support

For issues, check:
1. Console output in Xcode for error messages
2. Device Settings for permission status
3. Available storage on device
4. iOS version compatibility
