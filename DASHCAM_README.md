# iOS Dashcam App

A SwiftUI-based dashcam application for iOS that records video continuously, even when the app is backgrounded. Perfect for recording while driving.

## Features

✅ **Background Recording** - App continues recording when locked or switched away  
✅ **Video Chunking** - Automatically splits recordings into smaller files (1-15 min, configurable)  
✅ **Crash Detection** - Detects potential accidents via accelerometer and auto-protects current file  
✅ **Smart Storage** - Auto-deletes oldest unprotected videos when storage limit is reached  
✅ **File Protection** - Lock important videos to prevent accidental deletion  
✅ **Storage Management** - Set max storage in GB (1-100 GB, configurable)  
✅ **High-Quality Video** - Records at device camera quality  
✅ **Audio Included** - Captures stereo audio during recording  
✅ **Timer Display** - Shows recording duration and chunk number in real-time  
✅ **Simple Controls** - One-tap start/stop recording  
✅ **Error Handling** - Clear feedback for permission/setup issues  
✅ **File Management** - Browse, protect, and delete recordings in-app  

## Requirements

- iOS 14.0 or later
- iPhone with rear camera and microphone
- Xcode 13.0 or later

## Project Structure

```
DashcamApp/
├── DashcamApp.swift                    # Main app entry point
├── ContentView.swift                   # Recording UI and navigation
├── CameraDashcamViewModel.swift        # Recording, chunking, storage logic
├── SettingsView.swift                  # Settings for video duration & storage
├── FilesView.swift                     # File browser, protection & deletion
├── StorageManager.swift                # Storage calculations & cleanup
├── FileProtectionManager.swift         # File protection metadata
├── CrashDetectionManager.swift         # Accelerometer-based crash detection
├── INFO_PLIST_CONFIG.md               # Required configuration
└── DASHCAM_README.md                  # This file
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

1. Tap **Start Recording** (red button)
2. Grant permissions if first launch
3. Recording indicator shows live timer and chunk number
4. App continues in background even when locked

### During Recording

- **Chunk Indicator:** Shows current chunk number (e.g., "Recording Chunk 3")
- **Timer:** Displays elapsed time for current chunk
- **Status Bar:** Red dot indicates active recording
- **Automatic Chunking:** New chunks start automatically at configured duration

### Stopping a Recording

1. Return to app or wake from lock screen
2. Tap **Stop Recording** (orange button)
3. Current chunk saves automatically
4. Can start new recording immediately

### Checking Status

- **Main Screen:** Real-time storage usage and progress bar
- **Recording Status:** Shows "Recording..." or "Ready"
- **Chunk Counter:** Displays current chunk number when recording

### Managing Settings

1. Tap **Settings** (gear icon)
2. Adjust:
   - **Video Chunk Duration** (1-15 minutes)
   - **Maximum Storage** (1-100 GB)
3. Changes apply immediately
4. Settings persist across sessions

### Viewing & Managing Files

1. Tap **Recordings** (film icon)
2. See all recordings with:
   - File size
   - Date/time created
   - Protection status
3. Actions:
   - **Lock Icon:** Toggle protection on/off
   - **Trash Icon:** Delete file (only if unprotected)

### Protecting Important Videos

1. Open **Recordings** (Files View)
2. Tap the **lock icon** next to a video
3. Icon fills/highlights when protected
4. Protected videos won't be auto-deleted
5. Tap lock again to unprotect

### Checking Storage

**Main Screen:**
- Progress bar shows usage
- Text shows current/max storage (e.g., "2.45 GB / 10 GB")

**Settings Screen:**
- Detailed storage breakdown
- "X GB used" and "X GB available"
- Auto-cleanup indicator

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

## Video Chunking

Videos are automatically split into smaller files to reduce individual file sizes and improve manageability.

### Configuration
- **Default:** 5 minutes per chunk
- **Range:** 1-15 minutes (configurable in Settings)
- **Naming:** Each chunk is numbered sequentially
  - Example: `dashcam_2025_01_15_144230_chunk_0001.mov`

### How It Works
1. Recording starts with chunk 1
2. Timer tracks elapsed time for current chunk
3. When chunk duration is reached:
   - Current video is automatically saved
   - New chunk starts immediately
   - Recording continues seamlessly
4. No gap between chunks
5. All chunks stored in Documents folder

### Benefits
- Smaller individual files (easier to share/backup)
- Reduced memory usage per file
- Faster save times
- Better organization

---

## Storage Management

Automatic storage management keeps your device from filling up while protecting important videos.

### How It Works
1. **Track Usage:** App monitors total video storage used
2. **Set Limit:** Configure maximum storage (1-100 GB, default 10 GB)
3. **Auto-Cleanup:** When limit is reached:
   - Oldest unprotected videos are automatically deleted
   - Protected videos are preserved
   - New recordings can continue
4. **Protection:** Mark important videos as protected to prevent deletion

### Configuration (Settings)
- **Maximum Storage:** 1-100 GB in 0.5 GB increments
- Quick presets: 5 GB, 10 GB, 20 GB, 50 GB
- Custom slider for precise control

### Storage Display
- **Main Screen:** Real-time storage usage with progress bar
- **Settings:** Detailed breakdown (used / available)
- **Files View:** Individual file sizes for each recording

---

## File Protection

Protect important recordings from accidental deletion or auto-cleanup.

### How to Protect a File
1. Open **Recordings** (Files View)
2. Tap the **lock icon** next to a recording
   - Lock becomes **filled/yellow** = Protected
   - Lock is **open/gray** = Unprotected

### Protected File Behavior
- ✅ Cannot be deleted (delete button is disabled)
- ✅ Preserved during storage cleanup
- ✅ Only removed when manually unlocked
- ✅ Sync across app restarts

### Storage Cleanup Priority
When storage limit is reached:
1. Unprotected files are deleted first (oldest first)
2. Protected files are never auto-deleted
3. If only protected files remain and limit exceeded:
   - No cleanup occurs
   - User must manually delete protected files

---

## Crash Detection

Automatic detection of potential accidents using device accelerometer. When a crash is detected, the current recording is automatically protected.

### How It Works
1. **Monitoring:** Once recording starts, accelerometer continuously monitors device acceleration
2. **Detection Algorithm:** Analyzes acceleration patterns for sudden impacts
   - High sustained acceleration (>2.5G)
   - Rapid change in acceleration (>1G variation)
   - Pattern matching to distinguish crash from normal driving
3. **Auto-Protection:** When crash is detected:
   - Current video chunk is automatically write-protected
   - Alert notification appears
   - Recording continues normally
   - File cannot be deleted until manually unlocked

### Detection Sensitivity
- **Threshold:** 2.5G sustained acceleration (typical car crash)
- **Analysis Window:** Last 5 measurements (0.25 seconds)
- **Buffer Size:** 10 recent measurements
- **False Positive Prevention:** Requires both high acceleration AND rapid change

### What Triggers Detection
✓ Sudden collisions (frontal, rear, side)  
✓ Hard braking with impact  
✓ Pothole/severe road hazard impact  

### What Doesn't Trigger Detection
✗ Normal acceleration/braking  
✗ Turning and cornering  
✗ Speed bumps (low impact)  
✗ Highway bumps (distributed impact)  

### After Crash Detection
1. **Alert:** User sees notification
2. **Protection:** Current chunk is automatically locked
3. **Indicator:** ⚠️ icon shows on main screen
4. **Recovery:** Click through alert to continue recording
5. **File Unlocking:** User can manually unlock protected file later if needed

### Limitations
- ⚠️ Detection is heuristic-based (not 100% accurate)
- ⚠️ Sensitivity varies by device accelerometer
- ⚠️ False positives possible with severe road conditions
- ⚠️ Requires motion/movement to detect (parked vehicle won't detect)
- ⚠️ Accelerometer must be enabled on device

### Enabling/Disabling
- **Always Active:** Crash detection runs automatically when recording
- **No User Control:** Cannot be disabled (always on for safety)
- **Accelerometer:** Must be available (all modern iPhones have this)

---

## Technical Details

### Video Recording
- **Format:** MOV (H.264 video codec)
- **Resolution:** Device camera native resolution
- **Frame Rate:** 30 FPS (device standard)
- **Quality:** AVCaptureSession preset: `.high`
- **Chunking:** Automatic via `AVCaptureMovieFileOutput`

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

### Storage Management
- **Calculation:** Sums all `.mov` files in Documents folder
- **Unit:** Gigabytes (GB) with 2 decimal precision
- **Cleanup:** Async task, doesn't block recording
- **Protection:** Stored in UserDefaults as file name set

### File Protection
- **Storage:** UserDefaults (persistent across sessions)
- **Key:** Last path component (filename)
- **Scope:** Per-app only (not accessible to other apps)

## Limitations

- ⚠️ Requires valid developer signing certificate for real device
- ⚠️ Videos stored on-device only (implement iCloud/cloud sync if needed)
- ⚠️ Recording stops if app is force-closed or device restarts
- ⚠️ Battery drain during continuous recording (normal for video)
- ⚠️ Storage cleanup is best-effort (if all files are protected, no deletion occurs)
- ⚠️ File protection only prevents accidental deletion within the app

## Future Enhancements

Potential additions:
- Video playback/preview in app
- iCloud Drive or cloud sync
- Time-based auto-cleanup (delete after X days)
- GPS/location tagging for recordings
- Metadata editing (driver name, trip info)
- Video quality/bitrate settings
- Batch file operations (multi-select delete/protect)
- Export to cloud services
- Video compression to save space
- Incident flagging/tagging

## Code Architecture

### CameraDashcamViewModel
Manages:
- AVCaptureSession setup (camera/mic input)
- Video recording lifecycle & chunking
- Recording timer updates
- Crash detection integration
- Storage management
- File protection
- Error state management
- Audio session configuration

**Key Methods:**
- `setupCamera()` - Initialize capture session
- `startRecording()` - Begin video capture
- `stopRecording()` - End recording
- `startNewChunk()` - Start next video chunk
- `handleCrashDetected()` - Auto-protect on crash
- `toggleFileProtection()` - Lock/unlock files
- `getRecordedFiles()` - List all videos

### CrashDetectionManager
Monitors:
- Device accelerometer data
- Acceleration magnitude and changes
- Crash pattern detection
- Running buffer of recent measurements

**Key Methods:**
- `startMonitoring()` - Begin accelerometer updates
- `stopMonitoring()` - Stop tracking
- `isCrashDetected()` - Analyze sensor data for crashes

### StorageManager
Handles:
- Total storage calculation
- File cleanup when limit reached
- Unprotected file deletion (oldest first)
- Protection checking

### FileProtectionManager
Maintains:
- Protected file list in UserDefaults
- Toggle protection on/off
- Query protection status

### ContentView
Displays:
- Recording status with chunk number
- Start/Stop button
- Elapsed time counter
- Storage usage progress
- Crash detection status
- Error messages & alerts
- Navigation to Settings & Files
- Clean dark-themed UI

### SettingsView
Allows configuration of:
- Video chunk duration (1-15 minutes)
- Maximum storage (1-100 GB)
- Quick presets and custom slider
- Current storage usage display

### FilesView
Shows:
- List of all recordings
- File size and date
- Protection status for each file
- Lock/unlock buttons
- Delete buttons (disabled for protected files)

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
