# iOS Dashcam App

A SwiftUI-based dashcam application for iOS that records video continuously, even when the app is backgrounded. Perfect for recording while driving.

## Features

✅ **Multi-Camera Recording** - Simultaneously records from all available cameras (wide, telephoto, rear)  
✅ **Background Recording** - App continues recording when locked or switched away  
✅ **Video Chunking** - Automatically splits recordings into smaller files (1-15 min, configurable)  
✅ **Impact Detection** - Detects collisions and emergency braking via accelerometer and auto-protects all files  
✅ **Smart Storage** - Auto-deletes oldest unprotected videos when storage limit is reached  
✅ **File Protection** - Lock important videos to prevent accidental deletion  
✅ **Storage Management** - Set max storage in GB (1-100 GB, configurable)  
✅ **High-Quality Video** - Records at device camera quality from all cameras  
✅ **Audio Included** - Captures stereo audio during recording  
✅ **Camera Status** - Real-time display of all camera recording status  
✅ **Synchronized Chunks** - All cameras chunk at the same time  
✅ **Simple Controls** - One-tap start/stop recording for all cameras  
✅ **File Management** - Browse, protect, and delete recordings in-app  

## Requirements

- iOS 14.0 or later
- iPhone with rear camera and microphone
- Xcode 13.0 or later

## Multi-Camera Recording

The app simultaneously records from all available device cameras, providing comprehensive coverage for accident investigation and pedestrian detection.

### Available Cameras

**Front Wide-Angle** (Default 1x)
- Captures broad road view
- Pedestrian and obstacle detection
- Lane and traffic visibility
- Full dashboard view

**Front Telephoto** (Zoom, if available)
- Captures distant details
- License plate recognition at distance
- Traffic sign reading
- Focused perspective ahead

**Rear Camera** (if available)
- Rear-end collision evidence
- Tailgating documentation
- Rear traffic monitoring
- Backup perspective

### How Multi-Camera Works

1. **Simultaneous Recording:**
   - All available cameras record independently
   - Each has its own AVCaptureSession
   - Synchronized via single record/stop trigger

2. **File Organization:**
   ```
   dashcam_2025_01_15_144230_front_wide_chunk_0001.mov
   dashcam_2025_01_15_144230_front_zoom_chunk_0001.mov
   dashcam_2025_01_15_144230_rear_chunk_0001.mov
   ```

3. **Synchronized Chunking:**
   - All cameras chunk at the same time
   - Chunk numbers stay in sync across cameras
   - Easier to correlate footage

4. **Unified Control:**
   - Single Start button records all cameras
   - Single Stop button stops all cameras
   - Impact detection protects all concurrent files

5. **Storage:**
   - Each camera's footage counts toward total storage
   - All files subject to same protection/deletion rules
   - Protection applies to all related chunks

### Camera Status Display

Main screen shows real-time status for each camera:

- 🟢 **Green:** Ready (not recording)
- 🔴 **Red:** Recording actively
- ⚪ **Gray:** Unavailable on device

Examples:
```
Cameras
  ● Front Wide      Recording
  ● Front Zoom      Recording
  ● Rear            Unavailable
```

### Coverage Benefits

**Accident Investigation:**
- Wide angle captures full incident scene
- Telephoto shows fine details (plate numbers, signs)
- Rear shows following traffic

**Liability Protection:**
- Multiple angles reduce disputes
- Hard to argue with 3 synchronized views
- Pedestrian detection (wide angle)
- Vehicle identification (telephoto)

**Evidence Quality:**
- Wide + zoom = comprehensive coverage
- Rear prevents rear-end accident false claims
- Impact detection protects all perspectives

### Storage Implications

**Storage Calculation:**
- Wide angle: ~350-400 MB per minute (HD)
- Telephoto: ~350-400 MB per minute (HD)
- Rear: ~350-400 MB per minute (HD)
- **Total:** ~1 GB per minute for all 3 cameras

With 10 GB storage and 5-minute chunks:
- Each chunk set: ~5 GB
- ~2 complete chunk sets available
- Older chunks auto-delete as limit approaches

### Device Support

**All Cameras Available:**
- Most modern iPhones (iPhone 11+)
- iPhone 12, 13, 14, 15, 16 Pro models
- Wide angle always available
- Telephoto on iPhone 12 Pro and newer

**Limited Cameras:**
- iPhone SE, XR, 11: Wide angle only
- iPhone 12-15 standard: Wide angle + telephoto
- iPhone 16: Wide angle + telephoto + ultra-wide option

**App Behavior:**
- Uses all available cameras on device
- Gracefully handles unavailable cameras
- Shows status for each camera
- Records with whatever is available

### Technical Implementation

**Camera Initialization:**
- Detects available cameras at startup
- Creates separate AVCaptureSession per camera
- Handles failures gracefully
- Updates UI with availability status

**Synchronized Recording:**
- Single timer manages all sessions
- Chunk transitions coordinated across cameras
- Impact events protect all concurrent files
- Storage calculations sum all footage

**File Naming:**
- Timestamp matches across cameras
- Position indicator (front_wide, front_zoom, rear)
- Chunk number synchronized
- Easy to identify related files

### Limitations

- ⚠️ Significantly increases storage usage (3x typical)
- ⚠️ Not all iPhone models have telephoto
- ⚠️ Battery drain greater with multiple cameras
- ⚠️ Audio only from primary microphone
- ⚠️ Some older devices may have thermal issues

### Future Enhancements

- User toggle to disable specific cameras
- Separate resolution settings per camera
- Audio from multiple microphones
- Synchronized playback viewer
- Multi-angle incident replay

## Project Structure

```
DashcamApp/
├── DashcamApp.swift                    # Main app entry point
├── ContentView.swift                   # Recording UI and navigation
├── CameraDashcamViewModel.swift        # Multi-camera recording & control
├── CameraInfo.swift                    # Camera configuration & recorder
├── SettingsView.swift                  # Settings for video duration & storage
├── FilesView.swift                     # File browser, protection & deletion
├── StorageManager.swift                # Storage calculations & cleanup
├── FileProtectionManager.swift         # File protection metadata
├── CrashDetectionManager.swift         # Impact detection (collision + braking)
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

## Impact Detection

Automatic detection of accidents and emergency situations using device accelerometer. When an impact event is detected, the current recording is automatically protected.

### Event Types

#### Collision Detection
Detects sudden high-impact collisions from various angles:

**Triggers:**
- Frontal impacts
- Rear-end collisions
- Side-impact crashes
- Pothole/road hazard impacts

**Detection Criteria:**
- High sustained acceleration (>2.5G)
- Rapid change in acceleration (>1G variation)
- Typical for car crashes and severe impacts

#### Emergency Brake Detection
Detects hard, sustained braking (emergency stops):

**Triggers:**
- Rapid deceleration >1.5G
- Sustained for 3+ measurements (0.15+ seconds)
- Typical for emergency braking situations

**Detection Criteria:**
- Strong negative Z-axis acceleration (>1.5G)
- Sustained deceleration pattern
- Indicates driver hit brakes hard to avoid incident

### How It Works
1. **Monitoring:** Once recording starts, accelerometer continuously monitors acceleration
2. **Dual Detection:**
   - **Collision:** Analyzes magnitude and sudden changes
   - **Emergency Brake:** Analyzes sustained deceleration on Z-axis
3. **Debouncing:** 2-second cooldown between detections to prevent false duplicates
4. **Auto-Protection:** When either event is detected:
   - Current video chunk is automatically write-protected
   - Appropriate alert notification appears
   - Recording continues normally
   - File cannot be deleted until manually unlocked

### Detection Sensitivity

**Collision:**
- **Threshold:** 2.5G sustained acceleration
- **Analysis Window:** Last 5 measurements (0.25 seconds)
- **Buffer Size:** 10 recent measurements

**Emergency Brake:**
- **Threshold:** 1.5G deceleration
- **Minimum Duration:** 3 consecutive measurements (~0.15 seconds)
- **Focus:** Z-axis (vertical/braking axis)

### What Triggers Detection

**Collisions:**
✓ Frontal crashes  
✓ Rear-end collisions  
✓ Side impacts  
✓ Severe road hazards (deep potholes)  
✓ Hard object impacts  

**Emergency Braking:**
✓ Hard emergency stops  
✓ Sudden obstacle avoidance  
✓ Panic braking  
✓ Collision prevention maneuvers  

### What Doesn't Trigger Detection

**Generally Safe (No Detection):**
✗ Normal acceleration/braking  
✗ Turning and cornering  
✗ Gentle lane changes  
✗ Speed bumps (low impact)  
✗ Highway bumps (distributed impact)  
✗ Normal driving variations  

### Status Indicators

**Normal Recording:**
- Green dot: "Impact Detection Active"

**Collision Detected:**
- Red warning: "Crash Detected - Recording Protected"
- ⚠️ icon on main screen

**Emergency Brake Detected:**
- Orange alert: "Emergency Brake - Recording Protected"
- 🛑 icon on main screen

### After Event Detection
1. **Alert:** User sees notification with event type
2. **Protection:** Current chunk automatically locked
3. **Indicator:** Visual status on main screen
4. **Message:** In-app notification explains what happened
5. **Continuation:** Recording continues normally
6. **Unlocking:** User can manually unlock if false positive

### Debouncing
- **Cooldown Period:** 2 seconds between detections
- **Purpose:** Prevent duplicate alerts for same incident
- **Behavior:** Only one alert per event sequence

### Limitations
- ⚠️ Detection is heuristic-based (not 100% accurate)
- ⚠️ Sensitivity varies by device accelerometer quality
- ⚠️ False positives possible with severe road conditions
- ⚠️ Requires motion/movement to detect (parked vehicle won't detect)
- ⚠️ Accelerometer must be enabled on device
- ⚠️ Accuracy depends on device orientation

### Enabling/Disabling
- **Always Active:** Impact detection runs automatically when recording
- **No User Control:** Cannot be disabled (always on for safety)
- **Accelerometer:** Must be available (all modern iPhones have this)

### Typical Thresholds (Gravity Units)
- Normal car acceleration: 0.3-0.5G
- Emergency braking: 0.8-1.2G ← **Emergency Brake Threshold: 1.5G**
- Collision impact: 2.5-8G ← **Collision Threshold: 2.5G**
- Severe crash: 10G+

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

### Impact Detection
- **Sensor:** Device accelerometer (CMMotionManager)
- **Sample Rate:** 20 Hz (0.05s intervals)
- **Buffer:** 10 measurements (0.5 second history)
- **Analysis:** Dual algorithm (collision + brake)
- **Debounce:** 2 second cooldown between events
- **Callback:** Notifies ViewModel with event type
- **Thread:** Main thread for UI updates

**Collision Detection:**
- Analyzes magnitude (all axes)
- Requires >2.5G sustained acceleration
- Needs >1.0G variation in 5-measurement window
- Stops monitoring after detection

**Emergency Brake Detection:**
- Analyzes Z-axis deceleration
- Requires >1.5G sustained deceleration
- Needs 3+ consecutive high-decel measurements
- Detects hard braking events

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
- Multi-camera setup and coordination
- Video recording lifecycle & chunking for all cameras
- Recording timer updates
- Impact detection integration (collisions + braking)
- Storage management (all cameras)
- File protection across all cameras
- Error state management
- Audio session configuration

**Published Properties:**
- `isRecording` - Recording state for all cameras
- `cameraStatus` - Per-camera status (Ready/Recording/Unavailable/Error)
- `crashDetected` - Collision event detected
- `emergencyBrakeDetected` - Emergency braking detected
- `showCrashAlert` - Show impact alert to user
- `currentChunkNumber` - Synchronized chunk across all cameras
- `currentStorageGB` - Total storage from all cameras

**Key Methods:**
- `setupCameras()` - Initialize all available cameras
- `startRecording()` - Begin recording all active cameras
- `stopRecording()` - Stop recording all cameras
- `startNewChunk()` - Synchronized chunk transition for all cameras
- `handleImpactEventDetected()` - Auto-protect all active recordings
- `setupCrashDetection()` - Initialize accelerometer monitoring
- `toggleFileProtection()` - Lock/unlock files
- `getRecordedFiles()` - List all recordings from all cameras

### CameraInfo
Defines:
- `CameraPosition` enum (frontWide, frontTelephoto, rear)
- Device type and position mapping
- File naming conventions per camera
- `CameraRecorder` struct for individual camera management

**Camera Positions:**
- Front Wide: Broad road view (all devices)
- Front Telephoto: Distant detail capture (Pro models)
- Rear: Trailing traffic monitoring (if available)

**File Prefix Examples:**
- `front_wide_chunk_0001.mov`
- `front_zoom_chunk_0001.mov`
- `rear_chunk_0001.mov`

### CrashDetectionManager
Monitors:
- Device accelerometer data
- Acceleration magnitude and changes
- Collision pattern detection
- Emergency braking patterns
- Debouncing between events
- Running buffer of recent measurements

**Event Types:**
- `.collision` - High-impact collision detected
- `.emergencyBrake` - Hard braking detected

**Key Methods:**
- `startMonitoring()` - Begin accelerometer updates with event callback
- `stopMonitoring()` - Stop tracking
- `isCrashDetected()` - Analyze sensor data for collisions
- `isEmergencyBrakeDetected()` - Analyze deceleration for hard braking
- `shouldDebounce()` - Check if event detection should be suppressed

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
