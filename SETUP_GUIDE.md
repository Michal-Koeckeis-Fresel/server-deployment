# Complete Setup Guide - iOS Dashcam App

Step-by-step instructions for creating and configuring the dashcam app from scratch.

## Part 1: Create Xcode Project

### Step 1.1: Open Xcode
- Launch Xcode (or use Xcode command line)
- Click "Create a new Xcode project"

### Step 1.2: Choose Template
1. Select **iOS** tab
2. Choose **App** template
3. Click **Next**

### Step 1.3: Configure Project
Fill in the form:
- **Product Name:** `DashcamApp`
- **Team:** (select your Apple Developer account)
- **Organization Identifier:** `com.yourname` (or similar)
- **Bundle Identifier:** `com.yourname.dashcam`
- **Interface:** `SwiftUI`
- **Language:** `Swift`
- **Storage:** `None`
- **Include Tests:** Unchecked

Click **Create**

### Step 1.4: Wait for Project to Load
Let Xcode finish initializing (usually 5-10 seconds)

---

## Part 2: Replace Code Files

### Step 2.1: Replace DashcamApp.swift

1. In Xcode's file navigator (left panel), locate `DashcamAppApp.swift`
   - Double-click to open
   - Select all (Cmd+A)
   - Delete

2. Copy the entire contents from the provided `DashcamApp.swift`
3. Paste into the editor
4. Save (Cmd+S)

### Step 2.2: Replace ContentView.swift

1. In file navigator, locate `ContentView.swift`
2. Double-click to open
3. Select all (Cmd+A) and delete
4. Copy entire contents from provided `ContentView.swift`
5. Paste and save

### Step 2.3: Create Additional Swift Files

Repeat this process for each of the following files:
- `CameraInfo.swift`
- `CameraDashcamViewModel.swift`
- `SettingsView.swift`
- `FilesView.swift`
- `StorageManager.swift`
- `FileProtectionManager.swift`
- `CrashDetectionManager.swift`

For each file:
1. Right-click the project folder in navigator
2. Select **New File...**
3. Choose **Swift File**
4. Name it appropriately
5. Click **Create**
6. Copy the entire provided code into the file
7. Save (Cmd+S)

**Your project should now have 9 Swift files:**
```
DashcamApp/
├── DashcamApp.swift
├── ContentView.swift
├── SettingsView.swift
├── FilesView.swift
├── CameraDashcamViewModel.swift
├── CameraInfo.swift
├── StorageManager.swift
├── FileProtectionManager.swift
├── CrashDetectionManager.swift
└── Assets.xcassets
```

**Verify in Xcode:**
- All 7 files should appear in the file navigator
- Each file should show "DashcamApp" under "Target Membership"

---

## Part 3: Configure Info.plist

### Option A: GUI Method (Recommended)

1. In file navigator, select your **project** (not target)
2. Select the **target** "DashcamApp"
3. Click the **Info** tab

4. **Add Camera Permission:**
   - Click the **+** button at bottom of key list
   - Search for or type: `NSCameraUsageDescription`
   - Set Value to: `This app needs camera access to record video for dashcam functionality`
   - Press Enter

5. **Add Microphone Permission:**
   - Click **+** again
   - Search for or type: `NSMicrophoneUsageDescription`
   - Set Value to: `This app needs microphone access to record audio with video`
   - Press Enter

6. **Add Background Modes:**
   - Click **+** again
   - Search for: `UIBackgroundModes`
   - Type defaults to Array (which is correct)
   - Click the arrow to expand it
   - Click **+** to add an item
   - Set the value to: `audio`

**You should see these keys now:**
```
NSCameraUsageDescription: This app needs camera access...
NSMicrophoneUsageDescription: This app needs microphone access...
UIBackgroundModes:
  └─ audio
```

### Option B: XML Method (Advanced)

1. Right-click on `Info.plist` in navigator
2. Select **Open As** → **Source Code**
3. Find the line: `</dict>` (near the end)
4. Add these keys before `</dict>`:

```xml
<key>NSCameraUsageDescription</key>
<string>This app needs camera access to record video for dashcam functionality</string>

<key>NSMicrophoneUsageDescription</key>
<string>This app needs microphone access to record audio with video</string>

<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
</array>
```

5. Right-click Info.plist again, select **Open As** → **Property List** to verify formatting

---

## Part 4: Enable Background Modes Capability

1. Select your **project** in navigator
2. Select the **target** "DashcamApp"
3. Click the **Signing & Capabilities** tab
4. Click the **+ Capability** button (top-left)
5. Search for: `Background Modes`
6. Double-click to add it
7. Check the **Audio** checkbox that appears

**You should see a section appear:**
```
Background Modes ✓
  ☑ Audio
```

---

## Part 5: Verify Configuration

### Check Info.plist Values
- [ ] `NSCameraUsageDescription` = camera access description
- [ ] `NSMicrophoneUsageDescription` = microphone access description  
- [ ] `UIBackgroundModes` contains `audio`

### Check Signing & Capabilities
- [ ] Background Modes section visible
- [ ] Audio checkbox is checked

### Build Settings
1. Select target → Build Settings tab
2. Search for: `Background Modes`
3. Verify it shows `UIBackgroundModes: audio`

---

## Part 6: Build & Run

### On Simulator

1. Select target device dropdown (top toolbar)
2. Choose an iPhone simulator (e.g., "iPhone 15")
3. Click the **Run** button (▶️) or press Cmd+R
4. Wait for build to complete
5. App launches in simulator

### On Real Device

1. Connect iPhone via USB cable
2. Select your device from dropdown (it will show under "Devices")
3. Click **Run** button
4. Enter your Apple ID password if prompted
5. Wait for app to launch on device

---

## Part 7: First Launch & Permission Grants

When app launches:

1. **Camera Permission Dialog** appears
   - Tap **Allow**

2. **Microphone Permission Dialog** appears
   - Tap **Allow**

3. App shows recording UI

---

## Part 8: Test Recording

### Basic Test

1. Tap **Start Recording** button (red button)
2. Watch the timer count up: 00:00 → 00:01 → 00:02...
3. In simulator: Press Cmd+H (or simulator menu Home button)
4. In real device: Press home button or lock screen
5. App goes to background (red recording indicator shows in status bar)
6. Wait 10 seconds
7. Return to app:
   - Simulator: Cmd+Tab to DashcamApp or click app icon
   - Device: Tap app icon from home screen
8. Timer has advanced! Still counting?
   - ✓ Background recording is working!
9. Tap **Stop Recording** (orange button)
10. Video is saved

### Verify Video was Saved

**On Simulator:**
1. Xcode → Window → Devices and Simulators
2. Select your simulator
3. Right-click your app "DashcamApp"
4. Click "Download Container..."
5. Save to Desktop
6. Right-click the saved folder → Show Package Contents
7. Navigate: `AppData/Documents/`
8. You'll see `dashcam_*.mov` files

**On Real Device:**
1. Xcode → Window → Devices and Simulators
2. Connect iPhone
3. Select it and your app
4. Click "Download Container..."
5. Files are in `Documents/` folder

---

## Part 9: Troubleshooting Checklist

If something doesn't work, check:

### App Crashes on Launch
- [ ] All three Swift files present and have correct names
- [ ] No syntax errors (check Xcode build errors)
- [ ] `DashcamApp.swift` is marked as part of target (File Inspector)

### Permissions Not Requested
- [ ] `NSCameraUsageDescription` in Info.plist
- [ ] `NSMicrophoneUsageDescription` in Info.plist
- [ ] Use exact key names (case-sensitive)

### Recording Stops When App Goes Background
- [ ] `UIBackgroundModes` contains `audio` in Info.plist
- [ ] **Audio** checkbox is checked in Signing & Capabilities
- [ ] Microphone permission was granted
- [ ] App wasn't force-closed

### "Camera not ready" Error
- [ ] Device has camera (simulator by default has one)
- [ ] Grant camera permission
- [ ] Restart app and try again

### No Videos Saved
- [ ] Check console for error messages (Xcode → View → Debug Area)
- [ ] Verify device has storage space
- [ ] Check app has Documents folder access

### Videos Save but Audio is Silent
- [ ] Microphone permission was granted
- [ ] Check simulator audio input (Simulator menu)
- [ ] On device: check mute switch is OFF

---

## Part 10: Customization (Optional)

### Change App Name
1. Select project → Target → General
2. Change "Display Name" field

### Change Bundle Identifier
1. Select target → Signing & Capabilities
2. Change "Bundle Identifier" field
3. Rebuild

### Change Video Quality
In `CameraDashcamViewModel.swift`:
```swift
session.sessionPreset = .high  // Change to .medium or .low
```

### Change Recording Location
Videos currently save to app Documents folder. To change:
In `CameraDashcamViewModel.swift`, modify:
```swift
let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
```

---

## Summary

You're done! Your iOS dashcam app should now:
- ✅ Record video from the rear camera
- ✅ Capture audio from the microphone
- ✅ Continue recording in the background
- ✅ Display recording timer
- ✅ Save videos to the Documents folder
- ✅ Handle permissions gracefully

**Next steps:**
- Test on real device with actual driving scenario
- Implement additional features (playback, file deletion, settings)
- Prepare for App Store submission if desired

For more details, see `DASHCAM_README.md` and `INFO_PLIST_CONFIG.md`
