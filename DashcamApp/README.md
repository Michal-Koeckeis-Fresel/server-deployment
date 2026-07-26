# DashCam iOS App - Xcode Project

A professional-grade iOS dashcam application with advanced recording, safety monitoring, g-force detection, and low-light capabilities.

## Project Structure

```
DashcamApp/
├── Sources/
│   └── DashcamApp/              # All Swift source files
│       ├── DashcamApp.swift     # App entry point
│       ├── ContentView.swift    # Main UI
│       ├── CameraDashcamViewModel.swift
│       ├── CameraInfo.swift
│       ├── CameraCapabilityChecker.swift
│       ├── NightModeManager.swift
│       ├── GForceMonitor.swift
│       ├── AudioEventDetector.swift
│       ├── PerformanceLogger.swift
│       ├── WatchConnectivityManager.swift
│       ├── EmergencySOSManager.swift
│       ├── StorageManager.swift
│       ├── LocationManager.swift
│       ├── BatteryMonitorManager.swift
│       ├── SettingsView.swift
│       ├── AudioAndWatchView.swift
│       ├── PerformanceDashboardView.swift
│       ├── LiveCameraFeedView.swift
│       ├── MultiCameraPreviewView.swift
│       ├── FilesView.swift
│       ├── AppearanceView.swift
│       ├── AppearanceManager.swift
│       ├── FPSCounter.swift
│       ├── FileProtectionManager.swift
│       ├── CrashDetectionManager.swift
│       ├── AutoStartRecordingManager.swift
│       ├── BatteryStatusView.swift
│       ├── VideoCodecManager.swift
│       ├── RealtimeVideoWriter.swift
│       └── ... (additional view and utility files)
├── Resources/
│   ├── Assets.xcassets/        # Image assets and color sets
│   └── LaunchScreen.storyboard # Launch screen configuration
├── Info.plist                  # App configuration and permissions
├── DashcamApp.xcodeproj/       # Xcode project configuration
│   └── project.pbxproj         # Project build settings
└── README.md                   # This file
```

## System Requirements

- **Xcode**: 14.0 or later
- **iOS Deployment Target**: iOS 16.0+
- **Swift Version**: 5.0+
- **Supported Devices**: iPhone with camera and microphone

## Features

### Core Recording
- Multi-camera support (Front Wide, Front Zoom)
- Real-time video and audio recording
- Adjustable frame rates (24fps, 30fps, 60fps)
- HDR video support (iOS 17.0+)
- Cinematic video stabilization
- Custom watermark overlays
- Codec management (H.264/H.265)

### Safety & Monitoring
- G-force monitoring with collision detection
- Audio event detection (airbag, glass break, sudden impact)
- Emergency SOS trigger (5-second debounce)
- Apple Watch integration via WatchConnectivity
- Crash detection with automatic emergency alerts

### Low-Light Performance
- Automatic Night Mode activation
- Low Light Boost technology
- Extended exposure for detail capture (8.33-33.33ms)
- Real-time brightness monitoring
- Exposure threshold configuration (-8.0 to -2.0 EV)

### Storage & Performance
- Intelligent storage management
- Reserved system space allocation (1-50 GB)
- Real-time performance metrics (FPS, memory, CPU)
- Thermal management with automatic FPS adjustment
- Video chunk-based recording
- Cleanup and archive capabilities

### User Interface
- SwiftUI-based modern design
- Multi-camera live preview
- Real-time performance dashboard
- Settings with granular controls
- Audio/Watch monitoring display
- Battery status monitoring

## Setting Up the Project in Xcode

### Method 1: Using Git Clone

```bash
git clone <repository-url> DashcamApp
cd DashcamApp
open DashcamApp/DashcamApp.xcodeproj
```

### Method 2: Extracting from ZIP

1. Extract the ZIP file to your desired location
2. Navigate to the extracted folder
3. Open `DashcamApp/DashcamApp.xcodeproj` with Xcode (double-click or `open DashcamApp.xcodeproj`)

### First-Time Setup in Xcode

After opening the project:

1. **Configure Bundle Identifier**
   - Select the project in the navigator
   - Select the "DashcamApp" target
   - Go to the "Signing & Capabilities" tab
   - Set your development team
   - Update Bundle Identifier to your organization's domain (e.g., `com.yourcompany.dashcam`)

2. **Add App Icons**
   - In Xcode, select `Resources/Assets.xcassets`
   - Click the "AppIcon" set
   - Drag your app icon images (multiple sizes required)
   - Required sizes: 29x29, 40x40, 60x60, 76x76, 83.5x83.5, 167x167, 180x180

3. **Configure Capabilities**
   - Select the target
   - Go to "Signing & Capabilities"
   - Click "+ Capability" and add:
     - Camera
     - Microphone
     - Motion (for accelerometer)
     - Background Modes (select "Audio, AirPlay, and Picture in Picture")
     - Watch Connectivity (if using Apple Watch)

4. **Review Info.plist Permissions**
   - The `Info.plist` file already includes all necessary permission strings
   - They will be displayed to users when requesting permissions
   - Edit values as needed for your organization

## Required Permissions

The app requests the following permissions from users:

- **Camera**: Recording video
- **Microphone**: Recording audio and detecting events
- **Motion**: G-force and collision detection
- **Location**: GPS tagging (optional, configured in app)
- **Local Network**: Enhanced features
- **Photo Library**: Saving recordings
- **Bluetooth**: Apple Watch connectivity

All permission descriptions are configured in `Info.plist`.

## Building and Running

### For Development (Debug)

1. Select a physical iPhone or simulator in Xcode
2. Click the "Play" button or press `Cmd + R`
3. The app will build and launch on your device

**Note**: Some features require a physical device:
- Camera recording
- Audio input
- G-force sensors
- Apple Watch connectivity

### For Distribution (Release)

1. Archive the project:
   - Xcode menu → Product → Archive
2. In the Organizer window:
   - Click "Distribute App"
   - Follow the distribution workflow for App Store or TestFlight
3. Submit for review or testing

## Project Configuration

### Info.plist Settings

Key configurations:

```xml
<!-- Minimum iOS version -->
<key>MinimumOSVersion</key>
<string>16.0</string>

<!-- Camera usage -->
<key>NSCameraUsageDescription</key>
<string>Recording video for dashcam functionality</string>

<!-- Microphone usage -->
<key>NSMicrophoneUsageDescription</key>
<string>Recording audio with video</string>

<!-- Motion sensors -->
<key>NSMotionUsageDescription</key>
<string>Detecting collisions and G-forces</string>

<!-- Watch connectivity -->
<key>WKWatchKitRequired</key>
<false/>
```

### Build Settings

Default configurations:

- **Deployment Target**: iOS 16.0
- **Swift Version**: 5.0
- **Product Bundle Identifier**: `com.koeckeis.dashcam`
- **Code Sign Style**: Automatic
- **Supported Interface Orientations**: Portrait (iPhone)

Change these in Xcode:
1. Select the project
2. Select the target
3. Edit in "Build Settings" tab

## Key Swift Files Overview

### Core Managers

- **CameraDashcamViewModel.swift**: Main view model coordinating recording, storage, and settings
- **CameraInfo.swift**: Camera enumeration, device configuration, setup
- **NightModeManager.swift**: Night mode control with brightness monitoring
- **GForceMonitor.swift**: Accelerometer-based collision detection
- **AudioEventDetector.swift**: Real-time audio analysis for events

### Safety & Monitoring

- **EmergencySOSManager.swift**: SOS activation with countdown
- **WatchConnectivityManager.swift**: iOS-watchOS communication
- **PerformanceLogger.swift**: FPS, memory, CPU metrics
- **StorageManager.swift**: Storage calculations and cleanup

### User Interface

- **ContentView.swift**: Main app interface
- **SettingsView.swift**: User preferences
- **LiveCameraFeedView.swift**: Real-time video display
- **PerformanceDashboardView.swift**: Analytics display

### Utilities

- **VideoCodecManager.swift**: Video encoding settings
- **RealtimeVideoWriter.swift**: Watermark and frame processing
- **LocationManager.swift**: GPS integration
- **BatteryMonitorManager.swift**: Battery level tracking

## Common Development Tasks

### Adding a New View

1. Create a new Swift file in `Sources/DashcamApp/`
2. Define your SwiftUI view:
   ```swift
   import SwiftUI
   
   struct MyView: View {
       var body: some View {
           Text("Hello")
       }
   }
   ```
3. Add to the navigation in `ContentView.swift`

### Modifying Permissions

1. Edit `Info.plist` in Xcode
2. Update the description strings for required permissions
3. Add new permission keys as needed
4. Test with a physical device

### Adjusting Recording Settings

Edit `CameraInfo.swift`:
- Change video codec settings in `configureVideoCodec()`
- Modify frame rate limits in `setFrameRate()`
- Adjust video stabilization in `configureVideoStabilization()`

### Customizing the UI Theme

1. Edit `AppearanceManager.swift` for color schemes
2. Modify `AppearanceView.swift` for user preferences
3. Update `Assets.xcassets` for custom colors and images

## Troubleshooting

### Camera Not Initializing

- Check `CameraInfo.swift` for device availability
- Verify Info.plist has Camera usage description
- Test on physical device (simulator has limited camera support)

### Low-Light Recording Issues

- Review `NightModeManager.swift` settings
- Check brightness threshold (-8.0 to -2.0 EV)
- Verify device supports Low Light Boost
- Test extended exposure in Settings

### Audio Event Detection Not Working

- Ensure microphone permissions are granted
- Check `AudioEventDetector.swift` thresholds
- Verify audio monitoring is started in `CameraDashcamViewModel.swift`

### Storage Issues

- Review `StorageManager.swift` calculation logic
- Check reserved system space setting in Settings view
- Monitor free space before recording

### Apple Watch Connection Issues

- Verify watch companion app is installed
- Check `WatchConnectivityManager.swift` session status
- Ensure both devices have latest OS versions
- Review Watch connectivity capability in Xcode

## Performance Optimization

### For Simulator Testing
- Use iPhone 14 Pro simulator (most capable)
- Disable extended exposure during testing
- Reduce logging output for faster performance

### For Device Testing
- Monitor memory usage in Xcode's memory debugger
- Check FPS in PerformanceDashboardView
- Monitor thermal state in performance metrics
- Use instruments to profile CPU usage

### Storage Optimization
- Adjust video chunk size in `CameraDashcamViewModel.swift`
- Enable automatic cleanup in Settings
- Configure reserved system space for your device

## Contributing

When modifying the project:

1. Maintain the source organization in `Sources/DashcamApp/`
2. Keep UI components in views and managers
3. Update this README for significant changes
4. Test on physical device before committing
5. Document complex algorithms with brief comments

## License

This project uses dual licensing:
- **AGPL v3**: For open-source usage (see LICENSE-AGPL)
- **MIT**: For commercial licensing (see LICENSE-MIT)

## Support

For issues or questions:

1. Check the DASHCAM_README.md for detailed feature documentation
2. Review INFO_PLIST_CONFIG.md for permission configuration
3. Check Xcode build output for compilation errors
4. Verify device capabilities in PerformanceDashboardView

## Version Information

- **Project Version**: 1.0
- **Swift Version**: 5.0+
- **Minimum iOS**: 16.0
- **Xcode**: 14.0+

## Next Steps

1. Update the Bundle Identifier with your organization's domain
2. Add your app icons to Assets.xcassets
3. Configure your development team in Xcode
4. Test on a physical iPhone
5. Customize settings and features as needed
6. Prepare for App Store submission

---

For detailed feature documentation, see `DASHCAM_README.md` in the repository root.
