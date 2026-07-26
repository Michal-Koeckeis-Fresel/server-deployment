# Dashcam App - Quick Start

Get your iOS dashcam running in 5 minutes.

## 30-Second Setup

1. **Create Xcode Project**
   ```
   File → New → Project → iOS App (SwiftUI)
   Product Name: DashcamApp
   ```

2. **Copy Code Files**
   - Replace `DashcamApp.swift` with provided file
   - Replace `ContentView.swift` with provided file
   - Add new file `CameraDashcamViewModel.swift` with provided code

3. **Configure Permissions**
   - Select target → Info tab
   - Add Camera: "This app needs camera access to record video"
   - Add Microphone: "This app needs microphone access for audio"

4. **Enable Background Recording**
   - Select target → Signing & Capabilities
   - Click `+ Capability` → Add `Background Modes`
   - Check `Audio` checkbox

5. **Run**
   - Press Cmd+R
   - Grant permissions
   - Tap Start Recording
   - Press home button (app keeps recording!)

## Key Files

| File | Purpose |
|------|---------|
| `DashcamApp.swift` | App entry point |
| `ContentView.swift` | Recording UI & navigation |
| `SettingsView.swift` | Video duration, storage, and location settings |
| `FilesView.swift` | File browser, protection & deletion |
| `CameraDashcamViewModel.swift` | Multi-camera recording & chunking |
| `CameraInfo.swift` | Camera configuration & recorder |
| `StorageManager.swift` | Storage calculations & cleanup |
| `StorageLocationManager.swift` | iCloud & on-device storage selection |
| `FileProtectionManager.swift` | File protection metadata |
| `CrashDetectionManager.swift` | Impact detection (collision + braking) |
| `INFO_PLIST_CONFIG.md` | Detailed config reference |
| `DASHCAM_README.md` | Full documentation |

## Testing

**Verify background recording:**
1. Start recording (timer shows 00:00:00)
2. Tap home button
3. Wait 5 seconds (status bar shows red dot = recording)
4. Open app again (timer has advanced)
5. Tap Stop

**Find videos:**
- Xcode: Select target → Device Organizer → Documents folder
- Device Files app: Files → On My iPhone → DashcamApp
- All saved as: `dashcam_YYYY_MM_DD_HHMMSS.mov`

## Common Issues

| Problem | Solution |
|---------|----------|
| App stops when backgrounded | Verify "Audio" is checked in Background Modes |
| No camera access | Settings → DashcamApp → enable Camera |
| "Microphone permission denied" | Settings → DashcamApp → enable Microphone |
| Videos not saving | Check available storage, check app has Documents access |

## Deployment

Ready for TestFlight/App Store?

```
1. Signing & Capabilities → Add provisioning profile
2. Product → Archive
3. Distribute via Organizer
4. Upload to TestFlight or App Store Connect
```

---

**Done!** You now have a working iOS dashcam app that records continuously, even in the background.

For full documentation, see `DASHCAM_README.md`
