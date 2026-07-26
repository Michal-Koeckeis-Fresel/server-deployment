# Quick Xcode Setup Guide

## One-Minute Setup

1. **Extract and Open**
   ```bash
   unzip DashcamApp.zip
   cd DashcamApp
   open DashcamApp/DashcamApp.xcodeproj
   ```

2. **Configure Your Signing**
   - Select project → Target
   - Signing & Capabilities tab
   - Select your team

3. **Update Bundle ID**
   - Product Bundle Identifier: `com.yourcompany.dashcam`

4. **Run on Device**
   - Connect iPhone
   - Select device in Xcode
   - Press Play (Cmd+R)

## What You Get

✅ 43 Swift source files fully organized  
✅ Multi-camera recording system  
✅ Night mode and low-light enhancement  
✅ G-force collision detection  
✅ Audio event detection  
✅ Apple Watch integration  
✅ Performance monitoring  
✅ Smart storage management  
✅ Complete SwiftUI interface  
✅ Professional code structure  

## Directory Layout

```
DashcamApp/
├── Sources/DashcamApp/        ← All 43 Swift files
├── Resources/
│   ├── Assets.xcassets/       ← Add your app icons here
│   └── LaunchScreen.storyboard
├── Info.plist                 ← Permissions configured
├── DashcamApp.xcodeproj/      ← Project configuration
└── README.md                  ← Full documentation
```

## First Build Checklist

- [ ] Updated Bundle Identifier
- [ ] Selected development team
- [ ] Connected iPhone (for testing)
- [ ] Granted Camera permission
- [ ] Granted Microphone permission
- [ ] Ran successfully (Cmd+R)

## Device Requirements

- iPhone 12 or later recommended
- iOS 16.0+
- 2GB+ free storage for recordings
- A14 Bionic chip or better for optimal performance

## Common First Issues

| Issue | Solution |
|-------|----------|
| "Cannot connect device" | Trust the computer on device, restart Xcode |
| "Bundle ID error" | Update to unique identifier |
| "No camera access" | Check Info.plist permissions, verify on physical device |
| "Build fails" | Clean build folder (Cmd+Shift+K), retry |

## Next: Adding App Icons

1. Open Assets.xcassets in Xcode
2. Right-click → "Add Assets" → "App Icon Set"
3. Drag icons for all sizes (29, 40, 60, 76, 83.5, 167, 180 pt)
4. Xcode will validate icon sizes automatically

## Documentation Files

- **README.md** - Complete project documentation
- **DASHCAM_README.md** - Feature documentation (in repo root)
- **INFO_PLIST_CONFIG.md** - Permission details
- **XCODE_SETUP.md** - This file

## Ready to Build?

```bash
open DashcamApp/DashcamApp.xcodeproj
```

Then in Xcode:
1. Select your device
2. Press ▶ (Play) button
3. App launches on your iPhone

## Support

- Check README.md for detailed setup
- Review feature docs in DASHCAM_README.md
- Test permissions in Settings app on device
- Monitor output in Xcode's console

Enjoy building your dashcam app! 🎥
