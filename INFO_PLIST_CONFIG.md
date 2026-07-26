# Info.plist Configuration for Dashcam App

Add the following keys to your `Info.plist` file to enable background recording and camera/microphone access:

## Required Privacy Permissions

Add these keys with appropriate descriptions:

```xml
<key>NSCameraUsageDescription</key>
<string>This app needs camera access to record video for dashcam functionality</string>

<key>NSMicrophoneUsageDescription</key>
<string>This app needs microphone access to record audio with video</string>
```

## Background Modes (Critical for Continuous Recording)

Add `UIBackgroundModes` to enable recording while app is backgrounded:

```xml
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
</array>
```

**Note:** Audio background mode allows the app to continue recording even when the user locks the screen or switches to another app. This is the key to keeping the dashcam running continuously.

## Additional Recommended Settings

### App Requires Full Screen (iOS 17+)
```xml
<key>UIRequiresFullScreen</key>
<true/>
```

### Prevent App from Sleeping During Recording
```xml
<key>NSBonjourServiceTypes</key>
<array/>
```

### Disable Picture-in-Picture (Optional)
```xml
<key>UIApplicationSupportsIndirectInputEvents</key>
<true/>
```

## Audio Session Configuration

The app configures the audio session with these settings in code:
- **Category:** `.record` - Prioritizes recording over playback
- **Mode:** `.default` - Standard recording mode
- **Options:** 
  - `.duckOthers` - Lowers volume of other audio apps
  - `.defaultToSpeaker` - Uses speaker for audio monitoring

## How to Add to Your Project

1. Open your Xcode project
2. Select your target
3. Go to **Info** tab
4. Click the **+** button to add new keys
5. Add the keys listed above with their values
6. Alternatively, open `Info.plist` as Source Code and paste the XML sections above

## iOS Version Requirements

- **Minimum:** iOS 14.0+
- **Recommended:** iOS 15.0+ for best performance

## Testing Background Recording

1. Start recording in the app
2. Press the home button or switch to another app
3. The app should continue recording (check the status bar for the red recording indicator)
4. Return to the app to stop recording or view status
5. Check the Documents folder to verify video files were saved
