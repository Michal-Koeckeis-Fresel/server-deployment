# App Icon Setup

The `Contents.json` file defines all required icon sizes for iOS. You need to add actual icon image files to this directory.

## Quick Setup Options

### Option 1: Generate Placeholder Icons (Recommended for Development)

If you have Python with Pillow installed:

```bash
cd DashcamApp/Resources/Assets.xcassets/AppIcon.appiconset/
python3 generate_icons.py
```

This creates placeholder icons with the DashCam brand colors and a camera lens design.

**Install Python dependencies if needed:**
```bash
pip install Pillow
```

### Option 2: Use Your Own Icons

1. Create or export icons in the following sizes (PNG format):
   - 20x20, 29x29, 40x40, 58x58, 60x60, 76x76, 80x80, 87x87
   - 120x120, 152x152, 167x167, 180x180
   - 1024x1024 (App Store / marketing)

2. Place them in this directory with the filenames specified in `Contents.json`

### Option 3: Online Icon Generator

Use an online tool like:
- AppIcon.co
- MakeAppIcon.com
- IconMoon.io

Upload a base image (1024x1024) and download all required sizes.

## Filename Reference

The `Contents.json` expects these filenames:

| Size | Filename | Use |
|------|----------|-----|
| 20x20 | icon-20.png | iPad notifications |
| 29x29 | icon-29.png | iPad settings |
| 40x40 | icon-40.png | iPhone notifications, iPad spotlight |
| 58x58 | icon-58.png | iPhone settings |
| 60x60 | icon-60.png | iPhone home (legacy) |
| 76x76 | icon-76.png | iPad home |
| 80x80 | icon-80.png | iPhone spotlight, iPad spotlight |
| 87x87 | icon-87.png | iPhone settings (3x) |
| 120x120 | icon-120.png | iPhone home, watch |
| 152x152 | icon-152.png | iPad home |
| 167x167 | icon-167.png | iPad Pro home |
| 180x180 | icon-180.png | iPhone home (3x) |
| 1024x1024 | icon-1024.png | App Store |

## Building Without Custom Icons

If you just want to build and test the app, generate placeholders:

```bash
python3 generate_icons.py
```

Then build in Xcode normally. The app will work fine with placeholder icons during development.

## For App Store Submission

Before submitting to the App Store:

1. Design a custom 1024x1024 icon
2. Use an icon generator to create all sizes
3. Replace the placeholder icons in this directory
4. Rebuild and submit

The App Store requires the 1024x1024 version for preview and marketing materials.

## Troubleshooting

**"AppIcon not found" error in Xcode?**
- Ensure `Contents.json` is in this directory
- Run `python3 generate_icons.py` to create placeholder images
- Clean build folder in Xcode (Cmd+Shift+K)

**Icons look blurry?**
- Ensure source images are the correct size
- PNG format is recommended
- Avoid scaling up small images

**Missing icon sizes?**
- Check `Contents.json` for the required filename
- All filenames must match exactly
- Run the generator script to create all sizes automatically
