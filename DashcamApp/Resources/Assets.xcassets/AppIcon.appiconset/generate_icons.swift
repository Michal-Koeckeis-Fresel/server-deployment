#!/usr/bin/env swift

import AppKit

let iconSizes = [
    (20, "icon-20.png"),
    (29, "icon-29.png"),
    (40, "icon-40.png"),
    (58, "icon-58.png"),
    (60, "icon-60.png"),
    (76, "icon-76.png"),
    (80, "icon-80.png"),
    (87, "icon-87.png"),
    (120, "icon-120.png"),
    (152, "icon-152.png"),
    (167, "icon-167.png"),
    (180, "icon-180.png"),
    (1024, "icon-1024.png"),
]

let scriptDir = FileManager.default.currentDirectoryPath
print("Generating iOS app icons in \(scriptDir)...")

for (size, filename) in iconSizes {
    // Create bitmap representation at exact pixel size
    guard let bitmapRep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: size * 4,
        bitsPerPixel: 32
    ) else {
        print("✗ Failed to create bitmap for \(filename)")
        continue
    }

    let context = NSGraphicsContext(bitmapImageRep: bitmapRep)
    NSGraphicsContext.current = context

    // Draw dark blue background (25, 55, 100)
    let bgRed = CGFloat(25) / CGFloat(255)
    let bgGreen = CGFloat(55) / CGFloat(255)
    let bgBlue = CGFloat(100) / CGFloat(255)
    let bgColor = NSColor(srgbRed: bgRed, green: bgGreen, blue: bgBlue, alpha: 1.0)
    bgColor.setFill()
    NSRect(x: 0, y: 0, width: size, height: size).fill()

    // Draw camera lens circle
    let lensRed = CGFloat(100) / CGFloat(255)
    let lensGreen = CGFloat(180) / CGFloat(255)
    let lensBlue = CGFloat(255) / CGFloat(255)
    let lensColor = NSColor(srgbRed: lensRed, green: lensGreen, blue: lensBlue, alpha: 1.0)
    lensColor.setFill()

    let margin = CGFloat(size) / 3
    let circle = NSRect(x: margin, y: margin, width: CGFloat(size) - (margin * 2), height: CGFloat(size) - (margin * 2))
    NSBezierPath(ovalIn: circle).fill()

    NSGraphicsContext.current = nil

    // Save as PNG
    let fileURL = URL(fileURLWithPath: "\(scriptDir)/\(filename)")
    guard let pngData = bitmapRep.representation(using: NSBitmapImageRep.FileType.png, properties: [:]) else {
        print("✗ Failed to create PNG data for \(filename)")
        continue
    }

    do {
        try pngData.write(to: fileURL, options: Data.WritingOptions.atomic)
        print("✓ Created \(filename) (\(size)x\(size))")
    } catch {
        print("✗ Error writing \(filename): \(error)")
    }
}

print("\n✓ Icon generation complete!")
print("Your app icons are ready to use in Xcode.")
