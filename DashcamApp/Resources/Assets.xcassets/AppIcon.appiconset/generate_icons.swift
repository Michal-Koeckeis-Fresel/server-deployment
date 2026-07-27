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
    // Create image
    let nsSize = NSSize(width: CGFloat(size), height: CGFloat(size))
    let image = NSImage(size: nsSize)

    image.lockFocus()

    // Draw dark blue background (25, 55, 100)
    let bgRed = CGFloat(25) / CGFloat(255)
    let bgGreen = CGFloat(55) / CGFloat(255)
    let bgBlue = CGFloat(100) / CGFloat(255)
    let bgColor = NSColor(srgbRed: bgRed, green: bgGreen, blue: bgBlue, alpha: 1.0)
    bgColor.setFill()
    NSRect(x: 0, y: 0, width: nsSize.width, height: nsSize.height).fill()

    // Draw camera lens circle
    let lensRed = CGFloat(100) / CGFloat(255)
    let lensGreen = CGFloat(180) / CGFloat(255)
    let lensBlue = CGFloat(255) / CGFloat(255)
    let lensColor = NSColor(srgbRed: lensRed, green: lensGreen, blue: lensBlue, alpha: 1.0)
    lensColor.setFill()

    let margin = CGFloat(size) / 3
    let circle = NSRect(x: margin, y: margin, width: nsSize.width - (margin * 2), height: nsSize.height - (margin * 2))
    NSBezierPath(ovalIn: circle).fill()

    image.unlockFocus()

    // Save as PNG
    let fileURL = URL(fileURLWithPath: "\(scriptDir)/\(filename)")
    guard let tiffData = image.tiffRepresentation,
          let bitmapImage = NSBitmapImageRep(data: tiffData),
          let pngData = bitmapImage.representation(using: .png, properties: [:]) else {
        print("✗ Failed to create \(filename)")
        continue
    }

    do {
        try pngData.write(to: fileURL, options: .atomic)
        print("✓ Created \(filename) (\(size)x\(size))")
    } catch {
        print("✗ Error writing \(filename): \(error)")
    }
}

print("\n✓ Icon generation complete!")
print("Your app icons are ready to use in Xcode.")
