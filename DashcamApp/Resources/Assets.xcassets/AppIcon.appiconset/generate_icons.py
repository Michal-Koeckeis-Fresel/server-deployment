#!/usr/bin/env python3
"""
Generate placeholder app icons for iOS development.
Run this script to create all required icon sizes.
"""

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Error: Pillow not installed. Install with: pip install Pillow")
    exit(1)

import os

# Icon sizes required for iOS
ICON_SIZES = [
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

def create_icon(size, filename):
    """Create a placeholder icon with the given size."""
    # Create image with DashCam brand colors (dark blue background)
    img = Image.new("RGB", (size, size), color=(25, 55, 100))
    draw = ImageDraw.Draw(img)

    # Add a simple camera icon representation
    margin = size // 6

    # Draw outer circle
    draw.ellipse(
        [margin, margin, size - margin, size - margin],
        outline=(100, 180, 255),
        width=max(1, size // 20)
    )

    # Draw inner circle (camera lens)
    inner_margin = size // 3
    draw.ellipse(
        [inner_margin, inner_margin, size - inner_margin, size - inner_margin],
        fill=(100, 180, 255)
    )

    # Save the image
    img.save(filename, "PNG")
    print(f"✓ Created {filename} ({size}x{size})")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("Generating iOS app icons...")
    print(f"Output directory: {script_dir}\n")

    for size, filename in ICON_SIZES:
        filepath = os.path.join(script_dir, filename)
        create_icon(size, filepath)

    print(f"\n✓ Generated {len(ICON_SIZES)} icon files")
    print("\nIcons are ready to use in Xcode.")
    print("You can now build the project without icon warnings.")

if __name__ == "__main__":
    main()
