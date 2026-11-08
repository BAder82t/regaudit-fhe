// Draws the application icon: the regaudit artwork on a white rounded tile, at every size macOS asks for.
// usage: make_icon <icon.png> <output.iconset>      then: iconutil -c icns <output.iconset>
//
// Copyright (C) 2026 VaultBytes Innovations Ltd
// Licensed under AGPL-3.0-or-later.

import AppKit
import Foundation

let args = CommandLine.arguments
guard args.count == 3, let mark = NSImage(contentsOf: URL(fileURLWithPath: args[1])) else {
    FileHandle.standardError.write(Data("usage: make_icon <icon.png> <output.iconset>\n".utf8))
    exit(2)
}
try FileManager.default.createDirectory(atPath: args[2], withIntermediateDirectories: true)

let sizes: [(String, Int)] = [
    ("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128),
    ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024),
]
for (name, px) in sizes {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)
    else { exit(1) }
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let s = CGFloat(px)
    let inset = s * 0.05
    let tile = NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let path = NSBezierPath(roundedRect: tile, xRadius: tile.width * 0.2237, yRadius: tile.height * 0.2237)
    NSColor.white.setFill()
    path.fill()
    // The artwork has its own white margin, so it is drawn larger than a bare mark would be, and clipped to the tile so
    // that its square corners can never show outside the rounded tile. The outline is drawn last, on top.
    NSGraphicsContext.saveGraphicsState()
    path.addClip()
    let m = s * 0.8
    mark.draw(in: NSRect(x: (s - m) / 2, y: (s - m) / 2, width: m, height: m), from: .zero,
              operation: .sourceOver, fraction: 1)
    NSGraphicsContext.restoreGraphicsState()
    NSColor(calibratedRed: 0, green: 0.4, blue: 1, alpha: 0.35).setStroke()
    path.lineWidth = max(1, s * 0.012)
    path.stroke()
    NSGraphicsContext.restoreGraphicsState()
    guard let png = rep.representation(using: .png, properties: [:]) else { exit(1) }
    try png.write(to: URL(fileURLWithPath: "\(args[2])/icon_\(name).png"))
}
