import Foundation
import SwiftUI

class FPSCounter: NSObject, ObservableObject {
    @Published var currentFPS: Int = 0
    @Published var averageFPS: Float = 0.0

    private var frameTimestamps: [CFTimeInterval] = []
    private let maxFrames = 60
    private var displayLink: CADisplayLink?
    private let updateInterval = 0.5

    override init() {
        super.init()
    }

    func start() {
        frameTimestamps.removeAll()
        setupDisplayLink()
    }

    func stop() {
        displayLink?.invalidate()
        displayLink = nil
        frameTimestamps.removeAll()
    }

    private func setupDisplayLink() {
        displayLink = CADisplayLink(
            target: self,
            selector: #selector(updateFPS)
        )
        displayLink?.preferredFramesPerSecond = 60
        displayLink?.add(to: .main, forMode: .common)
    }

    @objc private func updateFPS() {
        let now = CACurrentMediaTime()
        frameTimestamps.append(now)

        if frameTimestamps.count > maxFrames {
            frameTimestamps.removeFirst()
        }

        if frameTimestamps.count > 1 {
            let oldestFrame = frameTimestamps.first ?? now
            let timeDelta = now - oldestFrame

            if timeDelta > 0 {
                let fps = Double(frameTimestamps.count - 1) / timeDelta
                DispatchQueue.main.async {
                    self.currentFPS = Int(fps)
                    self.averageFPS = Float(fps)
                }
            }
        }
    }

    func printFPSReport() {
        print("[FPSCounter] Current: \(currentFPS) fps, Average: \(String(format: "%.1f", averageFPS)) fps")
    }
}
