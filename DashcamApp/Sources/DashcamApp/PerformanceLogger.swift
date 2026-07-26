import Foundation
import SwiftUI

class PerformanceLogger: NSObject, ObservableObject {
    static let shared = PerformanceLogger()

    @Published var recordingFPS: Double = 0.0
    @Published var memoryUsageMB: Double = 0.0
    @Published var cpuUsagePercent: Double = 0.0
    @Published var storageWriteSpeedMBps: Double = 0.0
    @Published var isRecording: Bool = false

    private var frameCount = 0
    private var lastFrameTime: Date = Date()
    private var recordingStartTime: Date?
    private var initialStorageSize: Int64 = 0
    private var lastStorageCheck: Date = Date()
    private var performanceHistory: [PerformanceSnapshot] = []
    private let historyMaxSize = 600

    struct PerformanceSnapshot {
        let timestamp: Date
        let fps: Double
        let memory: Double
        let cpu: Double
        let writeSpeed: Double
    }

    func startRecording() {
        isRecording = true
        recordingStartTime = Date()
        frameCount = 0
        lastFrameTime = Date()
        performanceHistory.removeAll()
    }

    func stopRecording() {
        isRecording = false
        recordingStartTime = nil
        printPerformanceReport()
    }

    func recordFrame() {
        guard isRecording else { return }

        frameCount += 1
        let now = Date()
        let timeDelta = now.timeIntervalSince(lastFrameTime)

        if timeDelta >= 1.0 {
            recordingFPS = Double(frameCount) / timeDelta
            frameCount = 0
            lastFrameTime = now

            updateSystemMetrics()
            captureSnapshot()
        }
    }

    private func updateSystemMetrics() {
        memoryUsageMB = getMemoryUsage()
        cpuUsagePercent = estimateCPUUsage()
        storageWriteSpeedMBps = estimateStorageSpeed()
    }

    private func getMemoryUsage() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info>.size)/4

        let kerr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_,
                         task_flavor_t(TASK_VM_INFO),
                         $0,
                         &count)
            }
        }

        guard kerr == KERN_SUCCESS else { return 0 }
        return Double(info.resident_size) / (1024 * 1024)
    }

    private func estimateCPUUsage() -> Double {
        var threadList: thread_act_port_array_t?
        var threadCount: mach_msg_type_number_t = 0

        let kerr = task_threads(mach_task_self_, &threadList, &threadCount)
        guard kerr == KERN_SUCCESS else { return 0 }

        var totalTime: UInt64 = 0
        for i in 0..<Int(threadCount) {
            var threadInfo = thread_basic_info()
            var count = mach_msg_type_number_t(MemoryLayout<thread_basic_info>.size)/4

            let threadKerr = thread_info(threadList![i],
                                        thread_flavor_t(THREAD_BASIC_INFO),
                                        &threadInfo,
                                        &count)

            if threadKerr == KERN_SUCCESS {
                totalTime += UInt64(threadInfo.cpu_usage)
            }
        }

        return min(Double(totalTime) / Double(TH_USAGE_SCALE) * 100, 100.0)
    }

    private func estimateStorageSpeed() -> Double {
        let now = Date()
        let timeSinceLastCheck = now.timeIntervalSince(lastStorageCheck)

        guard timeSinceLastCheck >= 2.0 else { return storageWriteSpeedMBps }

        let currentStorageSize = getRecordingStorageSize()
        let bytesDelta = Int64(currentStorageSize) - initialStorageSize
        let megaBytesDelta = Double(bytesDelta) / (1024 * 1024)

        if timeSinceLastCheck > 0 {
            storageWriteSpeedMBps = megaBytesDelta / timeSinceLastCheck
        }

        initialStorageSize = Int64(currentStorageSize)
        lastStorageCheck = now

        return storageWriteSpeedMBps
    }

    private func getRecordingStorageSize() -> Int {
        guard let recordingsPath = StorageLocationManager.shared.getRecordingsURL() else {
            return 0
        }

        do {
            let fileManager = FileManager.default
            let files = try fileManager.contentsOfDirectory(at: recordingsPath, includingPropertiesForKeys: [.fileSizeKey])

            var totalSize = 0
            for file in files {
                if let attributes = try? fileManager.attributesOfItem(atPath: file.path) {
                    if let size = attributes[.size] as? Int {
                        totalSize += size
                    }
                }
            }
            return totalSize
        } catch {
            return 0
        }
    }

    private func captureSnapshot() {
        let snapshot = PerformanceSnapshot(
            timestamp: Date(),
            fps: recordingFPS,
            memory: memoryUsageMB,
            cpu: cpuUsagePercent,
            writeSpeed: storageWriteSpeedMBps
        )

        performanceHistory.append(snapshot)
        if performanceHistory.count > historyMaxSize {
            performanceHistory.removeFirst()
        }
    }

    private func printPerformanceReport() {
        guard !performanceHistory.isEmpty else { return }

        let avgFPS = performanceHistory.map { $0.fps }.reduce(0, +) / Double(performanceHistory.count)
        let avgMemory = performanceHistory.map { $0.memory }.reduce(0, +) / Double(performanceHistory.count)
        let avgCPU = performanceHistory.map { $0.cpu }.reduce(0, +) / Double(performanceHistory.count)
        let avgWriteSpeed = performanceHistory.map { $0.writeSpeed }.reduce(0, +) / Double(performanceHistory.count)

        let maxFPS = performanceHistory.map { $0.fps }.max() ?? 0
        let maxMemory = performanceHistory.map { $0.memory }.max() ?? 0
        let maxCPU = performanceHistory.map { $0.cpu }.max() ?? 0
        let maxWriteSpeed = performanceHistory.map { $0.writeSpeed }.max() ?? 0

        let timestamp = ISO8601DateFormatter().string(from: Date())
        print("""
        [Performance] [\(timestamp)] Recording Session Report
        ─────────────────────────────────────────────
        FPS:        Avg: \(String(format: "%.1f", avgFPS)) | Peak: \(String(format: "%.1f", maxFPS))
        Memory:     Avg: \(String(format: "%.1f", avgMemory)) MB | Peak: \(String(format: "%.1f", maxMemory)) MB
        CPU Usage:  Avg: \(String(format: "%.1f", avgCPU))% | Peak: \(String(format: "%.1f", maxCPU))%
        Write Speed: Avg: \(String(format: "%.1f", avgWriteSpeed)) MB/s | Peak: \(String(format: "%.1f", maxWriteSpeed)) MB/s
        ─────────────────────────────────────────────
        """)
    }

    func getPerformanceString() -> String {
        return "FPS: \(String(format: "%.1f", recordingFPS)) | Mem: \(String(format: "%.0f", memoryUsageMB))MB"
    }
}

import os

// Memory info structures
struct task_vm_info {
    var resident_size: UInt64 = 0
}

var task_vm_info_data_t = task_vm_info()

let TASK_VM_INFO = Int32(22)
let THREAD_BASIC_INFO = Int32(3)
let TH_USAGE_SCALE = Int32(16)
