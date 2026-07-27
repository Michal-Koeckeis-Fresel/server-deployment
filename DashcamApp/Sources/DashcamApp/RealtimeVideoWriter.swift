import AVFoundation
import CoreImage
import UIKit

class RealtimeVideoWriter {
    private var assetWriter: AVAssetWriter?
    private var videoInput: AVAssetWriterInput?
    private var audioInput: AVAssetWriterInput?
    private var pixelBufferAdapter: AVAssetWriterInputPixelBufferAdaptor?
    private let ciContext = CIContext()
    private var frameCount = 0
    private var sessionStarted = false
    private var startTime: CMTime = .zero
    private let writeQueue = DispatchQueue(label: "com.dashcam.videowrite")

    var isRecording: Bool {
        assetWriter?.status == .writing
    }

    func startRecording(to url: URL, videoSettings: [String: Any], audioSettings: [String: Any], sourceVideoTrack: AVCaptureDeviceInput?) throws {
        print("[RealtimeVideoWriter] Starting recording to: \(url.lastPathComponent)")
        print("[RealtimeVideoWriter] Video settings: \(videoSettings)")
        print("[RealtimeVideoWriter] Audio settings: \(audioSettings)")

        do {
            try FileManager.default.removeItem(at: url)
            print("[RealtimeVideoWriter] ✅ Cleared existing file at: \(url.lastPathComponent)")
        } catch {
            print("[RealtimeVideoWriter] ⚠️ Failed to remove existing file: \(error)")
        }

        assetWriter = try AVAssetWriter(outputURL: url, fileType: .mov)
        guard let writer = assetWriter else {
            print("[RealtimeVideoWriter] ❌ Failed to create AVAssetWriter")
            throw NSError(domain: "RealtimeVideoWriter", code: -1)
        }
        print("[RealtimeVideoWriter] ✅ AVAssetWriter created")

        videoInput = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
        guard let videoInput = videoInput else {
            print("[RealtimeVideoWriter] ❌ Failed to create video input")
            throw NSError(domain: "RealtimeVideoWriter", code: -2)
        }
        print("[RealtimeVideoWriter] ✅ Video input created")

        let pixelBufferAttributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: 1920,
            kCVPixelBufferHeightKey as String: 1080
        ]
        print("[RealtimeVideoWriter] Pixel buffer attributes: format=32BGRA, size=1920x1080")

        pixelBufferAdapter = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: videoInput,
            sourcePixelBufferAttributes: pixelBufferAttributes
        )
        print("[RealtimeVideoWriter] ✅ Pixel buffer adapter created")

        audioInput = AVAssetWriterInput(mediaType: .audio, outputSettings: audioSettings)
        guard let audioInput = audioInput else {
            print("[RealtimeVideoWriter] ❌ Failed to create audio input")
            throw NSError(domain: "RealtimeVideoWriter", code: -3)
        }
        print("[RealtimeVideoWriter] ✅ Audio input created")

        writer.add(videoInput)
        writer.add(audioInput)
        videoInput.expectsMediaDataInRealTime = true
        audioInput.expectsMediaDataInRealTime = true
        print("[RealtimeVideoWriter] ✅ Inputs added to writer, real-time mode enabled")

        if writer.startWriting() {
            frameCount = 0
            sessionStarted = false
            print("[RealtimeVideoWriter] ✅ Writer started successfully, ready for frames")
        } else {
            let error = writer.error ?? NSError(domain: "RealtimeVideoWriter", code: -4)
            print("[RealtimeVideoWriter] ❌ Writer failed to start: \(error)")
            throw error
        }
    }

    func processAndWriteFrame(_ pixelBuffer: CVPixelBuffer, timestamp: CMTime, watermarkText: String) {
        guard let writer = assetWriter, writer.status == .writing else {
            if frameCount == 0 {
                print("RealtimeVideoWriter: Writer not ready (status: \(assetWriter?.status.rawValue ?? -1))")
            }
            return
        }

        if !sessionStarted {
            sessionStarted = true
            startTime = timestamp
            writer.startSession(atSourceTime: CMTime.zero)
            print("RealtimeVideoWriter: Session started at timestamp \(timestamp)")
        }

        let adjustedTime = CMTimeSubtract(timestamp, startTime)

        writeQueue.async { [weak self] in
            guard let self = self else { return }
            guard let videoInput = self.videoInput else {
                if self.frameCount == 0 {
                    print("RealtimeVideoWriter: ERROR - videoInput is nil!")
                }
                return
            }
            guard let pixelBufferAdapter = self.pixelBufferAdapter else {
                if self.frameCount == 0 {
                    print("RealtimeVideoWriter: ERROR - pixelBufferAdapter is nil!")
                }
                return
            }

            if videoInput.isReadyForMoreMediaData {
                let watermarkedBuffer = self.addWatermark(to: pixelBuffer, text: watermarkText)
                if !pixelBufferAdapter.append(watermarkedBuffer, withPresentationTime: adjustedTime) {
                    print("RealtimeVideoWriter: Failed to write video frame at time \(adjustedTime)")
                } else if self.frameCount % 30 == 0 {
                    print("RealtimeVideoWriter: Wrote frame \(self.frameCount) at time \(adjustedTime)")
                }
                self.frameCount += 1
            } else if self.frameCount == 0 {
                print("RealtimeVideoWriter: Video input not ready for media data - will wait for buffer availability")
            }
        }
    }

    func writeAudioSample(_ sampleBuffer: CMSampleBuffer) {
        guard let writer = assetWriter, writer.status == .writing, let audioInput = audioInput else { return }

        if audioInput.isReadyForMoreMediaData {
            audioInput.append(sampleBuffer)
        }
    }

    func finishWriting(completion: @escaping (Bool, Error?) -> Void) {
        print("[RealtimeVideoWriter] Requesting writer finish (current frame count: \(frameCount))")
        writeQueue.async { [weak self] in
            guard let self = self else {
                print("[RealtimeVideoWriter] ❌ Self deallocated during finishWriting")
                completion(false, nil)
                return
            }

            guard let writer = self.assetWriter else {
                print("[RealtimeVideoWriter] ❌ Writer is nil during finishWriting")
                completion(false, nil)
                return
            }

            print("[RealtimeVideoWriter] Writer status before finish: \(writer.status.rawValue)")
            writer.finishWriting {
                DispatchQueue.main.async {
                    let success = writer.status == .completed
                    let error = writer.error
                    print("[RealtimeVideoWriter] ✅ Writer finished - Status: \(writer.status.rawValue), Frames: \(self.frameCount), Success: \(success)")
                    if let error = error {
                        print("[RealtimeVideoWriter] ❌ Writer error: \(error.localizedDescription)")
                    }
                    completion(success, error)
                }
            }
        }
    }

    private func addWatermark(to pixelBuffer: CVPixelBuffer, text: String) -> CVPixelBuffer {
        let ciImage = CIImage(cvPixelBuffer: pixelBuffer)

        let textLayer = CATextLayer()
        textLayer.string = text
        textLayer.fontSize = 32
        textLayer.foregroundColor = UIColor.white.cgColor
        textLayer.shadowOpacity = 0.8
        textLayer.shadowColor = UIColor.black.cgColor
        textLayer.shadowOffset = CGSize(width: 1, height: 1)
        textLayer.shadowRadius = 2
        textLayer.frame = CGRect(x: 20, y: 20, width: 1880, height: 100)

        let textCIImage = textLayer.render(in: CGRect(x: 0, y: 0, width: 1920, height: 1080))
        let composited = textCIImage.composited(over: ciImage)

        var outputBuffer: CVPixelBuffer?
        if let pool = pixelBufferAdapter?.pixelBufferPool {
            CVPixelBufferPoolCreatePixelBuffer(nil, pool, &outputBuffer)
        }

        if let outputBuffer = outputBuffer {
            ciContext.render(composited, to: outputBuffer)
            return outputBuffer
        }

        return pixelBuffer
    }
}

extension CALayer {
    func render(in rect: CGRect) -> CIImage {
        let renderer = UIGraphicsImageRenderer(size: rect.size)
        let image = renderer.image { context in
            self.render(in: context.cgContext)
        }
        return CIImage(cgImage: image.cgImage!)
    }
}
