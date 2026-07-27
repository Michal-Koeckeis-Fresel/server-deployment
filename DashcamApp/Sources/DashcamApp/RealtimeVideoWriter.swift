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
    private var startTime: CMTime = .zero
    private let writeQueue = DispatchQueue(label: "com.dashcam.videowrite")

    var isRecording: Bool {
        assetWriter?.status == .writing
    }

    func startRecording(to url: URL, videoSettings: [String: Any], audioSettings: [String: Any], sourceVideoTrack: AVCaptureDeviceInput?) throws {
        try FileManager.default.removeItem(at: url)

        assetWriter = try AVAssetWriter(outputURL: url, fileType: .mov)
        guard let writer = assetWriter else { throw NSError(domain: "RealtimeVideoWriter", code: -1) }

        videoInput = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
        guard let videoInput = videoInput else { throw NSError(domain: "RealtimeVideoWriter", code: -2) }

        let pixelBufferAttributes: [String: Any] = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32ARGB,
            kCVPixelBufferWidthKey as String: 1920,
            kCVPixelBufferHeightKey as String: 1080
        ]

        pixelBufferAdapter = AVAssetWriterInputPixelBufferAdaptor(
            assetWriterInput: videoInput,
            sourcePixelBufferAttributes: pixelBufferAttributes
        )

        audioInput = AVAssetWriterInput(mediaType: .audio, outputSettings: audioSettings)
        guard let audioInput = audioInput else { throw NSError(domain: "RealtimeVideoWriter", code: -3) }

        writer.add(videoInput)
        writer.add(audioInput)
        videoInput.expectsMediaDataInRealTime = true
        audioInput.expectsMediaDataInRealTime = true

        if writer.startWriting() {
            frameCount = 0
            print("Video writer started recording to \(url.lastPathComponent)")
        } else {
            throw writer.error ?? NSError(domain: "RealtimeVideoWriter", code: -4)
        }
    }

    func processAndWriteFrame(_ pixelBuffer: CVPixelBuffer, timestamp: CMTime, watermarkText: String) {
        guard let writer = assetWriter, writer.status == .writing else { return }

        if frameCount == 0 {
            startTime = timestamp
            writeQueue.async {
                self.videoInput?.requestMediaDataWhenReady(on: self.writeQueue) { }
            }
        }

        let adjustedTime = CMTimeSubtract(timestamp, startTime)

        writeQueue.async { [weak self] in
            guard let self = self, let videoInput = self.videoInput else { return }

            if videoInput.isReadyForMoreMediaData {
                let watermarkedBuffer = self.addWatermark(to: pixelBuffer, text: watermarkText)
                if self.pixelBufferAdapter?.append(watermarkedBuffer, withPresentationTime: adjustedTime) == false {
                    print("Failed to write video frame at time \(adjustedTime)")
                }
            }

            self.frameCount += 1
        }
    }

    func writeAudioSample(_ sampleBuffer: CMSampleBuffer) {
        guard let writer = assetWriter, writer.status == .writing, let audioInput = audioInput else { return }

        if audioInput.isReadyForMoreMediaData {
            audioInput.append(sampleBuffer)
        }
    }

    func finishWriting(completion: @escaping (Bool, Error?) -> Void) {
        writeQueue.async { [weak self] in
            guard let self = self, let writer = self.assetWriter else {
                completion(false, nil)
                return
            }

            writer.finishWriting {
                DispatchQueue.main.async {
                    let success = writer.status == .completed
                    let error = writer.error
                    print("Video writing finished: \(success), frames written: \(self.frameCount)")
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
