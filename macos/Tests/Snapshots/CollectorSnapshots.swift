import Foundation
import SwiftUI

// The collector pane (design §9) on the sample lines of the contract (Tests/Support). The Details
// split view doesn't render in ImageRenderer, so the pane is rendered directly.

@MainActor
func collectorSnapshot(out: URL) {
    func event(_ line: String) -> CollectorEvent { CollectorEvent.decode(CollectorSamples.data(line)) }
    guard case .hello(let hello) = event(CollectorSamples.hello),
        case .batch(let batch) = event(CollectorSamples.batch),
        case .alert(let alert) = event(CollectorSamples.alert)
    else {
        check("collector.png: sample lines decode", false)
        return
    }
    let batches = (1...2).map {
        StoredBatch(id: $0, batch: batch, line: CollectorSamples.data(CollectorSamples.batch))
    }
    let alerts = [StoredAlert(id: 3, alert: alert, lineBytes: 300)]
    let pane = CollectorPaneView(
        state: .listening(hello), batches: batches, alerts: alerts, batchTotal: 2, alertTotal: 1,
        lastError: nil, onRetry: {}, onOpenSettings: {}
    )
    .frame(width: 570, alignment: .topLeading)
    let file = "collector.png"
    let url = out.appendingPathComponent(file)
    checkPNG(file, url, size: writePNG(pane, to: url), heights: 100...6000)

    let off = CollectorPaneView(
        state: .failed("Stopped: bind 127.0.0.1:4318: address in use"), batches: [], alerts: [],
        batchTotal: 0, alertTotal: 0, lastError: nil, onRetry: {}, onOpenSettings: {}
    )
    .frame(width: 570, alignment: .topLeading)
    let failedFile = "collector-failed.png"
    let failedURL = out.appendingPathComponent(failedFile)
    checkPNG(failedFile, failedURL, size: writePNG(off, to: failedURL), heights: 100...6000)
}
