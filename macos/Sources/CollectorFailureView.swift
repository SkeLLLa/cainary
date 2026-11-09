import SwiftUI

/// Where a failure's fix lives.
enum FailureFix: Equatable {
    case settings
    case setup
    case rules
    case none
}

/// What to tell the user about a `CollectorFailure`: a specific message per code and where the fix
/// is. Twin of linux/crates/cainary-tray/qml/components/CollectorFailure.qml.
struct FailureAdvice: Equatable {
    var message: String
    var fix: FailureFix

    /// The port a failure is about: the one it names, else the effective one (the takeover port in
    /// takeover mode, else the HTTP port).
    static func port(_ failure: CollectorFailure, in settings: CollectorSettings) -> Int {
        failure.port ?? (settings.takeover ? settings.takeoverPort : settings.port)
    }

    /// The settings with the failed port moved to the next one, for "Try port N+1": the takeover port
    /// when the failed port is it, else the HTTP port. Nil unless the port is in use and the next
    /// one is in range.
    static func tryNextPort(_ failure: CollectorFailure, in settings: CollectorSettings) -> (
        port: Int, settings: CollectorSettings
    )? {
        guard failure.code == "port-in-use" else { return nil }
        let port = Self.port(failure, in: settings)
        var next = settings
        if settings.takeover, port == settings.takeoverPort {
            guard CollectorSettings.takeoverPortRange.contains(port + 1) else { return nil }
            next.takeoverPort = port + 1
        } else if port == settings.port {
            guard CollectorSettings.portRange.contains(port + 1) else { return nil }
            next.port = port + 1
        } else {
            return nil
        }
        return (port + 1, next)
    }

    /// `takeover` is whether the HTTPS takeover is on: its port is set in Setup, not Settings.
    init(_ failure: CollectorFailure, takeover: Bool = false) {
        let place = takeover ? "Setup" : "Settings"
        let portFix: FailureFix = takeover ? .setup : .settings
        switch failure.code {
        case "port-in-use":
            let port = failure.port.map { "Port " + String($0) } ?? "The collector port"
            message =
                "\(port) is already in use. Choose another port in \(place), or quit the program that is using it."
            fix = portFix
        case "port-range":
            message = failure.message + " Change it in \(place)."
            fix = portFix
        case "patterns":
            message = failure.message + " Turn off a preset or remove a pattern in Rules."
            fix = .rules
        case "tls-no-host":
            message = "The HTTPS takeover needs at least one host name. Add one in Setup."
            fix = .setup
        case "tls-bad-host", "tls-too-many-hosts":
            message = failure.message + " Fix the host names in Setup."
            fix = .setup
        default:
            message = failure.message
            fix = .none
        }
    }
}

/// The banner shown while the collector has failed to start or has stopped.
struct CollectorFailureView: View {
    let failure: CollectorFailure
    let onRetry: () -> Void
    /// Opens Settings or Setup, whichever `FailureAdvice.fix` names.
    let onOpenSettings: () -> Void
    let onOpenSetup: () -> Void
    /// Opens the Rules tab, for the "patterns" failure.
    var onOpenRules: () -> Void = {}
    /// The HTTPS takeover is on: port failures are fixed in Setup.
    var takeover = false
    let onShowLogs: () -> Void
    /// The next free port to offer, from `FailureAdvice.tryNextPort`; nil hides the button.
    var nextPort: Int?
    var onTryPort: (Int) -> Void = { _ in }

    var body: some View {
        let advice = FailureAdvice(failure, takeover: takeover)
        VStack(alignment: .leading, spacing: 8) {
            Label {
                Text(advice.message).fontWeight(.semibold)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange)
            HStack(spacing: 8) {
                button("Retry", onRetry)
                switch advice.fix {
                case .settings: button("Open Settings", onOpenSettings)
                case .setup: button("Open Setup", onOpenSetup)
                case .rules: button("Open Rules", onOpenRules)
                case .none: EmptyView()
                }
                if let nextPort {
                    button("Try port " + String(nextPort)) { onTryPort(nextPort) }
                }
                button("Show logs", onShowLogs)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.orange.opacity(0.4)))
    }

    private func button(_ title: String, _ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title).font(.callout)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
    }
}
