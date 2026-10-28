import Foundation

/// Funds suggested instead of donating to the author; the same list as the README.
enum SupportLinks {
    struct Link: Identifiable {
        var id: String { title }
        let title: String
        let url: URL
    }

    static let note =
        "If cAInary is useful to you, please consider supporting Ukrainian defenders instead of sending money to the author."

    static let all: [Link] = [
        Link(title: "Come Back Alive", url: URL(string: "https://savelife.in.ua/en/donate-en/")!),
        Link(title: "Sternenko Fund", url: URL(string: "https://www.sternenkofund.org/en/donate")!),
        Link(
            title: "Prytula Foundation",
            url: URL(string: "https://prytulafoundation.org/en/donation")!),
    ]

    /// A referral link, shown only in Settings and About, never next to scan results.
    static let proton = Link(title: "Proton", url: URL(string: "https://pr.tn/ref/28M5WB8J")!)

    static let protonNote =
        "Private email, VPN, passwords and storage. This is a referral link: signing up through it gives the author a credit, at no cost to you."
}
