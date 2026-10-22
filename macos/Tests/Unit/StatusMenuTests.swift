import AppKit

// StatusItemMenu.menu(): the right-click menu mirrors the popover's "More" menu plus Open details.

@MainActor
func statusMenuTests() {
    var ran: [String] = []
    let actions = PopoverActions(
        openDetails: { ran.append("details") }, copyReport: { ran.append("copy") },
        openSupport: { ran.append($0.host ?? "") })

    let menu = StatusItemMenu.menu(actions: actions, canCopy: false)
    let titles = menu.items.map { $0.isSeparatorItem ? "-" : $0.title }
    check(
        "status menu: items in order",
        titles == [
            "Open details", "Copy report", "-", "Settings…", "About cAInary", "Support Ukraine",
            "-",
            "Quit cAInary",
        ])
    check("status menu: copy disabled without a report", menu.items[1].isEnabled == false)
    check(
        "status menu: copy enabled with a report",
        StatusItemMenu.menu(actions: actions, canCopy: true).items[1].isEnabled)
    check(
        "status menu: support links",
        menu.items[5].submenu?.items.map(\.title) == SupportLinks.all.map(\.title))

    // Target/action directly: performActionForItem needs a running NSApplication.
    func run(_ item: NSMenuItem?) { _ = (item?.target as? NSObject)?.perform(item?.action) }
    run(menu.items[0])
    run(menu.items[5].submenu?.items.first)
    check("status menu: items run their actions", ran == ["details", "savelife.in.ua"])
}
