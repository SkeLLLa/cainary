import SwiftUI

/// The red-flag rules editor: the presets and the user's own patterns. Twin of
/// linux/crates/cainary-tray/qml/components/RedFlagRules.qml. Every edit goes out through
/// `onChange` with the whole new settings (the store applies it and restarts a running collector).
struct CollectorRulesView: View {
    let settings: CollectorSettings
    let onChange: (CollectorSettings) -> Void
    /// Off where the notify toggle already sits elsewhere.
    var showNotify = true
    /// Snapshots only: ImageRenderer draws AppKit controls as placeholders.
    var staticLayout = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Presets").font(.headline)
            LazyVGrid(
                columns: [
                    GridItem(.flexible(), alignment: .leading),
                    GridItem(.flexible(), alignment: .leading),
                ],
                alignment: .leading, spacing: 4
            ) {
                ForEach(CollectorPreset.all, id: \.name) { preset in
                    check(preset.title, presetBinding(preset.name))
                }
            }
            Text("Your own red flags").font(.headline).padding(.top, 6)
            if settings.patterns.isEmpty {
                Text(
                    "None. Add a customer name, a project code or anything else that must not leave this device."
                )
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(settings.patterns) { pattern in patternRow(pattern.id) }
            if settings.overLimit {
                warning(
                    "The enabled presets and valid patterns exceed the collector limit of \(CollectorPattern.maxTotal). Turn off a preset or remove a pattern."
                )
            }
            addButton
            Text(
                "Names use a–z, 0–9, - and _. Patterns reach the collector over a pipe, not its command line."
            )
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            if showNotify { check("Notify about red flags", notifyBinding) }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: edits

    private func edit(_ change: (inout CollectorSettings) -> Void) {
        var new = settings
        change(&new)
        onChange(new)
    }

    private func presetBinding(_ name: String) -> Binding<Bool> {
        Binding(
            get: { settings.presets.contains(name) },
            set: { on in
                edit {
                    $0.presets.removeAll { $0 == name }
                    if on { $0.presets.append(name) }
                }
            })
    }

    private var notifyBinding: Binding<Bool> {
        Binding(get: { settings.notify }, set: { on in edit { $0.notify = on } })
    }

    private func patternBinding(_ id: UUID) -> Binding<CollectorPattern> {
        Binding(
            get: { settings.patterns.first { $0.id == id } ?? CollectorPattern() },
            set: { updated in
                edit {
                    guard let i = $0.patterns.firstIndex(where: { $0.id == id }) else { return }
                    $0.patterns[i] = updated
                }
            })
    }

    // MARK: pieces

    private var addButton: some View {
        let full = settings.patterns.count >= CollectorPattern.maxTotal
        return Button {
            edit { $0.patterns.append(CollectorPattern()) }
        } label: {
            Text("Add pattern").font(.callout)
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain).disabled(full).opacity(full ? 0.5 : 1)
    }

    private func patternRow(_ id: UUID) -> some View {
        let pattern = patternBinding(id)
        let index = settings.patterns.firstIndex { $0.id == id }
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                field("Name", pattern.wrappedValue.name, monospaced: false) { value in
                    setPattern(id) { $0.name = value }
                }
                .frame(width: 130)
                field("Pattern", pattern.wrappedValue.pattern, monospaced: true) { value in
                    setPattern(id) { $0.pattern = value }
                }
            }
            HStack(spacing: 12) {
                check("Regex", pattern.isRegex)
                check("Match case", pattern.caseSensitive)
                Spacer()
                Button {
                    edit { $0.patterns.removeAll { $0.id == id } }
                } label: {
                    Label("Remove", systemImage: "minus.circle").font(.callout)
                }
                .buttonStyle(.plain)
            }
            if let index, let problem = settings.problem(at: index) {
                warning("\(problem) This pattern is not used.")
            }
        }
        .padding(8)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
    }

    private func warning(_ text: String) -> some View {
        Text(text).font(.caption).foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func check(_ title: String, _ value: Binding<Bool>) -> some View {
        if staticLayout {
            Label(title, systemImage: value.wrappedValue ? "checkmark.square.fill" : "square")
                .font(.callout)
        } else {
            Toggle(title, isOn: value).toggleStyle(.checkbox)
        }
    }

    /// A text field that applies on Return or when it loses focus, never per keystroke: each apply
    /// restarts a running collector and clears its feed.
    @ViewBuilder
    private func field(
        _ title: String, _ text: String, monospaced: Bool, commit: @escaping (String) -> Void
    ) -> some View {
        let font = monospaced ? Font.system(.body, design: .monospaced) : Font.body
        if staticLayout {
            Text(text.isEmpty ? title : text).font(font)
                .foregroundStyle(text.isEmpty ? .secondary : .primary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 6).padding(.vertical, 3)
                .background(.background, in: RoundedRectangle(cornerRadius: 4))
                .overlay(RoundedRectangle(cornerRadius: 4).stroke(.quaternary))
        } else {
            CommitField(title: title, committed: text, font: font, commit: commit)
        }
    }

    private func setPattern(_ id: UUID, _ change: (inout CollectorPattern) -> Void) {
        edit {
            guard let i = $0.patterns.firstIndex(where: { $0.id == id }) else { return }
            change(&$0.patterns[i])
        }
    }
}

/// Edits a draft of `committed` and hands it to `commit` on Return, on losing focus and when the
/// view goes away. A change to `committed` from outside replaces the draft while it isn't focused.
private struct CommitField: View {
    let title: String
    let committed: String
    let font: Font
    let commit: (String) -> Void

    @StateObject private var draft: DraftBox
    @FocusState private var focused: Bool

    init(title: String, committed: String, font: Font, commit: @escaping (String) -> Void) {
        self.title = title
        self.committed = committed
        self.font = font
        self.commit = commit
        _draft = StateObject(wrappedValue: DraftBox(committed))
    }

    var body: some View {
        TextField(title, text: $draft.text)
            .font(font)
            .focused($focused)
            .onSubmit(save)
            .onChange(of: focused) { _, now in if !now { save() } }
            .onChange(of: committed) { _, new in if !focused { draft.text = new } }
            .onDisappear(perform: save)
    }

    private func save() {
        if draft.text != committed { commit(draft.text) }
    }
}

/// The text being typed. A class: the toolchain has no `@State`.
@MainActor
final class DraftBox: ObservableObject {
    @Published var text: String

    init(_ text: String) {
        self.text = text
    }
}
