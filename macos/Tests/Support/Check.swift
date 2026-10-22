import Foundation

// A tiny test harness: no XCTest in the Command Line Tools. `check` records a failure by name
// and the test binary exits non-zero if any check failed.

@MainActor
enum Checks {
    static var total = 0
    static var failures: [String] = []
}

/// Records one named check. A failure is printed at once.
@MainActor
func check(_ name: String, _ condition: @autoclosure () -> Bool) {
    Checks.total += 1
    if !condition() {
        Checks.failures.append(name)
        print("FAIL  \(name)")
    }
}

/// Checks that `body` throws.
@MainActor
func checkThrows(_ name: String, _ body: () throws -> Void) {
    do {
        try body()
        check(name, false)
    } catch {
        check(name, true)
    }
}

/// Prints the totals and returns the process exit code.
@MainActor
func finishChecks() -> Int32 {
    let failed = Checks.failures.count
    print("\(Checks.total - failed)/\(Checks.total) checks passed")
    return failed == 0 ? 0 : 1
}

/// The repo root: `CAINARY_ROOT` when set (run.sh sets it), else the working directory.
func repoRoot() -> URL {
    let path =
        ProcessInfo.processInfo.environment["CAINARY_ROOT"]
        ?? FileManager.default.currentDirectoryPath
    return URL(fileURLWithPath: path, isDirectory: true)
}

/// A fresh scratch directory under `$TMPDIR`.
func scratchDirectory(_ name: String) -> URL {
    let tmp = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
    let dir = URL(fileURLWithPath: tmp, isDirectory: true)
        .appendingPathComponent(
            "cainary-tests-\(ProcessInfo.processInfo.processIdentifier)-\(name)")
    try? FileManager.default.removeItem(at: dir)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}
