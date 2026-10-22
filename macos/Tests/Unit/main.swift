import Foundation

// The one entry point of the unit-test binary. Each suite task adds its call here.

@main
enum UnitTests {
    @MainActor
    static func main() async {
        // A closed helper pipe must give EPIPE, not kill the test binary.
        signal(SIGPIPE, SIG_IGN)

        decodeTests()
        trackerTests()
        notifierTests()
        statusMenuTests()
        await stateTests()
        await clientTests()
        await storeTests()
        await trackingStoreTests()
        await copyReportStoreTests()

        exit(finishChecks())
    }
}
