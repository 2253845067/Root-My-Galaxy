package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetProfileTest {
    private val profile = TargetProfile(
        profileId = "galaxy-s25-series-2026-06-07",
        displayName = "Galaxy S25 series",
        manufacturer = "samsung",
        supportedDevices = listOf(
            SupportedDevice("Galaxy S25", "SM-S931B", "International"),
            SupportedDevice("Galaxy S25 Ultra", "SM-S938N", "South Korea"),
        ),
        kernelRelease = KernelReleaseRule(
            exact = emptySet(),
            prefix = "6.6.",
            contains = "-android15-8-",
            suffix = "-4k",
        ),
        kernelBuildVersions = emptySet(),
        buildDisplays = emptySet(),
        securityPatchMonths = setOf("2026-06", "2026-07"),
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
        exploit = RemoteArtifact("https://example.invalid/exploit", 1),
        kernelSu = KernelSuArtifact(
            RemoteArtifact("https://example.invalid/ksud", 1),
            "android15-6.6",
            "me.weishu.kernelsu",
        ),
    )

    @Test
    fun matchesRegionalS25OnJuneAndJulyPatches() {
        assertTrue(profile.matches(snapshot("SM-S931B", "2026-06-01")))
        assertTrue(profile.matches(snapshot("SM-S938N", "2026-07-05")))
    }

    @Test
    fun rejectsUnlistedModelOrPatchMonth() {
        assertFalse(profile.matches(snapshot("SM-S928B", "2026-06-01")))
        assertFalse(profile.matches(snapshot("SM-S938N", "2026-08-01")))
    }

    @Test
    fun rejectsDifferentKernelFamily() {
        assertFalse(
            profile.matches(
                snapshot(
                    model = "SM-S938N",
                    securityPatch = "2026-06-01",
                    kernelRelease = "6.1.145-android14-11-abS938N-4k",
                ),
            ),
        )
    }

    private fun snapshot(
        model: String,
        securityPatch: String,
        kernelRelease: String = "6.6.102-android15-8-abS938BCZG1-4k",
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = kernelRelease,
        kernelBuildVersion = "#1 SMP PREEMPT",
        buildId = "BP4A.251205.006.S938BCZG1",
        fingerprint = "samsung/example",
        androidRelease = "16",
        securityPatch = securityPatch,
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )
}
