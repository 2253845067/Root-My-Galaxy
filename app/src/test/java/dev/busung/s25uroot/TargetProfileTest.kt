package dev.busung.s25uroot

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetProfileTest {
    private val profile = TargetProfile(
        profileId = "galaxy-s25-series-2026-06-07",
        displayName = "Galaxy S25 series",
        models = setOf("SM-S931B", "SM-S938N"),
        builds = emptySet(),
        securityPatchMonths = setOf("2026-06", "2026-07"),
        exploit = RemoteArtifact("https://example.invalid/exploit", 1),
        kernelSu = RemoteArtifact("https://example.invalid/ksud", 1),
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

    private fun snapshot(
        model: String,
        securityPatch: String,
    ) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = "unused",
        kernelRelease = "unused",
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
