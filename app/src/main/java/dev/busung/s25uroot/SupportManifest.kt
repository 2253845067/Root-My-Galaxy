package dev.busung.s25uroot

import org.json.JSONArray
import org.json.JSONObject

data class RemoteArtifact(
    val url: String,
    val size: Long,
)

data class KernelSuArtifact(
    val artifact: RemoteArtifact,
    val kmi: String,
    val managerPackage: String,
)

data class SupportedDevice(
    val name: String,
    val model: String,
    val region: String,
)

data class KernelReleaseRule(
    val exact: Set<String>,
    val prefix: String,
    val contains: String,
    val suffix: String,
) {
    init {
        require(exact.isNotEmpty() || listOf(prefix, contains, suffix).all(String::isNotEmpty)) {
            "Kernel release rule must be exact or fully bounded"
        }
    }

    fun matches(release: String): Boolean = if (exact.isNotEmpty()) {
        release in exact
    } else {
        release.startsWith(prefix) && release.contains(contains) && release.endsWith(suffix)
    }

    val description: String
        get() = if (exact.size == 1) {
            exact.first()
        } else if (exact.isNotEmpty()) {
            exact.joinToString()
        } else {
            "$prefix*$contains*$suffix"
        }
}

data class TargetProfile(
    val profileId: String,
    val displayName: String,
    val manufacturer: String,
    val supportedDevices: List<SupportedDevice>,
    val kernelRelease: KernelReleaseRule,
    val kernelBuildVersions: Set<String>,
    val buildDisplays: Set<String>,
    val securityPatchMonths: Set<String>,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
    val exploit: RemoteArtifact,
    val kernelSu: KernelSuArtifact,
) {
    init {
        require(supportedDevices.isNotEmpty()) { "Payload must support at least one device" }
    }

    fun matchesDevice(snapshot: DeviceSnapshot): Boolean =
        manufacturer.equals(snapshot.manufacturer, ignoreCase = true) &&
            supportedDevices.any { it.model.equals(snapshot.model, ignoreCase = true) }

    fun matchesKernel(snapshot: DeviceSnapshot): Boolean =
        kernelRelease.matches(snapshot.kernelRelease) &&
            (kernelBuildVersions.isEmpty() || snapshot.kernelBuildVersion in kernelBuildVersions)

    fun matchesBuild(snapshot: DeviceSnapshot): Boolean =
        (buildDisplays.isEmpty() || snapshot.buildId in buildDisplays) &&
            (securityPatchMonths.isEmpty() || snapshot.securityPatchMonth in securityPatchMonths)

    fun matches(snapshot: DeviceSnapshot): Boolean =
        matchesDevice(snapshot) &&
            matchesKernel(snapshot) &&
            matchesBuild(snapshot) &&
            sdk == snapshot.sdk &&
            abi == snapshot.abi &&
            pageSize == snapshot.pageSize

    val supportedModels: String
        get() = supportedDevices.joinToString { it.model }

    val buildDescription: String
        get() = when {
            buildDisplays.isNotEmpty() -> buildDisplays.joinToString()
            securityPatchMonths.isNotEmpty() -> securityPatchMonths.joinToString()
            else -> "Any listed-device build"
        }
}

data class SupportManifest(
    val schemaVersion: Int,
    val targets: List<TargetProfile>,
) {
    companion object {
        fun parse(bytes: ByteArray): SupportManifest {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.getInt("schemaVersion")
            require(schemaVersion == 3) { "Unsupported support manifest schema" }
            val payloadsJson = root.getJSONArray("payloads")
            val payloads = buildList {
                for (index in 0 until payloadsJson.length()) {
                    val payload = payloadsJson.getJSONObject(index)
                    val compatibility = payload.getJSONObject("compatibility")
                    val kernelRelease = compatibility.getJSONObject("kernelRelease")
                    val exploit = payload.getJSONObject("exploit")
                    val kernelSu = payload.getJSONObject("kernelsu")
                    add(
                        TargetProfile(
                            profileId = payload.getString("payloadId"),
                            displayName = payload.getString("displayName"),
                            manufacturer = compatibility.getString("manufacturer"),
                            supportedDevices = compatibility.getJSONArray("supportedDevices")
                                .objects { device ->
                                    SupportedDevice(
                                        name = device.getString("name"),
                                        model = device.getString("model"),
                                        region = device.getString("region"),
                                    )
                                },
                            kernelRelease = KernelReleaseRule(
                                exact = kernelRelease.getJSONArray("exact").strings(),
                                prefix = kernelRelease.getString("prefix"),
                                contains = kernelRelease.getString("contains"),
                                suffix = kernelRelease.getString("suffix"),
                            ),
                            kernelBuildVersions = compatibility
                                .getJSONArray("kernelBuildVersions").strings(),
                            buildDisplays = compatibility.getJSONArray("buildDisplays").strings(),
                            securityPatchMonths = compatibility
                                .getJSONArray("securityPatchMonths").strings(),
                            sdk = compatibility.getInt("sdk"),
                            abi = compatibility.getString("abi"),
                            pageSize = compatibility.getLong("pageSize"),
                            exploit = RemoteArtifact(
                                url = exploit.getString("url"),
                                size = exploit.getLong("size"),
                            ),
                            kernelSu = KernelSuArtifact(
                                artifact = RemoteArtifact(
                                    url = kernelSu.getString("url"),
                                    size = kernelSu.getLong("size"),
                                ),
                                kmi = kernelSu.getString("kmi"),
                                managerPackage = kernelSu.getString("managerPackage"),
                            ),
                        ),
                    )
                }
            }
            return SupportManifest(schemaVersion, payloads)
        }

        private fun JSONArray.strings(): Set<String> = buildSet {
            for (index in 0 until length()) add(getString(index))
        }

        private fun <T> JSONArray.objects(transform: (JSONObject) -> T): List<T> = buildList {
            for (index in 0 until length()) add(transform(getJSONObject(index)))
        }
    }
}
