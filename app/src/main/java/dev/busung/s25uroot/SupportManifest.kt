package dev.busung.s25uroot

import org.json.JSONArray
import org.json.JSONObject

data class RemoteArtifact(
    val url: String,
    val size: Long,
)

data class TargetProfile(
    val profileId: String,
    val displayName: String,
    val models: Set<String>,
    val builds: Set<String>,
    val securityPatchMonths: Set<String>,
    val exploit: RemoteArtifact,
    val kernelSu: RemoteArtifact,
) {
    init {
        require(models.isNotEmpty()) { "Payload must support at least one model" }
        require(builds.isNotEmpty() || securityPatchMonths.isNotEmpty()) {
            "Payload must restrict builds or security patch months"
        }
    }

    fun matchesDevice(snapshot: DeviceSnapshot): Boolean =
        models.any { it.equals(snapshot.model, ignoreCase = true) }

    fun matchesBuild(snapshot: DeviceSnapshot): Boolean =
        (builds.isEmpty() || snapshot.buildId in builds) &&
            (securityPatchMonths.isEmpty() || snapshot.securityPatchMonth in securityPatchMonths)

    fun matches(snapshot: DeviceSnapshot): Boolean =
        matchesDevice(snapshot) && matchesBuild(snapshot)

    val supportedModels: String
        get() = models.joinToString()

    val buildDescription: String
        get() = if (builds.isNotEmpty()) {
            builds.joinToString()
        } else {
            securityPatchMonths.joinToString()
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
                    val exploit = payload.getJSONObject("exploit")
                    val kernelSu = payload.getJSONObject("kernelsu")
                    add(
                        TargetProfile(
                            profileId = payload.getString("payloadId"),
                            displayName = payload.getString("displayName"),
                            models = payload.getJSONArray("models").strings(),
                            builds = payload.optJSONArray("builds")?.strings().orEmpty(),
                            securityPatchMonths = payload
                                .optJSONArray("securityPatchMonths")?.strings().orEmpty(),
                            exploit = RemoteArtifact(
                                url = exploit.getString("url"),
                                size = exploit.getLong("size"),
                            ),
                            kernelSu = RemoteArtifact(
                                url = kernelSu.getString("url"),
                                size = kernelSu.getLong("size"),
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
    }
}
