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
    val module: RemoteArtifact? = null,
)

data class TargetProfile(
    val profileId: String,
    val manufacturer: String,
    val model: String,
    val device: String,
    val kernelRelease: String,
    val kernelBuildVersion: String,
    val buildDisplay: String,
    val buildFingerprint: String,
    val sdk: Int,
    val abi: String,
    val pageSize: Long,
    val exploit: RemoteArtifact,
    val kernelSu: KernelSuArtifact,
    private val v3DisplayName: String? = null,
    private val v3Models: Set<String>? = null,
    private val v3KernelVersions: Set<String>? = null,
    val requiresFreshP0Session: Boolean = false,
) {
    private fun normalizedKernelBuildVersion(value: String): String =
        value.trim().replace(Regex("\\s+"), " ")

    fun matchesKernel(snapshot: DeviceSnapshot): Boolean =
        if (v3KernelVersions != null) {
            snapshot.kernelVersion in v3KernelVersions
        } else {
            kernelRelease == snapshot.kernelRelease &&
                normalizedKernelBuildVersion(kernelBuildVersion) ==
                    normalizedKernelBuildVersion(snapshot.kernelVersionInfo)
        }

    fun matches(snapshot: DeviceSnapshot): Boolean =
        if (v3KernelVersions != null) {
            matchesDevice(snapshot) && matchesKernel(snapshot)
        } else {
            matchesKernel(snapshot) &&
                buildDisplay == snapshot.buildId &&
                sdk == snapshot.sdk &&
                abi == snapshot.abi &&
                pageSize == snapshot.pageSize
        }

    // --- Bridge properties for v3 UI compatibility ---

    val displayName: String
        get() = v3DisplayName ?: "$model $kernelRelease"

    val models: List<String>
        get() = (v3Models ?: setOf(model)).toList()

    val supportedModels: String
        get() = models.joinToString()

    val supportedKernelVersions: String
        get() = v3KernelVersions?.joinToString() ?: "$kernelRelease / $kernelBuildVersion"

    fun matchesDevice(snapshot: DeviceSnapshot): Boolean =
        models.any { it.equals(snapshot.model, ignoreCase = true) }

    fun matchesKernelVersion(snapshot: DeviceSnapshot): Boolean =
        if (v3KernelVersions != null) snapshot.kernelVersion in v3KernelVersions
        else matchesKernel(snapshot)

    /** Constructor for the schema-v3 model/kernel-version feed. */
    constructor(
        profileId: String,
        displayName: String,
        models: Set<String>,
        kernelVersions: Set<String>,
        exploit: RemoteArtifact,
        kernelSu: RemoteArtifact,
        requiresFreshP0Session: Boolean = false,
    ) : this(
        profileId = profileId,
        manufacturer = "",
        model = models.firstOrNull().orEmpty(),
        device = "",
        kernelRelease = kernelVersions.firstOrNull().orEmpty(),
        kernelBuildVersion = "",
        buildDisplay = "",
        buildFingerprint = "",
        sdk = 0,
        abi = "",
        pageSize = 0,
        exploit = exploit,
        kernelSu = KernelSuArtifact(kernelSu, "", ""),
        v3DisplayName = displayName,
        v3Models = models,
        v3KernelVersions = kernelVersions,
        requiresFreshP0Session = requiresFreshP0Session,
    )
}

data class SupportManifest(
    val schemaVersion: Int,
    val targets: List<TargetProfile>,
) {
    companion object {
        fun parse(bytes: ByteArray): SupportManifest {
            val root = JSONObject(bytes.toString(Charsets.UTF_8))
            val schemaVersion = root.getInt("schemaVersion")
            return when (schemaVersion) {
                2 -> SupportManifest(schemaVersion, parseV2(root.getJSONArray("targets")))
                3 -> SupportManifest(schemaVersion, parseV3(root.getJSONArray("payloads")))
                else -> error("Unsupported support manifest schema")
            }
        }

        private fun parseV2(targetsJson: JSONArray): List<TargetProfile> = buildList {
            for (index in 0 until targetsJson.length()) {
                val target = targetsJson.getJSONObject(index)
                val exploit = target.getJSONObject("exploit")
                val kernelSu = target.getJSONObject("kernelsu")
                add(
                    TargetProfile(
                        profileId = target.getString("profileId"),
                        manufacturer = target.getString("manufacturer"),
                        model = target.getString("model"),
                        device = target.getString("device"),
                        kernelRelease = target.getString("kernelRelease"),
                        kernelBuildVersion = target.getString("kernelBuildVersion"),
                        buildDisplay = target.getString("buildDisplay"),
                        buildFingerprint = target.getString("buildFingerprint"),
                        sdk = target.getInt("sdk"),
                        abi = target.getString("abi"),
                        pageSize = target.getLong("pageSize"),
                        exploit = RemoteArtifact(exploit.getString("url"), exploit.getLong("size")),
                        kernelSu = parseKernelSuV2(kernelSu),
                        requiresFreshP0Session = target.optBoolean("requiresFreshP0Session", false),
                    ),
                )
            }
        }

        private fun parseV3(payloadsJson: JSONArray): List<TargetProfile> = buildList {
            for (index in 0 until payloadsJson.length()) {
                val payload = payloadsJson.getJSONObject(index)
                val exploit = payload.getJSONObject("exploit")
                val kernelSu = payload.getJSONObject("kernelsu")
                add(
                    TargetProfile(
                        profileId = payload.getString("payloadId"),
                        displayName = payload.getString("displayName"),
                        models = payload.getJSONArray("models").strings(),
                        kernelVersions = payload.getJSONArray("kernelVersions").strings(),
                        exploit = RemoteArtifact(exploit.getString("url"), exploit.getLong("size")),
                        kernelSu = RemoteArtifact(kernelSu.getString("url"), kernelSu.getLong("size")),
                        requiresFreshP0Session = payload.optBoolean("requiresFreshP0Session", false),
                    ),
                )
            }
        }

        private fun parseKernelSuV2(kernelSu: JSONObject): KernelSuArtifact = KernelSuArtifact(
            artifact = RemoteArtifact(kernelSu.getString("url"), kernelSu.getLong("size")),
            kmi = kernelSu.getString("kmi"),
            managerPackage = kernelSu.getString("managerPackage"),
            module = kernelSu.optJSONObject("module")?.let { module ->
                RemoteArtifact(module.getString("url"), module.getLong("size"))
            },
        )

        private fun JSONArray.strings(): Set<String> = buildSet {
            for (index in 0 until length()) add(getString(index))
        }
    }
}
