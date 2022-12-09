plugins {
    alias(libs.plugins.agp.app) apply false
    alias(libs.plugins.kotlin) apply false
    alias(libs.plugins.compose.compiler) apply false
}

val androidMinSdkVersion by extra(26)
val androidTargetSdkVersion by extra(36)
val androidCompileSdkVersion by extra(36)
val androidBuildToolsVersion by extra("36.1.0")
val androidCompileNdkVersion by extra(libs.versions.ndk.get())
val androidSourceCompatibility by extra(JavaVersion.VERSION_21)
val androidTargetCompatibility by extra(JavaVersion.VERSION_21)
val managerVersionCode by extra(getVersionCode())
val managerVersionName by extra(getVersionName())

fun getGitCommitCount(): Int {
    val pb = ProcessBuilder("git", "rev-list", "--count", "HEAD")
        .directory(rootProject.projectDir)
        .redirectErrorStream(true)
    val process = pb.start()
    val output = process.inputStream.bufferedReader().use { it.readText().trim() }
    return output.toIntOrNull() ?: 1
}

fun getGitDescribe(): String {
    val pb = ProcessBuilder("git", "describe", "--tags", "--always")
        .directory(rootProject.projectDir)
        .redirectErrorStream(true)
    val process = pb.start()
    val output = process.inputStream.bufferedReader().use { it.readText().trim() }
    return output.ifEmpty { "dev" }
}

fun getVersionCode(): Int {
    val commitCount = getGitCommitCount()
    return 30000 + commitCount
}

fun getVersionName(): String {
    return getGitDescribe()
}
