plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "auth-platform"

include("auth-server")
include("iam-server")
include("gateway")
include("resource-server")
