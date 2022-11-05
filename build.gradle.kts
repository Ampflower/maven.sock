/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

plugins {
    java
    application
    alias(libs.plugins.shadow)
    alias(libs.plugins.spotless)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("gay.ampflower.maven.Maven")
}

repositories {
    mavenCentral()
    maven("Mojang") {
        url = uri("https://libraries.minecraft.net")
        content {
            includeGroup("com.mojang")
        }
    }
}

dependencies {
    implementation(libs.bouncyCastle)
    implementation(libs.brigadier)
    implementation(libs.bundles.jetty)
    implementation(libs.bundles.logger)
    testImplementation(libs.junit.jupiter.api)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

spotless {
    java {
        importOrderFile(projectDir.resolve(".internal/spotless.importorder"))
        eclipse().configFile(projectDir.resolve(".internal/spotless-java.xml"))

        licenseHeaderFile(projectDir.resolve(".internal/license-header.java"))
    }
    kotlinGradle {
        // This would go ahead and do formatting as well,
        // but there is no formatter that would allow a sane format similar to Java-style.
        target("*.gradle.kts")
        licenseHeaderFile(projectDir.resolve(".internal/license-header.java"), "(import|plugins|rootProject)")
    }
}

tasks {
    test {
        useJUnitPlatform()
    }
}
