/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

plugins {
    java
    application
    id("com.github.johnrengelman.shadow")
    id("com.diffplug.spotless")
}

val projectVersion: String by project
val bouncyCastleVersion: String by project
val logbackVersion: String by project
val jettyVersion: String by project
val junitVersion: String by project

group = "gay.ampflower"
version = projectVersion

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("gay.ampflower.maven.Maven")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle", "bcprov-jdk15on", bouncyCastleVersion)
    implementation("org.eclipse.jetty", "jetty-server", jettyVersion)
    implementation("org.eclipse.jetty", "jetty-unixsocket-server", jettyVersion)
    implementation("ch.qos.logback", "logback-classic", logbackVersion)
    testImplementation("org.junit.jupiter", "junit-jupiter-api", junitVersion)
    testRuntimeOnly("org.junit.jupiter", "junit-jupiter-engine", junitVersion)
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