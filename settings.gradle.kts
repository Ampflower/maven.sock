/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

rootProject.name = "maven.sock"

pluginManagement {
    repositories {
        gradlePluginPortal()
    }
    plugins {
        id("com.diffplug.spotless") version System.getProperty("spotlessVersion")!!
        id("com.github.johnrengelman.shadow") version System.getProperty("shadowVersion")!!
    }
}
