/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-14-07T06:56:10

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.LineNumberReader;
import java.io.Writer;

/**
 * @author Ampflower
 * @since 0.1.0
 **/
public final class Ini {
	private static final Logger logger = LoggerFactory.getLogger(Ini.class);

	private Ini() {
	}

	public static void read(LineNumberReader reader, IniStream stream) throws IOException {
		String section = null, line;
		boolean skipSection = !stream.shouldReadSection(null);
		logger.debug("Skipping section: {}", skipSection);
		while ((line = reader.readLine()) != null) {
			// Skip comments & blank lines
			if (line.startsWith(";") || line.isBlank()) {
				continue;
			}
			// Parse out sections.
			if (line.startsWith("[") && line.endsWith("]")) {
				skipSection = !stream.shouldReadSection(section = line.substring(1, line.length() - 1));
				logger.debug("Skipping section {}: {}", section, skipSection);
			} else if (!skipSection) {
				// Parse out each entry.
				int equalIndex = line.indexOf('=');
				int colonIndex = line.indexOf(':');
				if (equalIndex < 0 || (colonIndex >= 0 && colonIndex < equalIndex)) {
					equalIndex = colonIndex;
				}
				if (equalIndex < 0) {
					logger.warn("Unable to parse line @ {}: {} in section {}", reader.getLineNumber(), line, section);
					continue;
				}
				stream.ofEntry(section, line.substring(0, equalIndex), line.substring(equalIndex + 1));
			}
		}
	}

	public static class IniWriter implements AutoCloseable {
		private final Writer writer;

		public IniWriter(Writer writer) {
			this.writer = writer;
		}

		public void section(String section) throws IOException {
			writer.append("\r\n[").append(section).append("]\r\n");
		}

		public void entry(String key, String value) throws IOException {
			int i = key.indexOf('=');
			if (i >= 0) {
				throw new IllegalArgumentException(
						"Invalid character for key `" + key + "` at " + i + "; Paired with " + value);
			}
			i = Math.max(value.indexOf('\r'), value.indexOf('\n'));
			if (i >= 0) {
				throw new IllegalArgumentException(
						"Invalid character for value `" + value + "` at " + i + "; Paired with " + key);
			}
			writer.append(key).append('=').append(value).append("\r\n");
		}

		@Override
		public void close() throws IOException {
			writer.close();
		}
	}

	@FunctionalInterface
	public interface IniStream {
		default boolean shouldReadSection(String section) {
			return true;
		}

		void ofEntry(String section, String key, String value) throws IOException;
	}
}
