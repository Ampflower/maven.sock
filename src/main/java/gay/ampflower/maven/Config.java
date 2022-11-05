/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-13-07T04:40:07

import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;

/**
 * @author Ampflower
 * @since 0.1.0
 **/
public class Config {
	private static final Logger logger = LoggerFactory.getLogger(Config.class);
	private static final Path migrate = Path.of("migrate.ini");
	private final Path config, secrets, users;
	Path socket;
	final Map<String, Host> hosts = new HashMap<>();

	Config(Path store) {
		this.config = store.resolve("config.ini");
		this.secrets = store.resolve(".secrets");
		this.users = store.resolve(".users");
	}

	/**
	 * Post-initialisation
	 */
	public void init() throws IOException {
		for (var host : hosts.entrySet()) {
			var path = host.getValue().path;
			if (path == null) {
				logger.warn("No directory specified for {}", host.getKey());
			} else {
				Files.createDirectories(path);
			}
		}
		if (socket == null) {
			socket = Path.of(Objects.requireNonNullElse(System.getenv("unix_socket"), "./maven.sock"));
		}
	}

	public void read() throws IOException {
		hosts.clear();
		if (Files.notExists(config)) {
			migrate();
			return;
		}
		var authMap = new HashMap<String, Map<String, String>>();
		try (var reader = Utils.lineNumberReader(users)) {
			Ini.read(reader,
					(section, key, value) -> authMap.computeIfAbsent(section, ($) -> new HashMap<>()).put(key, value));
		}
		try (var reader = Utils.lineNumberReader(secrets)) {
			Ini.read(reader, (section, key, value) -> {
				if (section != null) {
					logger.warn("Unknown section {} for secrets, reading through", section);
				}
				if ("*".equals(key)) {
					key = null;
				}
				hosts.put(key, new Host(Utils.DECODER.decode(value), authMap.get(key)));
			});
		}

		try (var reader = Utils.lineNumberReader(config)) {
			Ini.read(reader, (section, key, value) -> {
				if (section == null) {
					if ("socket".equals(key)) {
						socket = Path.of(value);
					} else {
						logger.warn("Unknown entry {}={} from header section", key, value);
					}
				} else if ("hosts".equals(section)) {
					if ("*".equals(key)) {
						key = null;
					}
					var host = hosts.get(key);
					if (host == null) {
						hosts.put(key, new Host(value));
					} else {
						host.path = Path.of(value);
					}
				} else {
					logger.warn("Unknown section {} for entry {}={}", section, key, value);
				}
			});
		}
	}

	public void write() throws IOException {
		// Write users to password hashes into each host section.
		try (var secrets = new Ini.IniWriter(Utils.secretWriter(this.secrets));
				var users = new Ini.IniWriter(Utils.secretWriter(this.users));
				var config = new Ini.IniWriter(Files.newBufferedWriter(this.config))) {
			// Store the socket in the main config.
			config.entry("socket", socket.toString());
			// Preload the hosts section.
			config.section("hosts");

			// INI can't handle this, and this may appear in the middle of iteration.
			var auth = hosts.get(null);
			if (auth != null) {
				auth.writeUsers(users);
			}
			for (var entry : hosts.entrySet()) {
				var key = entry.getKey();
				var value = entry.getValue();
				// Write secrets for each host.
				secrets.entry(Objects.requireNonNullElse(key, "*"), Utils.ENCODER.encodeToString(value.secret));
				// Write the path to each host.
				config.entry(Objects.requireNonNullElse(key, "*"), value.path.toString());
				// Write users for each host.
				if (key != null) {
					users.section(key);
					value.writeUsers(users);
				}
			}
		}
	}

	public void importRaw(String domain, Host host) {
		Objects.requireNonNull(host, "host");
		hosts.put(domain, host);
	}

	public void migrate() throws IOException {
		var set = new HashSet<String>();
		if (Files.exists(migrate)) {
			try (var reader = Utils.lineNumberReader(secrets)) {
				Ini.read(reader, (section, key, value) -> {
					if (section != null) {
						logger.warn("Unknown section {} for migrate, reading through", section);
					}
					if ("*".equals(key)) {
						key = null;
					}
					if (!set.add(value)) {
						logger.warn("Duplicate path {} from {}", value, key);
					}

					// TODO: Merge & Verify
					hosts.put(key, Utils.readLegacy(Path.of(value)));
				});
			}
			Files.move(migrate, Path.of("migrate.ini.bak"));
		}
		var cwd = Path.of(".");
		if (!set.contains(".") && Files.notExists(config)) {
			if (!hosts.containsKey(null)) {
				var legacy = Utils.readLegacy(cwd);
				legacy.path = Path.of(Objects.requireNonNullElse(System.getenv("maven"), "./maven/"));
				hosts.put(null, legacy);
			}
			var usersOld = cwd.resolve(".users." + System.nanoTime() + ".old");
			Files.move(users, usersOld);
		}
	}

	/**
	 * @param host The host domain for the maven.
	 * @return The path of the maven corresponding to the domain, if any.
	 */
	public Path location(String host) {
		var conf = hosts.get(host);
		if (conf == null) {
			conf = hosts.get(null);
		}
		return conf.path;
	}

	public void createHost(String host, Path path) {
		hosts.put(host, new Host(path));
	}

	public boolean deleteHost(String host) {
		return hosts.remove(host) != null;
	}

	public void authorize(String host, String user, char[] password) {
		var auth = hosts.get(host);
		if (auth == null) {
			throw new IllegalArgumentException("Unknown host " + host);
		}
		var passIn = CharBuffer.wrap(password);
		var passBuf = StandardCharsets.UTF_8.encode(passIn);
		var passRaw = new byte[passBuf.limit() - passBuf.position()];
		passBuf.get(passRaw);
		var hash = Argon2.generate(passRaw, auth.secret);
		Arrays.fill(passIn.array(), '\u0000');
		Arrays.fill(passBuf.array(), (byte) 0);
		Arrays.fill(passRaw, (byte) 0);
		auth.users.put(user, hash);
	}

	public boolean authorized(String host, String user, byte[] password) {
		var auth = hosts.get(host);
		if (auth == null) {
			auth = hosts.get(null);
		}
		if (auth != null) {
			var hash = auth.users.get(user);
			if (hash != null) {
				return Argon2.verify(hash, password, auth.secret);
			}
		}
		return false;
	}

	public int taint(String host, String user) {
		int i = 0;
		var auth = hosts.get(host);
		if (auth != null && auth.users.remove(user) != null) {
			i++;
		}
		auth = hosts.get(null);
		if (auth != null && auth.users.remove(user) != null) {
			i++;
		}
		return i;
	}

	static final class Host {
		Path path;
		byte[] secret;
		final Map<String, String> users;

		Host(Path path, byte[] secret, Map<String, String> users) {
			this.path = path;
			this.secret = secret;
			this.users = users;
		}

		Host(Path path) {
			this(path, Utils.createSecret(), new HashMap<>());
		}

		Host(String path) {
			this(Path.of(path), Utils.createSecret(), new HashMap<>());
		}

		Host(byte[] secret, Map<String, String> users) {
			this(null, secret, users);
		}

		Host() {
			this(null, Utils.createSecret(), new HashMap<>());
		}

		void writeUsers(Ini.IniWriter ini) throws IOException {
			for (var user : users.entrySet()) {
				ini.entry(user.getKey(), user.getValue());
			}
		}

		public Path path() {
			return path;
		}

		public byte[] secret() {
			return secret;
		}

		public Map<String, String> users() {
			return users;
		}
	}
}
