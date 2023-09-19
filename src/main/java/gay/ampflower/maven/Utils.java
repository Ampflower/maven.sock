/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-13-07T05:03:18

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.LineNumberReader;
import java.io.Writer;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author Ampflower
 * @since 0.1.0
 **/
public final class Utils {
	private static final Logger logger = LoggerFactory.getLogger(Utils.class);
	/**
	 * Base64 decoder used for both HTTP Basic Authentication decoding and Argon2
	 * hash decoding.
	 */
	static final Base64.Decoder DECODER = Base64.getMimeDecoder();
	/**
	 * Base64 encoder used for Argon2 hash encoding.
	 */
	static final Base64.Encoder ENCODER = Base64.getEncoder().withoutPadding();
	/**
	 * Allows for reading nonce for hashing purposes.
	 */
	static final VarHandle BYTES_AS_INT = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.nativeOrder());
	/**
	 * Strong instance of SecureRandom.
	 */
	private static SecureRandom STRONG_RANDOM;
	/**
	 * Safe writing options for writing a store.
	 */
	static final Set<OpenOption> SAFE_WRITE_OPTIONS = Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE,
			StandardOpenOption.SYNC, StandardOpenOption.TRUNCATE_EXISTING);

	static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
		private final AtomicInteger counter = new AtomicInteger();

		@Override
		public Thread newThread(final Runnable r) {
			final var thread = new Thread(r, "scheduler daemon " + counter.incrementAndGet());
			thread.setDaemon(true);
			return thread;
		}
	});

	static {
		// Pre-initialise it.
		getStrongRandom();
	}

	public static SecureRandom getStrongRandom() {
		final var rng = STRONG_RANDOM;
		if (rng == null)
			try {
				return STRONG_RANDOM = SecureRandom.getInstanceStrong();
			} catch (NoSuchAlgorithmException nsae) {
				throw new AssertionError("Unable to initialise StrongRandom for use.", nsae);
			}

		return rng;
	}

	public static boolean contains(final Object[] array, Object obj) {
		for (int i = 0, l = array.length; i < l; i++) {
			if (Objects.equals(array[i], obj))
				return true;
		}
		return false;
	}

	public static String toString(Enumeration<?> enumeration) {
		var builder = new StringBuilder();
		while (enumeration.hasMoreElements()) {
			builder.append(enumeration.nextElement()).append(", ");
		}

		return builder.toString();
	}

	/**
	 * Determines secure permissions for a new secret file.
	 *
	 * @return Group read & write for the user "nobody", onwer otherwise.
	 */
	private static FileAttribute<Set<PosixFilePermission>> getSecretPermissions() {
		final boolean isNobody = "nobody".equals(ProcessHandle.current().info().user().orElse(null));
		return PosixFilePermissions
				.asFileAttribute(isNobody ? Set.of(PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE)
						: Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
	}

	/**
	 * Creates a writer with safe permissions for output.
	 *
	 * @param path The secret store to open a writer for.
	 * @return A writer pointing to the path.
	 */
	public static Writer secretWriter(Path path) throws IOException {
		final var byteChannel = Files.newByteChannel(path, SAFE_WRITE_OPTIONS, getSecretPermissions());
		final var writer = Channels.newWriter(byteChannel, StandardCharsets.UTF_8);
		return new BufferedWriter(writer);
	}

	/**
	 * Creates a reader that tracks line numbers.
	 */
	public static LineNumberReader lineNumberReader(Path path) throws IOException {
		final var byteChannel = Files.newByteChannel(path, StandardOpenOption.READ);
		final var reader = Channels.newReader(byteChannel, StandardCharsets.UTF_8);
		return new LineNumberReader(reader);
	}

	public static byte[] createSecret() {
		final var $secret = new byte[1024];
		STRONG_RANDOM.nextBytes($secret);
		return $secret;
	}

	@Deprecated
	public static Config.Host readLegacy(Path old) throws IOException {
		final var secretPath = old.resolve(".secret");
		final var usersTable = old.resolve(".users");
		logger.debug("secretPath: {}", secretPath.normalize());
		logger.debug("usersTable: {}", usersTable.normalize());

		final boolean secretExists = Files.exists(secretPath);
		final boolean usersExists = Files.exists(usersTable);

		if (!secretExists && !usersExists) {
			return null;
		}
		// Reads or creates a secret for use with password hashing.
		final byte[] $secret;
		if (secretExists) {
			$secret = Files.readAllBytes(secretPath);
			logger.debug("Read secret");
		} else {
			$secret = createSecret();
			logger.debug("Created secret");
		}
		// Initialises the users map.
		final var $users = new HashMap<String, String>();
		if (usersExists) {
			logger.debug("Reading {}", usersTable);
			try (final var reader = Utils.lineNumberReader(usersTable)) {
				Ini.read(reader, (section, key, value) -> {
					logger.debug("{} -> {}", key, value);
					$users.put(key, value);
				});
			}
		}
		return new Config.Host($secret, $users);
	}
}
