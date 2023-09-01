/* Copyright 2023 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;

import gay.ampflower.maven.concurrent.ResourceLimiter;

/**
 * @author Ampflower
 * @since 0.1.0
 */
public final class Passwd {
	private static final long K = 1024L, M = K * K, K8 = 8 * K, M8 = 8 * M;

	private static final ResourceLimiter limiter = new ResourceLimiter(Runtime.getRuntime().maxMemory() - M8, M8 + K8);

	public static boolean verify(String input, byte[] password, byte[] secret) {
		final var decoded = Argon2.decode(input, secret);
		try {
			limiter.acquire(decoded.parameters().getMemory() * K + K8);
			return Argon2.verify(decoded, password);
		} catch (InterruptedException interruptedException) {
			throw new RuntimeException(interruptedException);
		} finally {
			limiter.release();
		}
	}
}
