/* Copyright 2023 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;

import gay.ampflower.maven.concurrent.ResourceLimiter;
import org.bouncycastle.util.Arrays;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author Ampflower
 * @since 0.1.0
 */
public final class Passwd {
	private static final long K = 1024L, M = K * K, K8 = 8 * K, M8 = 8 * M;

	private static final ResourceLimiter limiter = new ResourceLimiter(Runtime.getRuntime().maxMemory() - M8, M8 + K8);

	private static final ConcurrentMap<String, CompletableFuture<Boolean>> map = new ConcurrentHashMap<>();

	public static boolean authorized(Config config, String host, String authorization, boolean taint) {
		// A MIME decoder can decode regular and URL base64.
		var rawAuthorization = Utils.DECODER.decode(authorization.substring(6));
		int i = 0;
		int l = rawAuthorization.length;
		while (i < l && rawAuthorization[i] != ':') {
			i++;
		}
		var username = new String(rawAuthorization, 0, i);
		byte[] password = Arrays.copyOfRange(rawAuthorization, i + 1, rawAuthorization.length);

		boolean flag;

		final var either = tryLease(authorization);
		if (either.a != null) {
			flag = either.a.join();
			if (flag & taint) {
				either.a.obtrudeValue(false);
			}
		} else {
			flag = config.authorized(host, username, password);
			either.b.complete(flag ^ taint);
		}

		Arrays.clear(rawAuthorization);
		Arrays.clear(password);

		if (flag && taint) {
			config.taint(host, username);
		}

		return flag;
	}

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

	private static Either<CompletableFuture<Boolean>, CompletableFuture<Boolean>> tryLease(String key) {
		final var current = map.get(key);
		if (current != null) {
			return Either.a(current);
		}

		final var trial = new CompletableFuture<Boolean>();

		final var old = map.putIfAbsent(key, trial);

		if (old != null) {
			return Either.a(old);
		}

		return Either.b(trial);
	}

	private record Either<A, B> (A a, B b) {
		static <A, B> Either<A, B> a(A a) {
			return new Either<>(a, null);
		}

		static <A, B> Either<A, B> b(B b) {
			return new Either<>(null, b);
		}
	}
}
