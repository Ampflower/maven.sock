/* Copyright 2023 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;

import gay.ampflower.maven.concurrent.ResourceLimiter;
import org.bouncycastle.util.Arrays;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/**
 * @author Ampflower
 * @since 0.1.0
 */
public final class Passwd {
	private static final long K = 1024L, M = K * K, K8 = 8 * K, M8 = 8 * M;

	private static final ResourceLimiter limiter = new ResourceLimiter(Runtime.getRuntime().maxMemory() - M8, M8 + K8);

	private static final ConcurrentMap<Sha256Hash, Carrier> map = new ConcurrentHashMap<>();

	static {
		Utils.scheduler.scheduleWithFixedDelay(map::clear, 30, 30, TimeUnit.SECONDS);
	}

	public static boolean authorized(Config config, String host, String authorization, byte[] nonce, boolean taint)
			throws InterruptedException {
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

		var hash = config.authHashKey(host, username, password, nonce);

		final var either = tryLease(hash);
		if (either.a != null) {
			flag = either.a.value(taint);
		} else {
			flag = either.b.complete(config.authorized(host, username, password), taint);
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

	private static Either<Carrier, Carrier> tryLease(Sha256Hash key) {
		final var current = map.get(key);
		if (current != null) {
			return Either.a(current);
		}

		final var trial = new Carrier();

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

	private static class Carrier {
		private volatile boolean taint;
		private boolean success;
		private volatile Queue<Thread> threadQueue;

		private static final VarHandle threadQueueHandle;

		static {
			try {
				final var lookup = MethodHandles.lookup();
				threadQueueHandle = lookup.findVarHandle(Carrier.class, "threadQueue", Queue.class);
			} catch (ReflectiveOperationException e) {
				throw new ExceptionInInitializerError(e);
			}
		}

		{
			// Relaxed set as publishing is when being stored in a hashmap.
			threadQueueHandle.set(this, new LinkedBlockingQueue<Thread>());
		}

		boolean value(boolean taint) throws InterruptedException {
			taint(taint);

			final var queue = threadQueue;
			if (queue != null) {
				queue.add(Thread.currentThread());
				hold();
			}

			return this.success;
		}

		void taint(boolean taint) {
			if (taint) {
				this.taint = true;
				this.success = false;
			}
		}

		boolean complete(boolean success, boolean taint) {
			taint(taint);
			final var queue = this.threadQueue;

			if (queue == null) {
				throw new IllegalStateException("completed already, race condition? v=" + this.success);
			}

			this.success = success &= !this.taint;

			this.threadQueue = null;
			queue.forEach(LockSupport::unpark);

			return success;
		}

		private void hold() throws InterruptedException {
			while (this.threadQueue != null) {
				LockSupport.park(this);

				if (Thread.interrupted()) {
					throw new InterruptedException();
				}
			}
		}
	}
}
