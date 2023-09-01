/* Copyright 2023 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven.concurrent;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.LockSupport;

/**
 * An overbuilt semaphore for limiting predictable memory usage.
 *
 * @author Ampflower
 * @since 0.1.0
 */
public final class ResourceLimiter {
	@SuppressWarnings("unused") // Used by VarHandle
	private volatile long _allocated;
	private final ThreadLocal<Long> allocations = new ThreadLocal<>();
	private final Queue<Hold> threads = new ConcurrentLinkedQueue<>();
	private final long limit;

	private static final VarHandle allocated;

	static {
		try {
			var lookup = MethodHandles.lookup();
			allocated = lookup.findVarHandle(ResourceLimiter.class, "_allocated", long.class);
		} catch (ReflectiveOperationException roe) {
			throw new ExceptionInInitializerError(roe);
		}
	}

	/**
	 * @param limit    The limit for the resources.
	 * @param expected The expected maximum of each lease.
	 * @throws OutOfMemoryError If expected would exceed the given limit.
	 */
	public ResourceLimiter(long limit, long expected) {
		this.limit = limit;
		if (limit < expected) {
			throw new OutOfMemoryError("JVM cannot provide " + expected + " with JVM heap " + limit);
		}
	}

	/**
	 * Acquires a lease for a given amount of memory.
	 *
	 * @param memory The amount of memory to lease.
	 * @throws InterruptedException If the thread was interrupted while parked.
	 */
	public void acquire(long memory) throws InterruptedException {
		if (memory > limit) {
			throw new OutOfMemoryError("Cannot provide " + memory + " with limit " + limit);
		}
		if (!tryLease(memory)) {
			hold(memory);
		}
		allocations.set(memory);
	}

	/**
	 * Releases a lease for a given amount of memory.
	 *
	 * @implNote This also attempts to wake any waiting threads in the process.
	 */
	public void release() {
		Long l = allocations.get();
		if (l == null)
			return;
		allocated.getAndAdd(this, -l);
		allocations.remove();
		wake();
	}

	/**
	 * Attempts to lease {@code memory}
	 *
	 * @param memory The amount of memory to lease.
	 * @return {@code true} if the new amount is below the limit, false otherwise.
	 */
	private boolean tryLease(long memory) {
		final var j = (long) allocated.getAndAdd(this, memory);
		if (j + memory > limit) {
			allocated.getAndAdd(this, -memory);
			return false;
		}
		return true;
	}

	/** Parks the thread, waiting for given {@code memory} amount to be freed. */
	private void hold(long memory) throws InterruptedException {
		final var hold = new Hold(memory);
		if (!threads.offer(hold)) {
			throw new IllegalStateException();
		}
		do {
			LockSupport.park(this);
		} while (!Thread.currentThread().isInterrupted() && !hold.released);
		if (Thread.interrupted()) {
			throw new InterruptedException();
		}
	}

	/** Wakes up any threads able to compute within memory constraints. */
	private void wake() {
		if (threads.isEmpty())
			return;
		final var itr = threads.iterator();
		while (itr.hasNext()) {
			final var hold = itr.next();
			if (tryLease(hold.memory)) {
				hold.released = true;
				LockSupport.unpark(hold.thread);
				itr.remove();
			}
		}
	}

	private static class Hold {
		private final long memory;
		private final Thread thread;
		private volatile boolean released;

		Hold(long memory) {
			this.memory = memory;
			this.thread = Thread.currentThread();
		}

		@Override
		public String toString() {
			return "Hold{" + "memory=" + memory + ", thread=" + thread + ", released=" + released + '}';
		}
	}
}
