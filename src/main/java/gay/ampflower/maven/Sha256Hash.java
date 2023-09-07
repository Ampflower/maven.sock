/* Copyright 2023 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteOrder;

/**
 * @author Ampflower
 * @since 0.1.0
 **/
public record Sha256Hash(long a, long b, long c, long d) {

	private static final VarHandle handle = MethodHandles.byteArrayViewVarHandle(long[].class, ByteOrder.BIG_ENDIAN);

	public Sha256Hash(byte[] hash) {
		this((long) handle.get(hash, 0), (long) handle.get(hash, 8), (long) handle.get(hash, 16),
				(long) handle.get(hash, 24));
		if (hash.length != 32) {
			throw new IllegalArgumentException("Array length must be 32");
		}
	}
}
