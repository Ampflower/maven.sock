/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-04-02T01:36:51

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;
import java.util.concurrent.Callable;

import static gay.ampflower.maven.Maven.DECODER;
import static gay.ampflower.maven.Maven.ENCODER;

/**
 * Argon2 wrapper around Bouncy Castle's implementation.
 *
 * @author Ampflower
 * @since ${version}
 **/
public class Argon2 {
	/**
	 * SecureRandom instance for generating strong salts.
	 */
	private static final SecureRandom random = tryOrDie(SecureRandom::getInstanceStrong);

	/**
	 * Generates a new password hash by using a strong Argon2id instance with the
	 * given secret.
	 *
	 * @param password The password to hash.
	 * @param secret   The constant secret hash to use with creating the hashing
	 *                 instance.
	 * @return The Argon2-compliant output string containing the parameters used,
	 *         the salt and the resulting hash.
	 * @throws AssertionError When encoded password fails internal sanity check.
	 */
	public static String generate(byte[] password, byte[] secret) {
		byte[] salt = new byte[8], output = new byte[32];
		random.nextBytes(salt);
		var params = initArgon2id(secret, salt);
		execute(params, password, output);
		var encoded = encode(params, output);
		if (!verify(encoded, password, secret)) {
			throw new AssertionError("Encoded password failed self-verification.");
		}
		return encoded;
	}

	/**
	 * Verifies the password with the given hash, decoding the Argon2 string into
	 * its parameters and salt.
	 *
	 * @param input    The Argon2-compliant string containing all parameters used.
	 * @param password The password to verify.
	 * @param secret   The constant secret hash to use with creating the hashing
	 *                 instance.
	 * @return true if the Argon2 hash successfully was reproduced by the given
	 *         password and secret, false otherwise.
	 */
	public static boolean verify(String input, byte[] password, byte[] secret) {
		byte[] intermediate = new byte[32], output = new byte[32];
		execute(decode(input, intermediate, secret), password, output);
		return Arrays.constantTimeAreEqual(32, intermediate, 0, output, 0);
	}

	/**
	 * Generates the hash using the parameters and password, outputting to out.
	 *
	 * @param params   The Argon2 byte generator parameters.
	 * @param password The password to hash.
	 * @param out      The output array.
	 */
	static void execute(Argon2Parameters params, byte[] password, byte[] out) {
		var gen = new Argon2BytesGenerator();
		gen.init(params);
		gen.generateBytes(password, out);
	}

	/**
	 * Decodes an Argon2-complaint string to the base parameterts, and injects the
	 * secret.
	 *
	 * @param input  The Argon2-compliant string to decode.
	 * @param hash   The byte array to outputt the hash to. <em>Should match the
	 *               original hash length.</em> If unsure, use 32.
	 * @param secret The secret to inject into the parameters.
	 * @return The parameters as decoded from the original input string.
	 */
	static Argon2Parameters decode(String input, byte[] hash, byte[] secret) {
		try {
			if (!input.startsWith("$argon2"))
				throw new IllegalArgumentException("Invalid hash.");
			int last = input.indexOf('$', 7);
			var typeRaw = input.substring(7, last);
			var params = new Argon2Parameters.Builder(switch (typeRaw) {
				case "d" -> Argon2Parameters.ARGON2_d;
				case "i" -> Argon2Parameters.ARGON2_i;
				case "id" -> Argon2Parameters.ARGON2_id;
				default -> throw new IllegalArgumentException("Invalid type " + typeRaw);
			}).withVersion(Integer.parseUnsignedInt(input, last + 3, last = input.indexOf('$', last + 3), 10))
					.withMemoryAsKB(Integer.parseUnsignedInt(input, last + 3, last = input.indexOf(',', last + 3), 10))
					.withIterations(Integer.parseUnsignedInt(input, last + 3, last = input.indexOf(',', last + 3), 10))
					.withParallelism(Integer.parseUnsignedInt(input, last + 3, last = input.indexOf('$', last + 3), 10))
					.withSecret(secret);
			int saltStart = last + 1;
			last = input.indexOf('$', last + 4);
			if (last != -1)
				params.withSalt(DECODER.decode(input.substring(saltStart, last)));
			if (hash != null)
				System.arraycopy(DECODER.decode(input.substring(Math.max(saltStart, last))), 0, hash, 0, 32);
			return params.build();
		} catch (Exception e) {
			throw new RuntimeException(input, e);
		}
	}

	/**
	 * Encodes the parameters and the given hash into an Argon2 string.
	 * <p>
	 * The encoded output will produce something similar to
	 * {@code $argon2id$v=16$m=4096,t=3,p=1$YSBzYWx0eSBzYWx0$D4rX1U2bx/1zhp20gA54e06gvcpOFcs/v+NYPICswXw}.
	 *
	 * <ul>
	 * <li>{@code $argon2} - The start of the string.</li>
	 * <li>{@code id} - Either {@code i}, {@code d} or {@code id}. Specifies what
	 * variant of Argon2 was used to generate the hash.</li>
	 * <li>{@code $v=[0-9]} - The version of the hash. Either 16, 19 or any other
	 * version released after 1.3 that Bouncy Castle supports.</li>
	 * <li>{@code $m=[0-9],t=[0-9],p=[0-9]} - How much <u>m</u>emory &amp;
	 * <u>p</u>arallelism and how many <u>t</u>imes and it took to generate the
	 * resulting hash.</li>
	 * <li>{@code $SaltAsBase64} - The salt used for creating the hash.</li>
	 * <li>{@code $HashAsBase64} - The resulting hash from the previous parameters +
	 * the secret.</li>
	 * </ul>
	 *
	 * @param parameters The Argon2 parameters used to generate the hash.
	 * @param hash       The output hash.
	 * @return The Argon2-complaint string. The secret is omitted from the output.
	 */
	static String encode(Argon2Parameters parameters, byte[] hash) {
		var sb = new StringBuilder("$argon2");
		switch (parameters.getType()) {
			case Argon2Parameters.ARGON2_d -> sb.append('d');
			case Argon2Parameters.ARGON2_i -> sb.append('i');
			case Argon2Parameters.ARGON2_id -> sb.append("id");
			default -> throw new IllegalArgumentException("invalid type " + parameters.getType());
		}
		sb.append("$v=").append(parameters.getVersion()).append("$m=").append(parameters.getMemory()).append(",t=")
				.append(parameters.getIterations()).append(",p=").append(parameters.getLanes()).append('$');
		sb.append(ENCODER.encodeToString(parameters.getSalt())).append('$');
		sb.append(ENCODER.encodeToString(hash));
		return sb.toString();
	}

	static Argon2Parameters initArgon2id(byte[] secret, byte[] salt) {
		var builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id);
		builder.withVersion(Argon2Parameters.ARGON2_VERSION_13);
		builder.withMemoryAsKB(8192);
		builder.withIterations(15);
		builder.withParallelism(2);
		builder.withSecret(secret);
		builder.withSalt(salt);
		Arrays.clear(salt);
		return builder.build();
	}

	private static <T> T tryOrDie(Callable<T> callable) {
		try {
			return callable.call();
		} catch (Exception exception) {
			throw new ExceptionInInitializerError(exception);
		}
	}
}
