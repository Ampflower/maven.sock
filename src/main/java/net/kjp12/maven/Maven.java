/* Copyright 2022 KJP12
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package net.kjp12.maven;// Created 2022-02-02T21:46:08

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.util.Arrays;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.unixsocket.server.UnixSocketConnector;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Tiny maven upload backend over a unix socket.
 * <p>
 * Use by a reverse proxy like Caddy.
 *
 * @author KJP12
 * @since ${version}
 **/
public class Maven extends AbstractHandler {
	private static final int nonceLength = 64;
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
	 * Maven upload folder.
	 */
	public static final Path maven = Path.of(Objects.requireNonNullElse(System.getenv("maven"), "./maven/"));
	/**
	 * Nonce-reading for hashing purposes.
	 */
	private static final VarHandle BYTES_AS_INT = MethodHandles.byteArrayViewVarHandle(int[].class,
			ByteOrder.nativeOrder());
	/**
	 * Nonce for current session & secret for password hashing
	 */
	private static final byte[] nonce = new byte[nonceLength], secret;
	/**
	 * Username -> Password Hash map
	 */
	private static final Map<String, String> users;
	/**
	 * Deny-cache to help prevent DOS by same invalid user & password. Argon2
	 * compute is after all, rather expensive.
	 */
	private int[] deniedEntries = new int[64];

	static {
		byte[] $secret = null;
		Map<String, String> $users = null;
		try {
			var random = SecureRandom.getInstanceStrong();
			// Initialise the runtime nonce for use with hashing data to obscure the
			// original data in a way where it's
			// difficult to recover.
			random.nextBytes(nonce);
			// Reads or creates a secret for use with password hashing.
			var secretPath = Path.of(".secret");
			var usersTable = Path.of(".users");
			if (Files.exists(secretPath)) {
				$secret = Files.readAllBytes(secretPath);
			} else {
				boolean isNobody = "nobody".equals(ProcessHandle.current().info().user().orElse(null));
				var opts = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.SYNC);
				var attr = PosixFilePermissions.asFileAttribute(
						isNobody ? Set.of(PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE)
								: Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
				$secret = new byte[1024];
				random.nextBytes($secret);
				try (var channel = Files.newByteChannel(secretPath, opts, attr)) {
					channel.write(ByteBuffer.wrap($secret));
				}
			}
			// Initialises the users map.
			if (Files.exists(usersTable)) {
				$users = Files.readAllLines(usersTable).stream().filter(Predicate.not(String::isBlank)).map(s -> {
					int i = s.indexOf(':');
					return i == -1 ? Map.entry(s, "") : Map.entry(s.substring(0, i), s.substring(i + 1));
				}).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			} else {
				$users = new HashMap<>();
			}
		} catch (Exception ioe) {
			throw new ExceptionInInitializerError(ioe);
		} finally {
			secret = $secret;
			users = $users;
		}
	}

	/**
	 * Prompts for new passwords if any arguments are defined, else boots straight
	 * into Jetty.
	 */
	public static void main(String[] args) throws Exception {
		// Bootstraps the users table. This is required for as this uses a secret,
		// which cannot be inputted into CLI Argon2.
		if (args.length > 0) {
			var console = System.console();
			console.printf("""
					Please input each password for the following %d users.
					It is normal for your input to not echo back.

					""", args.length);
			for (var str : args) {
				if (str.indexOf(':') >= 0) {
					// Usernames cannot `:` as that's the separator for basic authentication.
					// Passwords containing `:` however, are perfectly fine.
					console.printf("Username %s is invalid, must *NOT* contain `:`\n", str);
					continue;
				}
				var passwd = CharBuffer.wrap(console.readPassword("%s>", str));
				var passby = StandardCharsets.UTF_8.encode(passwd);
				Arrays.fill(passwd.array(), '\u0000');
				var hash = Argon2.generate(passby.array(), secret);
				if (!Argon2.verify(hash, passby.array(), secret))
					throw new AssertionError();
				users.put(str, hash);
			}
			var sb = new StringBuilder();
			for (var e : users.entrySet()) {
				sb.append(e.getKey()).append(':').append(e.getValue()).append('\n');
			}
			Files.writeString(Path.of(".users"), sb.substring(0, sb.length() - 1));
			System.exit(0);
		}
		// If there's no users, there's no point in starting.
		if (users.isEmpty()) {
			System.err.println("Please add a user by specifying each one in the command line.");
			System.err.println("On execution, this program will ask you for a password for each user.");
			System.exit(1);
		}

		// Ensure that the maven folder is created.
		Files.createDirectories(maven);

		var server = new Server();
		{
			var connector = new UnixSocketConnector(server);
			connector.setUnixSocket(Objects.requireNonNullElse(System.getenv("unix_socket"), "./maven.sock"));
			server.addConnector(connector);
		}

		server.setHandler(new Maven());

		server.start();
	}

	/**
	 * Handles the authentication and uploading logic for the server.
	 *
	 * @param target      The target directory relative to {@link #maven}.
	 * @param baseRequest Ignored - Normally for generic information.
	 * @param request     Source of headers & the upload data.
	 * @param response    The outgoing response for the client, either to send
	 *                    success or denied.
	 */
	@Override
	public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		// TODO: Implement an invalidator for when the password is exposed as plain
		// text.
		// We are a bit blind being a unix socket however, so, it's not as easy to
		// determine
		// if the request was made as HTTP, as a header is required to tell us.
		// For now, we'll log each request to try to determine what was made as an HTTP
		// vs. HTTPS request later.
		System.out.println("New request for " + target);
		for (var headers = request.getHeaderNames(); headers.hasMoreElements();) {
			var header = headers.nextElement();
			// Ignore Authorization as we shouldn't log that at all.
			if ("Authorization".equalsIgnoreCase(header))
				continue;
			for (var headerValues = request.getHeaders(header); headerValues.hasMoreElements();) {
				System.out.printf("%s: %s\n", header, headerValues.nextElement());
			}
		}
		System.out.flush();
		// No point in executing on any other.
		baseRequest.setHandled(true);
		if (!"PUT".equalsIgnoreCase(request.getMethod())) {
			response.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
			return;
		}
		int contentLength = request.getContentLength();
		// Ignore any upload that is too small or is too large (24M)
		if (contentLength < 0) {
			response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
			return;
		}
		if (contentLength > 1024 * 1024 * 24) {
			response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
			return;
		}
		// Check to see if the IP was banned from uploading.
		// if(checkObject(baseRequest.getRemoteInetSocketAddress().getAddress())) {
		// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		// return;
		// }
		var authorization = request.getHeader("Authorization");
		if (authorization == null || !authorization.startsWith("Basic ") || checkObject(authorization)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		// A MIME decoder can decode regular and URL base64.
		var rawAuthorization = DECODER.decode(authorization.substring(6));
		int i = 0;
		int l = rawAuthorization.length;
		while (i < l && rawAuthorization[i] != ':') {
			i++;
		}
		var username = new String(rawAuthorization, 0, i);
		var hash = users.get(username);
		if (hash == null) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			Arrays.clear(rawAuthorization);
			return;
		}
		byte[] password = Arrays.copyOfRange(rawAuthorization, i + 1, rawAuthorization.length);
		if (!Argon2.verify(hash, password, secret)) {
			denyObject(authorization);
			Arrays.clear(rawAuthorization);
			Arrays.clear(password);
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		Arrays.clear(rawAuthorization);
		Arrays.clear(password);
		var path = maven.resolve('.' + target);
		if (Files.exists(path) && !target.contains("SNAPSHOT")
				&& !target.regionMatches(target.lastIndexOf('/') + 1, "maven-metadata", 0, 14)) {
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			response.getWriter().println("File cannot be replaced or deleted once uploaded.");
			return;
		}
		var parent = path.getParent();
		if (Files.exists(path) && !Files.isDirectory(path)) {
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			response.getWriter().println("Package is a file.");
			return;
		}
		Files.createDirectories(parent);
		try (var pathOut = Files.newOutputStream(path, StandardOpenOption.CREATE_NEW);
				var srvIn = request.getInputStream()) {
			srvIn.transferTo(pathOut);
		}
		response.setStatus(HttpServletResponse.SC_CREATED);
	}

	/**
	 * Checks if the object has not been denied.
	 *
	 * @param object The object to hash then test.
	 * @return true if denied, false otherwise
	 */
	private boolean checkObject(Object object) {
		int hash = hashWithNonce(object);
		return deniedEntries[hash & (deniedEntries.length - 1)] == hash;
	}

	/**
	 * Hashes the object then inserts the result into a small hashset.
	 *
	 * @param object The object to deny.
	 */
	private void denyObject(Object object) {
		int hash = hashWithNonce(object);
		deniedEntries[hash & (deniedEntries.length - 1)] = hash;
	}

	/**
	 * Hashes the object with the {@link #nonce nonce}.
	 *
	 * @param object The object to hash.
	 * @return The object's hash with the nonce compounded on top.
	 */
	private static int hashWithNonce(Object object) {
		int hash = object.hashCode();
		for (int i = 0; i < nonceLength / 4; i++)
			hash = 31 * hash + (int) BYTES_AS_INT.get(nonce, i);
		return hash;
	}
}
