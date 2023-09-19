/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-02-02T21:46:08

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.unixdomain.server.UnixDomainServerConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.TimeUnit;

import static gay.ampflower.maven.Utils.getStrongRandom;

/**
 * Tiny maven upload backend over a unix socket.
 * <p>
 * Use behind a reverse proxy like Caddy.
 *
 * @author Ampflower
 * @since 0.0.0
 **/
public class Maven extends AbstractHandler {
	private static final Logger logger = LoggerFactory.getLogger(Maven.class);
	private static final int nonceLength = 64;
	/**
	 * Nonce for current session.
	 */
	private static final byte[] nonce = new byte[nonceLength];
	/**
	 * Deny-cache to help prevent DOS by same invalid user & password. Argon2
	 * compute is after all, rather expensive.
	 */
	private final int[] deniedEntries = new int[64];
	private final Config config;

	Maven(Config config) {
		this.config = config;
	}

	/**
	 * Opens the management console if , else boots straight into Jetty.
	 */
	public static void main(String[] args) throws Exception {
		// Initialise the runtime nonce for use with hashing data to obscure the
		// original data in a way where it's
		// difficult to recover.
		getStrongRandom().nextBytes(nonce);

		// Renews the nonce hourly. Yes, this operation is not atomic, although frankly,
		// there's no reason for it to be.
		Utils.scheduler.scheduleWithFixedDelay(() -> getStrongRandom().nextBytes(nonce), 1, 1, TimeUnit.HOURS);

		logger.info("Reading config...");
		var config = new Config(Path.of("."));
		config.read();
		// Bootstraps the users table. This is required for as this uses a secret,
		// which cannot be inputted into CLI Argon2.
		if (Utils.contains(args, "--console")) {
			new Console(config).repl();
			return;
		}
		// If there's no users, there's no point in starting.
		if (config.hosts.values().stream().allMatch(host -> host.users.isEmpty())) {
			System.err.println("Please add a user by specifying each one in the command line.");
			System.err.println("On execution, this program will ask you for a password for each user.");
			System.exit(1);
		}

		// Ensure that the maven folder is created.
		config.init();

		var server = new Server();
		{
			var connector = new UnixDomainServerConnector(server);
			connector.setUnixDomainPath(config.socket);
			server.addConnector(connector);
		}

		server.setHandler(new Maven(config));

		server.start();

		config.socket.toFile().deleteOnExit();
	}

	/**
	 * Handles the authentication and uploading logic for the server.
	 *
	 * @param target      The target directory relative to the
	 *                    {@link Config.Host#path maven path} for the domain.
	 * @param baseRequest Ignored - Normally for generic information.
	 * @param request     Source of headers & the upload data.
	 * @param response    The outgoing response for the client, either to send
	 *                    success or denied.
	 */
	@Override
	public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		var host = request.getHeader("Host");
		var maven = config.location(host);
		var user = Passwd.user(request.getHeader("Authorization"));

		logger.info("request: {} {}@{}{} from {}:{} ({}), real: {}, cf: {} / {}, agent: {}", request.getMethod(), user,
				host, target, request.getRemoteAddr(), request.getRemotePort(), request.getRemoteHost(),
				Utils.toString(request.getHeaders("X-Fowarded-For")), request.getHeader("CF-Connecting-IP"),
				request.getHeader("True-Client-IP"), request.getHeader("User-Agent"));

		// CF-Connecting-IP and X-Forwarded-For :blobfox_3c:
		if (!checkPreconditions(user, baseRequest, request, response)) {
			logger.info("invalid: {} {}@{}{} from {}:{} ({})", request.getMethod(), user, host, target,
					request.getRemoteAddr(), request.getRemotePort(), request.getRemoteHost());
			user.close();
			return;
		}

		logger.info("authenticated: {} {}@{}{} from {}:{} ({})", request.getMethod(), user, host, target,
				request.getRemoteAddr(), request.getRemotePort(), request.getRemoteHost());

		var path = maven.resolve('.' + target);
		if (Files.exists(path) && !target.contains("SNAPSHOT")
				&& !target.regionMatches(target.lastIndexOf('/') + 1, "maven-metadata", 0, 14)) {
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			response.getWriter().println("File cannot be replaced or deleted once uploaded.");

			logger.info("attempted replacing: {} {}@{}{}", request.getMethod(), user, host, target);
			return;
		}
		var parent = path.getParent();
		if (Files.exists(parent) && !Files.isDirectory(parent)) {
			response.setStatus(HttpServletResponse.SC_CONFLICT);
			response.getWriter().println("Package is a file.");

			logger.info("package is a file: {} {}@{}{}", request.getMethod(), user, host, target);
			return;
		}

		Files.createDirectories(parent);
		try (var srvIn = request.getInputStream()) {
			Files.copy(srvIn, path, StandardCopyOption.REPLACE_EXISTING);
		}

		logger.info("successful upload: {} {}@{}{}", request.getMethod(), user, host, target);
		response.setStatus(HttpServletResponse.SC_CREATED);
	}

	private boolean checkPreconditions(Passwd.User user, Request baseRequest, HttpServletRequest request,
									   HttpServletResponse response) throws IOException {
		boolean taint = "http".equals(request.getHeader("X-Forwarded-Proto"));
		// No point in executing on any other.
		baseRequest.setHandled(true);
		if (!"PUT".equalsIgnoreCase(request.getMethod())) {
			response.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
			return false;
		}
		int contentLength = request.getContentLength();
		// Ignore any upload that is too small or is too large (24M)
		if (contentLength < 0) {
			response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
			return false;
		}
		if (contentLength > 1024 * 1024 * 24) {
			response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
			return false;
		}

		var host = request.getHeader("Host");
		var maven = config.location(host);
		// Check to see if the host is valid.
		if (maven == null) {
			response.setStatus(HttpServletResponse.SC_NOT_FOUND);
			return false;
		}
		// Check to see if the IP was banned from uploading.
		// if(checkObject(baseRequest.getRemoteInetSocketAddress().getAddress())) {
		// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
		// return;
		// }
		if (checkObject(request.getHeader("Authorization"))) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().println("Unacceptable Authorization Method");
			return false;
		}

		try {
			if (!Passwd.authorized(config, host, user, nonce, taint)) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().println("Invalid credentials.");
				return false;
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		if (taint) {
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.getWriter().println("Use HTTPS next time. Password invalidated, contact sysadmin.");
			return false;
		}

		return true;
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
			hash = 31 * hash + (int) Utils.BYTES_AS_INT.get(nonce, i);
		return hash;
	}
}
