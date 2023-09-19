/* Copyright 2022 Ampflower
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package gay.ampflower.maven;// Created 2022-14-07T05:54:23

import com.mojang.brigadier.Command;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.ArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOError;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Objects;

import static com.mojang.brigadier.arguments.StringArgumentType.*;

/**
 * @author Ampflower
 * @since 0.1.0
 **/
public class Console {
	private static final Logger logger = LoggerFactory.getLogger(Console.class);

	private final Input console;
	private final Config config;
	private String host = null;

	Console(Config config) {
		this.config = config;
		if (System.console() != null) {
			console = new TTY();
		} else {
			console = new Raw();
		}
	}

	public void repl() throws IOException {
		var dispatcher = new CommandDispatcher<Console>();
		registerHelpCommand(dispatcher);
		registerUserCommand(dispatcher);
		registerHostCommand(dispatcher);
		console.printf("""
				maven.sock management console

				Run `help` for commands.

				""");
		String input;
		while ((input = console.readLine("[%s@maven.sock] $ ", host)) != null) {
			if (input.equals("exit"))
				break;
			try {
				dispatcher.execute(input, this);
			} catch (CommandSyntaxException cse) {
				logger.warn(cse.getMessage());
			} catch (Throwable t) {
				logger.error("Failure executing command", t);
			}
		}
		if (input == null) {
			console.printf("exit\n");
		}
		config.init();
		config.write();
		System.exit(0);
	}

	private static void registerHelpCommand(CommandDispatcher<Console> dispatcher) {
		Command<Console> base = ctx -> {
			for (var s : dispatcher.getAllUsage(dispatcher.getRoot(), ctx.getSource(), false)) {
				logger.info(s);
			}
			return Command.SINGLE_SUCCESS;
		};
		var help = dispatcher
				.register(literal("help").executes(base).then(argument("command", greedyString()).executes(ctx -> {
					var results = dispatcher.parse(getString(ctx, "command"), ctx.getSource());
					var nodes = results.getContext().getNodes();
					if (nodes.isEmpty())
						throw new IllegalStateException();
					for (var s : dispatcher.getAllUsage(nodes.get(nodes.size() - 1).getNode(), ctx.getSource(),
							false)) {
						if (s.isBlank()) {
							logger.info("*");
						} else {
							logger.info(s);
						}
					}

					return Command.SINGLE_SUCCESS;
				})));
		dispatcher.register(literal("h").executes(base).redirect(help));
		dispatcher.register(literal("?").executes(base).redirect(help));
	}

	private static void registerUserCommand(CommandDispatcher<Console> dispatcher) {
		var user = dispatcher
				.register(literal("user").then(literal("add").then(argument("name", greedyString()).executes(ctx -> {
					var name = getString(ctx, "name");
					if (name.indexOf(':') >= 0) {
						throw new IllegalArgumentException("Username must not contain :");
					}
					var source = ctx.getSource();
					var console = source.console;
					var passwd = console.readPass("%s@%s>", name, source.host);

					if (passwd == null) {
						logger.warn("Password wasn't provided.");
						return 0;
					} else if (passwd.length < 8) {
						logger.warn("Password too weak.");
						return 0;
					} else {
						source.config.authorize(source.host, name, passwd);
					}

					return Command.SINGLE_SUCCESS;
				}))).then(literal("remove").then(argument("name", greedyString()).executes(ctx -> {
					var name = getString(ctx, "name");
					var source = ctx.getSource();
					return source.config.taint(source.host, name);
				}))).then(literal("list").executes(ctx -> {
					var source = ctx.getSource();
					if (source.host == null) {
						for (var entry : source.config.hosts.entrySet()) {
							logger.info("Host: {}", Objects.requireNonNullElse(entry.getKey(), "*"));
							for (var u : entry.getValue().users().keySet()) {
								logger.info(u);
							}
							logger.info("");
						}
					} else {
						for (var u : source.config.hosts.get(source.host).users().keySet()) {
							logger.info(u);
						}
					}

					return Command.SINGLE_SUCCESS;
				})));
		dispatcher.register(literal("u").redirect(user));
	}

	private static void registerHostCommand(CommandDispatcher<Console> dispatcher) {
		dispatcher.register(literal("host").then(
				literal("add").then(argument("name", string()).then(argument("path", greedyString()).executes(ctx -> {
					var name = host(ctx, "name");
					var path = Path.of(getString(ctx, "path"));

					ctx.getSource().config.createHost(name, path);

					return Command.SINGLE_SUCCESS;
				})))).then(literal("remove").then(argument("name", string()).executes(ctx -> {
					var name = getString(ctx, "name");
					if (ctx.getSource().config.deleteHost(name)) {
						logger.info("Deleted {}", name);
						return Command.SINGLE_SUCCESS;
					} else {
						logger.info("No such host.");
						return 0;
					}
				}))).then(literal("import").then(literal("legacy").then(argument("name", string())
						.then(argument("maven", string()).then(argument("config", greedyString()).executes(ctx -> {
							try {
								var config = path(ctx, "config");
								logger.info("Reading {}", config);
								var host = Utils.readLegacy(config);
								if (host == null) {
									logger.warn("Not data found: {}", config);
									return 0;
								}
								host.path = path(ctx, "maven");
								ctx.getSource().config.importRaw(host(ctx, "name"), host);
							} catch (IOException e) {
								throw new RuntimeException(e);
							}

							return Command.SINGLE_SUCCESS;
						}))))).then(literal("modern").then(argument("path", greedyString()).executes(ctx -> {
							var path = path(ctx, "path");
							logger.info("Reading {}", path);

							var configIn = new Config(path);

							try {
								configIn.read();
							} catch (IOException e) {
								e.printStackTrace();
							}

							// TODO: Console input prompt on collisions.

							var config = ctx.getSource().config;

							for (var entry : configIn.hosts.entrySet()) {
								config.importRaw(entry.getKey(), entry.getValue());
							}

							return Command.SINGLE_SUCCESS;
						}))))
				.then(literal("set").then(argument("host", greedyString()).executes(ctx -> {
					ctx.getSource().host = getString(ctx, "host");

					return Command.SINGLE_SUCCESS;
				}))).then(literal("list").executes(ctx -> {
					for (var key : ctx.getSource().config.hosts.keySet()) {
						logger.info(key);
					}
					return Command.SINGLE_SUCCESS;
				})));
	}

	/**
	 * Extracts the host from the command context.
	 *
	 * Assumes that the input <em>may</em> be a URI and attempts to correct for it.
	 *
	 * @param ctx      The Brigadier command context.
	 * @param argument The name of the argument to get the string of.
	 * @return The host, cleaned by URI or of any path.
	 */
	private static String host(CommandContext<?> ctx, String argument) {
		var name = getString(ctx, argument);

		if ("*".equals(name)) {
			name = null;
		} else
			try {
				var uri = new URI(name);
				var host = uri.getHost();
				if (host != null) {
					name = host;
				} else {
					int slash = name.indexOf('/');
					if (slash >= 0) {
						name = name.substring(0, slash);
					}
				}
			} catch (URISyntaxException e) {
				throw new RuntimeException("Failed to parse host.", e);
			}

		return name;
	}

	private static Path path(CommandContext<?> ctx, String argument) {
		return Path.of(getString(ctx, argument));
	}

	private static LiteralArgumentBuilder<Console> literal(String name) {
		return LiteralArgumentBuilder.literal(name);
	}

	private static <T> RequiredArgumentBuilder<Console, T> argument(String name, ArgumentType<T> argumentType) {
		return RequiredArgumentBuilder.argument(name, argumentType);
	}

	private interface Input {
		String readLine() throws IOException;

		String readLine(String fmt, Object... args);

		char[] readPass() throws IOException;

		char[] readPass(String fmt, Object... args);

		void printf(String fmt, Object... args);
	}

	private static class TTY implements Input {
		private final java.io.Console console = Objects.requireNonNull(System.console());

		@Override
		public String readLine() {
			return console.readLine();
		}

		@Override
		public String readLine(String fmt, Object... args) {
			return console.readLine(fmt, args);
		}

		@Override
		public char[] readPass() {
			return console.readPassword();
		}

		@Override
		public char[] readPass(String fmt, Object... args) {
			return console.readPassword(fmt, args);
		}

		@Override
		public void printf(String fmt, Object... args) {
			console.printf(fmt, args);
		}
	}

	private static class Raw implements Input {
		private final BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

		@Override
		public String readLine() {
			try {
				return reader.readLine();
			} catch (IOException ioe) {
				throw new IOError(ioe);
			}
		}

		@Override
		public String readLine(String fmt, Object... args) {
			System.out.printf(fmt, args);
			return readLine();
		}

		@Override
		public char[] readPass() {
			System.out.println("Warning: Password will be echoed.");
			return read0();
		}

		@Override
		public char[] readPass(String fmt, Object... args) {
			System.out.println("Warning: Password will be echoed.");
			System.out.printf(fmt, args);
			return read0();
		}

		private char[] read0() {
			try {
				char[] buf = new char[8192];
				int read, total = 0;
				while ((read = reader.read(buf, total, buf.length - total)) >= 0) {
					total += read;
					if (buf[read - 1] == '\n') {
						char[] tmp = Arrays.copyOf(buf, total - 1);
						Arrays.fill(buf, '\u0000');
						return tmp;
					}
					if (total == buf.length) {
						char[] tmp = Arrays.copyOf(buf, buf.length << 1);
						Arrays.fill(buf, '\u0000');
						buf = tmp;
					}
				}
				return buf;
			} catch (IOException ioe) {
				throw new IOError(ioe);
			}
		}

		@Override
		public void printf(String fmt, Object... args) {
			System.out.printf(fmt, args);
		}
	}
}
