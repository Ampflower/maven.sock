# maven.sock

[![Actions](https://github.com/Ampflower/maven.sock/actions/workflows/build.yml/badge.svg)](https://github.com/Ampflower/maven.sock/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/Ampflower/maven.sock)](LICENSE)
<br/>
[![Stable](https://img.shields.io/github/v/release/Ampflower/maven.sock?label=stable)](https://github.com/Ampflower/maven.sock/releases)
[![Beta](https://img.shields.io/github/v/release/Ampflower/maven.sock?include_prereleases&label=beta)](https://github.com/Ampflower/maven.sock/releases)
<br/>
[![Discord](https://img.shields.io/discord/380201541078089738?color=7289da&label=Development&logo=discord&logoColor=7289da)](https://discord.gg/EmPS9y9)

A small Maven upload backend over a UNIX socket, meant for use with reverse proxies such as Caddy.

## Installation & Usage

0. Be sure you're on a system that supports unix sockets. Required for as that's the only method of connecting to the
   server.
1. [Grab the latest stable release available](https://github.com/Ampflower/maven.sock/releases).
2. Grab Java 17 from either your vendor or [Adoptium](https://adoptium.net).
3. Create the Maven repository folder you want to use.
4. Create a user by running the server with `java -jar maven.sock-0.0.0-all.jar username` in a console.
    - It'll prompt you for each username given what you want the password to be. Be sure each one used is sufficiently
      strong, for as the username & password is the only form of authentication, guarded with Argon2id by default.
    - The username cannot contain `:` or any form of newlines. Anything else is free range.
5. Setup the environment. You can set the environment variables `maven` and `unix_socket`.
    - An example configuration is to use `maven=/var/www/maven` and `unix_socket=/run/maven.sock`.
6. Setup the reverse proxy/webserver.
    - Note that this server only supports `PUT`. Anything else will return 501 Not Implemented, even on `GET` and
      `HEAD`.
    - For Caddy, an example configuration is to use...
      ```caddyfile
      # /etc/caddy/Caddyfile
      maven.the-glitch.network {
         root * /var/www/maven
         file_server browse
         @put method PUT
         reverse_proxy @put unix//run/maven.sock
      }
      ```
7. Setup the clients using HTTP Basic Authorization.