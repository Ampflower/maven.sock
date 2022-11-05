## Files on Disk

### Modern

#### config.ini

```ini
socket=./maven.sock

[hosts]
*=/var/www/legacy
maven.example.com=/var/www/maven/
```

#### .users

```ini
user=$argon2id$...

[maven.example.com]
user=$argon2id$...
```

#### .secrets

```ini
*=base64
maven.example.com=base64
```

#### migrate.ini

```ini
; All the hosts known to the server.
; `*` is special-cased to be global.
;
; Note, this is to the root of each instance, should
; you be migrating multiple maven instances into one.
;
; Value being `.` is special-cased
; Instead of allocating to `*`, the root instance,
; `maven.example.com` will take the data instead.
; If `.` is not present, `*` will be the default.
maven.example.com=.
maven.the-glitch.network=/var/maven/tgmvn
```

### Legacy

#### Files

 - `.secret` - Raw secret used for verifying and generating Argon2 hashes.
 - `.users` - Raw K/V Users store of `name:$argon2...`.

#### Environment

 - `maven` - Path to the maven directory. Defaulted to `./maven/`
 - `unix_socket` - Path to the unix socket. Defaulted to `./maven.sock`
