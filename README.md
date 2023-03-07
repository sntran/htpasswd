# htpasswd

Deno port of [Apache's `htpasswd`](https://httpd.apache.org/docs/2.4/programs/htpasswd.html).

## Installation

```shell
deno install --allow-read --allow-write --allow-net -n htpasswd https://deno.land/x/htpasswd/main.ts
```

## Usage

### CLI

```shell
$ deno run --allow-read --allow-write --allow-net https://deno.land/x/htpasswd/main.ts
Usage:
      htpasswd [-cimBdpsDv] [-C cost] passwordfile username
      htpasswd -b[cmBdpsDv] [-C cost] passwordfile username password

      htpasswd -n[imBdps] [-C cost] username
      htpasswd -nb[mBdps] [-C cost] username password

  -c  Create a new file.
  -n  Don't update file; display results on stdout.
  -b  Use the password from the command line rather than prompting for it.
  -i  Read password from stdin without verification (for script usage).
  -m  Force MD5 encryption of the password (default).
  -B  Force bcrypt encryption of the password (very secure).
  -C  Set the computing time used for the bcrypt algorithm
      (higher is more secure but slower, default: 5, valid: 4 to 17).
  -d  Force CRYPT encryption of the password (8 chars max, insecure).
  -s  Force SHA encryption of the password (insecure).
  -p  Do not encrypt the password (plaintext, insecure).
  -D  Delete the specified user.
  -v  Verify password for the specified user.
On other systems than Windows and NetWare the '-p' flag will probably not work.
The SHA algorithm does not use a salt and is less secure than the MD5 algorithm.
```

### API

```ts
import {
  compare,
  digest,
  remove,
  upsert,
  validate,
} from "https://deno.land/x/htpasswd/main.ts";

const algorithm = "BCRYPT";

const hash = await digest("password", algorithm);
await compare("password", hash, algorithm); // true

const passwordfile = ".htpasswd";
await validate(passwordfile, "username", "password"); // false

await upsert(passwordfile, "username", "password", { create: true, algorithm});
await validate(passwordfile, "username", "password"); // true
await validate(passwordfile, "username", "fake"); // false

await remove(passwordfile, "username");
await validate(passwordfile, "username", "password"); // false
```

## Current Limitations

- `CRYPT` encryption is not supported.
- `MD5` encryption is not the same as Apache's MD5.
