#!/usr/bin/env -S deno run --allow-read --allow-write --allow-net
import {
  bcrypt, bcryptVerify,
  crypto,
  DigestAlgorithm,
  readLines,
  toHashString,
} from "./deps.ts";

const encoder = new TextEncoder();

const HELP = `Usage:
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
The SHA algorithm does not use a salt and is less secure than the MD5 algorithm.`;

//#region API
export type hash = string;

export type Options = {
  create?: boolean;
} & Digest;

type Digest = {
  algorithm?: string;
  salt?: Uint8Array;
  costFactor?: number;
}

/**
 * Inserts or updates a user in a password file.
 * @returns the new line added to the password file.
 */
export async function upsert(
  passwordfile: string,
  username: string,
  password: string,
  options: Options = {},
): Promise<string> {
  const {
    create,
    ...digestOptions
  } = options;

  const hash = await digest(password, digestOptions);
  const newline = `${username}:${hash}`;

  if (passwordfile) {
    const htpasswd = await Deno.open(passwordfile, {
      create,
      read: true,
      write: true,
    });

    const lines = [];
    let found = false;
    for await (const line of readLines(htpasswd)) {
      const [user] = line.split(":");

      if (user !== username) {
        lines.push(line);
      } else {
        found = true;
        lines.push(newline);
      }
    }

    if (!found) {
      lines.push(newline);
    }

    htpasswd.close();
    await Deno.writeTextFile(passwordfile, lines.join("\n"));
  }

  return newline;
}

/**
 * Removes a user from a password file.
 * @returns true if the user was found and removed, false otherwise.
 */
export async function remove(passwordfile: string, username: string) {
  const htpasswd = await Deno.open(passwordfile, { read: true });

  const lines = [];
  let found = false;
  for await (const line of readLines(htpasswd)) {
    const [user] = line.split(":");

    if (user !== username) {
      lines.push(line);
    } else {
      found = true;
    }
  }

  htpasswd.close();
  await Deno.writeTextFile(passwordfile, lines.join("\n"));

  return found;
}

/**
 * Validates a user's password against a password file.
 * @returns whether the password matches.
 */
export async function validate(
  passwordfile: string,
  username: string,
  password: string,
  options: Options = {},
): Promise<boolean> {
  const {
    create,
    algorithm,
  } = options;

  let found = false;
  const htpasswd = await Deno.open(passwordfile, { create, read: true });

  const algorithms = algorithm ? [algorithm] : ["MD5", "SHA-1", "BCRYPT"];

  for await (const line of readLines(htpasswd)) {
    const [user, hash] = line.split(":");

    if (user !== username) continue;

    for await (const algorithm of algorithms) {
      if (await compare(password, hash, algorithm)) {
        found = true;
        break;
      }
    }
  }

  htpasswd.close();

  return found;
}

/**
 * Digests a string using the specified algorithm.
 * @returns the digest hash
 */
export async function digest(text: string, options: Digest = {}): Promise<hash> {
  const {
    algorithm = "MD5",
    costFactor = 5,
    salt = genSalt(16),
  } = options;

  if (algorithm === "PLAIN") {
    return text;
  }

  if (algorithm === "BCRYPT") {
    return bcrypt({
      password: text,
      salt,
      costFactor,
    });
  }

  const hash = await crypto.subtle.digest(
    algorithm as DigestAlgorithm,
    encoder.encode(text),
  );

  return toHashString(hash, "base64");
}

function genSalt(size = 16) {
  const salt = new Uint8Array(size);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Compares a string against a hash using the specified algorithm.
 * @returns whether the string matches the hash.
 */
export async function compare(
  text: string,
  hash: hash,
  algorithm: string,
): Promise<boolean> {
  if (algorithm === "PLAIN") {
    return text === hash;
  }

  if (algorithm === "BCRYPT") {
    try {
      return await bcryptVerify({
        password: text,
        hash
      });
    } catch (_error) {
      return false;
    }
  }

  return crypto.subtle.timingSafeEqual(
    encoder.encode(await digest(text, { algorithm })),
    encoder.encode(hash),
  );
}
//#endregion API

//#region CLI
if (import.meta.main) {
  const { parse } = await import("https://deno.land/std@0.192.0/flags/mod.ts");

  const args: string[] = [];
  let algorithm;

  const {
    // See `HELP` for flag details
    c,
    n,
    b,
    i,
    // m, B, d, s, p,
    C,
    D,
    v,
  } = parse(Deno.args, {
    boolean: [
      "c",
      "n",
      "b",
      "i",
      // "m", "B", "d", "s", "p",
      "D",
      "v",
    ],
    string: ["_", "C"],
    default: {
      C: "5",
    },
    unknown: (arg, key, value) => {
      // Multiple algorithms can be specified, but only the last one will be used.
      if (key === "m") {
        algorithm = "MD5";
      } else if (key === "B") {
        algorithm = "BCRYPT";
      } else if (key === "d") {
        algorithm = "CRYPT";
      } else if (key === "s") {
        algorithm = "SHA-1";
      } else if (key === "p") {
        algorithm = "PLAIN";
      }

      // Because we use `unknown` option, we need to handle the arguments ourselves.
      if (arg && !key) {
        args.push(arg);
      }

      // If the algorithm flag is specified right before the passwordfile arg, it would
      // be parsed as the value of the flag. So we need to handle it manually.
      if (value && value !== true) {
        args.push(value as string);
      }
    },
  });

  let [passwordfile, username, password] = args;

  if (!passwordfile) { // In fact, must have at least 1 argument.
    console.info(HELP);
    Deno.exit(1);
  }

  // Only one of -c -n -D -v may be specified.
  if ([c, n, D, v].filter(Boolean).length > 1) {
    console.error("htpasswd: only one of -c -n -v -D may be specified");
    Deno.exit(1);
  }

  if (!b && password) { // If not using -b, password must be read from prompt.
    console.info(HELP);
    Deno.exit(1);
  }

  if (D) { // Delete the specified user.
    if (await remove(passwordfile, username)) {
      console.info(`Deleting password for user ${username}`);
    } else {
      console.info(`User ${username} not found`);
    }
    Deno.exit(0);
  }

  if (v) { // Verify password for the specified user
    if (!b) { // If not using -b, password must be read from prompt or stdin.
      if (i) { // Read password from stdin without verification.
        password = await new Response(Deno.stdin.readable).text();
        password = password.trim();
      } else { // Read password from prompt.
        password = prompt("Enter password: ")!;
      }
    }

    const validated = await validate(passwordfile, username, password, {
      create: c,
      algorithm,
    });
    if (!validated) {
      console.info("password verification failed");
      Deno.exit(0);
    } else {
      console.info(`Password for user ${username} correct.`);
      Deno.exit(0);
    }
  }

  if (algorithm === "CRYPT") {
    console.error("CRYPT algorithm is too old and not supported.");
    Deno.exit(1);
  }

  if (n && password) { // If using -n, no passwordfile should be specified.
    console.info(HELP);
    Deno.exit(1);
  }

  if (n) { // Don't update file; display results on stdout.
    password = username;
    username = passwordfile;
    passwordfile = "";
  }

  if (algorithm === "PLAIN") {
    console.warn(
      "Warning: storing passwords as plain text might just not work on this platform.",
    );
  }

  try {
    const entry = await upsert(passwordfile, username, password, {
      create: c,
      algorithm,
      costFactor: parseInt(C),
    });

    if (n) {
      console.info(entry);
    } else {
      console.info(`Updating password for user ${username}`);
    }
  } catch (_error) {
    console.error(
      `htpasswd: cannot modify file ${passwordfile}; use '-c' to create it`,
    );
  }
}
//#endregion CLI
