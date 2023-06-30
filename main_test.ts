import { bcrypt, crypto, DigestAlgorithm, toHashString } from "./deps.ts";
import { assertEquals, fc, prepareVirtualFile } from "./dev_deps.ts";

import { compare, digest, remove, upsert, validate } from "./main.ts";

const encoder = new TextEncoder();

const passwordfile = "./.htpasswd";
prepareVirtualFile(passwordfile);

Deno.test("digest", async (t) => {

  await t.step("PLAIN", async () => {
    const opts = { algorithm: "PLAIN" };
    await fc.assert(
      fc.asyncProperty(fc.string(), async (text: string) => {
        assertEquals(await digest(text, opts), text);
      })
    );
  });

  await t.step("MD5", async () => {
    const opts = { algorithm: "MD5" };
    await fc.assert(
      fc.asyncProperty(fc.string(), async (text: string) => {
        const hash = await crypto.subtle.digest(
          opts.algorithm as DigestAlgorithm,
          encoder.encode(text),
        );
        assertEquals(await digest(text, opts), toHashString(hash, "base64"));
      })
    );
  });

  await t.step("SHA-1", async () => {
    const opts = { algorithm: "SHA-1" };
    await fc.assert(
      fc.asyncProperty(fc.string(), async (text: string) => {
        const hash = await crypto.subtle.digest(
          opts.algorithm as DigestAlgorithm,
          encoder.encode(text),
        );
        assertEquals(await digest(text, opts), toHashString(hash, "base64"));
      })
    );
  });

  await t.step("BCRYPT", async () => {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);

    const bcryptOptions = { salt, costFactor: 5 };
    const opts = { algorithm: "BCRYPT", ...bcryptOptions, };
    await fc.assert(
      fc.asyncProperty(fc.string({minLength: 1}), async (text: string) => {
        const hash = await bcrypt({
          password: text,
          ...bcryptOptions,
        });

        assertEquals(await digest(text, opts), hash);
      })
    );
  });

});

Deno.test("compare", async (t) => {
  for await (const algorithm of ["PLAIN", "MD5", "SHA-1", "BCRYPT"]) {
    await t.step(algorithm, async () => {
      await fc.assert(
        fc.asyncProperty(fc.string({minLength: 1}), async (text: string) => {
          const hash = await digest(text, { algorithm });
          assertEquals(await compare(text, hash, algorithm), true);
        })
      );
    });
  }
});

Deno.test("upsert", async (t) => {
  for await (const algorithm of ["PLAIN", "MD5", "SHA-1", "BCRYPT"]) {
    await t.step(algorithm, async () => {
      await fc.assert(
        fc.asyncProperty(fc.string({minLength: 1}), async (text: string) => {
          const salt = new Uint8Array(16);
          crypto.getRandomValues(salt);
          const options = { algorithm, salt };

          // Inserts
          let hash = await digest(text, options);
          await upsert(passwordfile, "username", text, options);
          let content = await Deno.readTextFile(passwordfile);

          assertEquals(content, `username:${hash}`);

          // Updates
          const newText = text + crypto.randomUUID();
          hash = await digest(newText, options);
          await upsert(passwordfile, "username", newText, options);
          content = await Deno.readTextFile(passwordfile);
          assertEquals(content, `username:${hash}`);

          await Deno.writeTextFile(passwordfile, ""); // Clean up
        })
      );
    });
  }
});

Deno.test("remove", async (t) => {
  for await (const algorithm of ["PLAIN", "MD5", "SHA-1", "BCRYPT"]) {
    await t.step(algorithm, async () => {
      await fc.assert(
        fc.asyncProperty(fc.string({minLength: 1}), async (text: string) => {
          const salt = new Uint8Array(16);
          crypto.getRandomValues(salt);
          const options = { algorithm, salt };

          const hash = await digest(text, options);

          await upsert(passwordfile, "A", text, options);
          await remove(passwordfile, "A");
          assertEquals(await Deno.readTextFile(passwordfile), ``);

          await upsert(passwordfile, "A", text, options);
          await upsert(passwordfile, "B", text, options);
          await remove(passwordfile, "A");
          assertEquals(await Deno.readTextFile(passwordfile), `B:${hash}`);

          await Deno.writeTextFile(passwordfile, ""); // Clean up
        })
      );
    });
  }
});

Deno.test("validate", async (t) => {
  for await (const algorithm of ["MD5", "SHA-1", "BCRYPT"]) {
    await t.step(algorithm, async () => {
      await fc.assert(
        fc.asyncProperty(fc.string({minLength: 1}), async (text: string) => {
          const salt = new Uint8Array(16);
          crypto.getRandomValues(salt);
          const options = { algorithm, salt };

          await upsert(passwordfile, "A", text, options);
          assertEquals(await validate(passwordfile, "A", text), true);

          await Deno.writeTextFile(passwordfile, ""); // Clean up
        })
      );
    });
  }
});
