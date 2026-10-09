import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { promptHidden, promptSecret, type PromptInput } from "../src/prompt.js";

function fakeTty() {
  const input = new PassThrough() as PassThrough & PromptInput;
  input.isTTY = true;
  input.isRaw = false;
  input.setRawMode = () => input;
  const output = new PassThrough();
  output.setEncoding("utf8");
  let printed = "";
  output.on("data", (chunk) => { printed += chunk; });
  input.pause();
  return { input, output, printed: () => printed };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("pasted username then pasted password are read as two hidden prompts", async () => {
  const io = fakeTty();
  const username = promptHidden("Username: ", io);
  await settle();
  io.input.write("\x1b[200~synthetic-user@example.com\x1b[201~\r\n");
  assert.equal(await username, "synthetic-user@example.com");

  const password = promptHidden("Password: ", io);
  await settle();
  io.input.write("\x1b[200~synthetic-paste-password-NOT-REAL\x1b[201~\n");
  assert.equal(await password, "synthetic-paste-password-NOT-REAL");
  assert.match(io.printed(), /Username:/);
  assert.match(io.printed(), /Password:/);
});

test("stray newline from a previous paste does not become an empty password", async () => {
  const io = fakeTty();
  const first = promptHidden("User: ", io);
  await settle();
  io.input.write("alice\n\n");
  assert.equal(await first, "alice");

  const secret = promptSecret("Vault passphrase", undefined, io);
  await settle();
  io.input.write("\n\x1b[200~correct-horse\x1b[201~\r");
  assert.equal(await secret, "correct-horse");
});

test("promptSecret accepts env, then a TTY paste after stdin was paused", async () => {
  const io = fakeTty();
  assert.equal(await promptSecret("Vault passphrase", "from-env-NOT-SECRET"), "from-env-NOT-SECRET");
  const pending = promptSecret("Password", undefined, io);
  await settle();
  io.input.write("\x1b[200~pasted-secret-NOT-REAL\x1b[201~\n");
  assert.equal(await pending, "pasted-secret-NOT-REAL");
});
