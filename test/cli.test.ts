import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("CLI help explains local vs cloud+companion", async () => {
  const out = await new Promise<string>((resolve, reject) => {
    const child = spawn("node", ["dist/cli.js", "help"], { cwd: root });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(stderr || `exit ${code}`));
      else resolve(stdout);
    });
  });
  assert.match(out, /local/);
  assert.match(out, /cloud/);
  assert.match(out, /companion/);
  assert.match(out, /never returns secrets/i);
});
