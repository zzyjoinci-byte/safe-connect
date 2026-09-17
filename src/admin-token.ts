import fs from "node:fs";
import path from "node:path";
import { hexe, hexd } from "./bytes.js";
import { randomBytes } from "./crypto.js";

export function adminTokenPath(home: string): string {
  return path.join(home, "admin.token");
}

export function writeAdminToken(home: string): Uint8Array {
  fs.mkdirSync(home, { recursive: true });
  const token = randomBytes(32);
  const file = adminTokenPath(home);
  fs.writeFileSync(file, hexe(token) + "\n", { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return token;
}

export function readAdminToken(home: string): Uint8Array {
  const raw = fs.readFileSync(adminTokenPath(home), "utf8").trim();
  return hexd(raw);
}
