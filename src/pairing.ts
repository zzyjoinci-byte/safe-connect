import { hexd, hexe } from "./bytes.js";
import { boxKeypair, generatePairingKey } from "./crypto.js";
import type { PairingMaterial } from "./types.js";
import fs from "node:fs";
import path from "node:path";

export interface CompanionFile {
  pairing_key: string;
  public_key: string;
  private_key: string;
}

export function generatePairing(): PairingMaterial {
  const pairingKey = generatePairingKey();
  const kp = boxKeypair();
  return { pairingKey, publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function materialFromFile(file: CompanionFile): PairingMaterial {
  return {
    pairingKey: hexd(file.pairing_key),
    publicKey: hexd(file.public_key),
    privateKey: hexd(file.private_key),
  };
}

export function writeCompanionFile(filePath: string, material: PairingMaterial): void {
  if (!material.privateKey) {
    throw new Error("companion private key required");
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const body: CompanionFile = {
    pairing_key: hexe(material.pairingKey),
    public_key: hexe(material.publicKey),
    private_key: hexe(material.privateKey),
  };
  fs.writeFileSync(filePath, JSON.stringify(body, null, 2) + "\n", { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

export function readCompanionFile(filePath: string): PairingMaterial {
  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = JSON.parse(raw) as CompanionFile;
  if (!parsed.pairing_key || !parsed.public_key || !parsed.private_key) {
    throw new Error("invalid companion.json");
  }
  return materialFromFile(parsed);
}
