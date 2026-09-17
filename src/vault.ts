import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { b64d, b64e, jsonBytes, utf8 } from "./bytes.js";
import {
  MAGIC,
  VAULT_VERSION,
  KIND_LOCAL,
  KIND_CLOUD,
  aeadDecrypt,
  aeadEncrypt,
  argon2idKey,
  kdfLimits,
  keyedHash,
  memzero,
  randomBytes,
  seal,
} from "./crypto.js";
import type { Grade, PlainCredential, PublicItem, SealedItem, SealedSecret } from "./types.js";

export interface LocalEntry {
  id: string;
  label: string;
  origin: string;
  grade: "L1";
  username: string;
  password: string;
}

interface LocalPayload {
  entries: LocalEntry[];
}

interface CloudPayload {
  companion_public_key: string;
  entries: SealedItem[];
}

export class LocalVault {
  private entries = new Map<string, LocalEntry>();
  private key: Uint8Array | null = null;
  private salt: Uint8Array | null = null;
  private opslimit = 0;
  private memlimit = 0;

  constructor(private readonly filePath: string) {}

  get unlocked(): boolean {
    return this.key !== null;
  }

  async init(passphrase: string): Promise<void> {
    if (fs.existsSync(this.filePath)) {
      throw new Error(`vault already exists: ${this.filePath}`);
    }
    const limits = kdfLimits();
    this.salt = randomBytes(16);
    this.opslimit = limits.opslimit;
    this.memlimit = limits.memlimit;
    this.key = argon2idKey(passphrase, this.salt, limits);
    this.entries.clear();
    await this.persist();
  }

  async unlock(passphrase: string): Promise<void> {
    const raw = fs.readFileSync(this.filePath);
    const parsed = parseHeader(raw);
    if (parsed.kind !== KIND_LOCAL) {
      throw new Error("not a local vault");
    }
    const salt = raw.subarray(6, 22);
    const opslimit = raw.readUInt32LE(22);
    const memlimit = raw.readUInt32LE(26);
    const nonce = raw.subarray(30, 54);
    const ciphertext = raw.subarray(54);
    const key = argon2idKey(passphrase, salt, { opslimit, memlimit });
    const plain = aeadDecrypt(key, nonce, ciphertext, utf8("local-vault"));
    try {
      const payload = JSON.parse(Buffer.from(plain).toString("utf8")) as LocalPayload;
      this.entries.clear();
      for (const e of payload.entries ?? []) {
        if (e.grade !== "L1") continue;
        this.entries.set(e.id, e);
      }
      this.key = key;
      this.salt = new Uint8Array(salt);
      this.opslimit = opslimit;
      this.memlimit = memlimit;
    } finally {
      memzero(plain);
    }
  }

  list(): PublicItem[] {
    return [...this.entries.values()].map(({ id, label, origin, grade }) => ({
      id,
      label,
      origin,
      grade,
    }));
  }

  get(id: string): LocalEntry | undefined {
    return this.entries.get(id);
  }

  findByOrigin(origin: string): LocalEntry | undefined {
    return [...this.entries.values()].find((e) => e.origin === origin);
  }

  async addL1(input: {
    label: string;
    origin: string;
    username: string;
    password: string;
    id?: string;
  }): Promise<PublicItem> {
    this.requireKey();
    const id = input.id ?? randomUUID();
    const entry: LocalEntry = {
      id,
      label: input.label,
      origin: input.origin,
      grade: "L1",
      username: input.username,
      password: input.password,
    };
    this.entries.set(id, entry);
    await this.persist();
    return { id, label: entry.label, origin: entry.origin, grade: "L1" };
  }

  async persist(): Promise<void> {
    const key = this.requireKey();
    const payload: LocalPayload = { entries: [...this.entries.values()] };
    const box = aeadEncrypt(key, jsonBytes(payload), utf8("local-vault"));
    const buf = Buffer.alloc(54 + box.ciphertext.length);
    MAGIC.copy(buf, 0);
    buf.writeUInt8(VAULT_VERSION, 4);
    buf.writeUInt8(KIND_LOCAL, 5);
    Buffer.from(this.salt!).copy(buf, 6);
    buf.writeUInt32LE(this.opslimit, 22);
    buf.writeUInt32LE(this.memlimit, 26);
    Buffer.from(box.nonce).copy(buf, 30);
    Buffer.from(box.ciphertext).copy(buf, 54);
    atomicWrite(this.filePath, buf);
  }

  lock(): void {
    memzero(this.key);
    this.key = null;
    this.entries.clear();
  }

  private requireKey(): Uint8Array {
    if (!this.key) throw new Error("vault is locked");
    return this.key;
  }
}

export class CloudVault {
  private entries = new Map<string, SealedItem>();
  private fileKey: Uint8Array | null = null;
  private companionPublicKeyB64 = "";

  constructor(private readonly filePath: string) {}

  configure(pairingKey: Uint8Array, companionPublicKey: Uint8Array): void {
    memzero(this.fileKey);
    this.fileKey = keyedHash(pairingKey, utf8("safe-connect-cloud-vault"));
    this.companionPublicKeyB64 = b64e(companionPublicKey);
    if (fs.existsSync(this.filePath)) {
      this.load();
    } else {
      this.entries.clear();
      this.persist();
    }
  }

  list(): PublicItem[] {
    return [...this.entries.values()].map(({ id, label, origin, grade }) => ({
      id,
      label,
      origin,
      grade,
    }));
  }

  get(id: string): SealedItem | undefined {
    return this.entries.get(id);
  }

  findByOrigin(origin: string): SealedItem | undefined {
    return [...this.entries.values()].find((e) => e.origin === origin);
  }

  addSealed(item: SealedItem): PublicItem {
    if (item.grade !== "L1") {
      throw new Error("cloud disk vault accepts L1 only");
    }
    this.entries.set(item.id, item);
    this.persist();
    return { id: item.id, label: item.label, origin: item.origin, grade: item.grade };
  }

  persist(): void {
    const key = this.fileKey;
    if (!key) throw new Error("cloud vault not configured");
    const payload: CloudPayload = {
      companion_public_key: this.companionPublicKeyB64,
      entries: [...this.entries.values()],
    };
    const box = aeadEncrypt(key, jsonBytes(payload), utf8("cloud-vault"));
    const buf = Buffer.alloc(30 + box.ciphertext.length);
    MAGIC.copy(buf, 0);
    buf.writeUInt8(VAULT_VERSION, 4);
    buf.writeUInt8(KIND_CLOUD, 5);
    Buffer.from(box.nonce).copy(buf, 6);
    Buffer.from(box.ciphertext).copy(buf, 30);
    atomicWrite(this.filePath, buf);
  }

  private load(): void {
    const key = this.fileKey;
    if (!key) throw new Error("cloud vault not configured");
    const raw = fs.readFileSync(this.filePath);
    const parsed = parseHeader(raw);
    if (parsed.kind !== KIND_CLOUD) throw new Error("not a cloud vault");
    const nonce = raw.subarray(6, 30);
    const ciphertext = raw.subarray(30);
    const plain = aeadDecrypt(key, nonce, ciphertext, utf8("cloud-vault"));
    try {
      const payload = JSON.parse(Buffer.from(plain).toString("utf8")) as CloudPayload;
      this.entries.clear();
      for (const e of payload.entries ?? []) {
        if (e.grade !== "L1") continue;
        this.entries.set(e.id, e);
      }
    } finally {
      memzero(plain);
    }
  }
}

export function sealCredential(
  publicKey: Uint8Array,
  cred: PlainCredential,
): SealedSecret {
  const dek = randomBytes(32);
  try {
    const box = aeadEncrypt(dek, jsonBytes(cred), utf8("item"));
    const sealedDek = seal(dek, publicKey);
    return {
      nonce: b64e(box.nonce),
      ciphertext: b64e(box.ciphertext),
      sealed_dek: b64e(sealedDek),
    };
  } finally {
    memzero(dek);
  }
}

export function parseHeader(raw: Buffer): { version: number; kind: number } {
  if (raw.length < 6 || !raw.subarray(0, 4).equals(MAGIC)) {
    throw new Error("invalid vault magic");
  }
  return { version: raw.readUInt8(4), kind: raw.readUInt8(5) };
}

export function originOf(url: string): string {
  try {
    return new URL(url).origin;
  } catch {
    throw new Error("invalid url");
  }
}

export function atomicWrite(filePath: string, data: Buffer): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, 0o600);
}

export { b64d };
