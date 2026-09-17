import { createRequire } from "node:module";
import { b64d, b64e, utf8 } from "./bytes.js";

const require = createRequire(import.meta.url);
const _sodium = require("libsodium-wrappers-sumo") as typeof import("libsodium-wrappers-sumo");

type Sodium = typeof _sodium;
let sodium: Sodium | undefined;

export async function cryptoReady(): Promise<Sodium> {
  if (sodium) return sodium;
  await _sodium.ready;
  sodium = _sodium;
  return sodium;
}

function n(): Sodium {
  if (!sodium) {
    throw new Error("crypto not initialized — call cryptoReady() first");
  }
  return sodium;
}

export function randomBytes(length: number): Uint8Array {
  return n().randombytes_buf(length);
}

export function memzero(buf: Uint8Array | undefined | null): void {
  if (!buf) return;
  n().memzero(buf);
}

export function kdfLimits(): { opslimit: number; memlimit: number } {
  const s = n();
  if (process.env.SAFE_CONNECT_KDF === "fast" || process.env.NODE_ENV === "test") {
    return {
      opslimit: s.crypto_pwhash_OPSLIMIT_MIN,
      memlimit: s.crypto_pwhash_MEMLIMIT_MIN,
    };
  }
  return {
    opslimit: s.crypto_pwhash_OPSLIMIT_MODERATE,
    memlimit: s.crypto_pwhash_MEMLIMIT_MODERATE,
  };
}

export function argon2idKey(
  passphrase: string | Uint8Array,
  salt: Uint8Array,
  limits = kdfLimits(),
): Uint8Array {
  const s = n();
  const pw = typeof passphrase === "string" ? utf8(passphrase) : passphrase;
  try {
    return s.crypto_pwhash(
      s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      pw,
      salt,
      limits.opslimit,
      limits.memlimit,
      s.crypto_pwhash_ALG_ARGON2ID13,
    );
  } finally {
    if (typeof passphrase !== "string") {
      // caller owns the buffer
    } else {
      memzero(pw);
    }
  }
}

export interface AeadBox {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array | null = null,
): AeadBox {
  const s = n();
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key,
  );
  return { nonce, ciphertext };
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array | null = null,
): Uint8Array {
  const s = n();
  const plain = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    key,
  );
  if (!plain) {
    throw new Error("aead decrypt failed");
  }
  return plain;
}

export function boxKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = n().crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return n().crypto_box_seal(message, publicKey);
}

export function sealOpen(
  sealed: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): Uint8Array {
  const opened = n().crypto_box_seal_open(sealed, publicKey, privateKey);
  if (!opened) {
    throw new Error("sealed box open failed");
  }
  return opened;
}

export function keyedHash(key: Uint8Array, message: Uint8Array): Uint8Array {
  return n().crypto_generichash(32, message, key);
}

export function generatePairingKey(): Uint8Array {
  return randomBytes(32);
}

export function confirmCode(): string {
  const buf = randomBytes(4);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const v = view.getUint32(0, false) % 900000;
  memzero(buf);
  return String(100000 + v);
}

export function encryptJson(key: Uint8Array, value: unknown, aadStr?: string): { nonce: string; ciphertext: string } {
  const aad = aadStr ? utf8(aadStr) : null;
  const box = aeadEncrypt(key, utf8(JSON.stringify(value)), aad);
  return { nonce: b64e(box.nonce), ciphertext: b64e(box.ciphertext) };
}

export function decryptJson<T>(
  key: Uint8Array,
  nonceB64: string,
  ciphertextB64: string,
  aadStr?: string,
): T {
  const aad = aadStr ? utf8(aadStr) : null;
  const plain = aeadDecrypt(key, b64d(nonceB64), b64d(ciphertextB64), aad);
  try {
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  } finally {
    memzero(plain);
  }
}

export const MAGIC = Buffer.from("SC01");
export const VAULT_VERSION = 1;
export const KIND_LOCAL = 1;
export const KIND_CLOUD = 2;
