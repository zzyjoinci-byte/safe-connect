import { randomUUID } from "node:crypto";
import { GRANT_TTL_MS, HEARTBEAT_STALE_MS, VERSION } from "./config.js";
import { confirmCode, memzero } from "./crypto.js";
import { EphemeralStore } from "./ephemeral.js";
import { createGrant, decryptItem, openGrant, zeroizeCredential } from "./grants.js";
import { logInfo } from "./logger.js";
import type {
  CompanionStatus,
  CryptoGrant,
  Filler,
  HealthBody,
  LoginRequestInput,
  LoginRequestRecord,
  LoginRequestView,
  Mode,
  PairingMaterial,
  PublicItem,
  RequestStatus,
  SealedItem,
  UnwrapChallenge,
} from "./types.js";
import { CloudVault, LocalVault, originOf, sealCredential } from "./vault.js";

export interface BrokerOptions {
  mode: Mode;
  filler: Filler;
  localVault?: LocalVault;
  cloudVault?: CloudVault;
  pairing?: PairingMaterial;
  now?: () => number;
}

interface PendingChallenge {
  record: LoginRequestRecord;
  sealed_dek: string;
  nonce: string;
  ciphertext: string;
  consumeL0: boolean;
  waiter: {
    resolve: (grant: CryptoGrant) => void;
    reject: (err: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
}

export class Broker {
  readonly mode: Mode;
  readonly ephemeral = new EphemeralStore();
  private readonly filler: Filler;
  private readonly localVault?: LocalVault;
  private readonly cloudVault?: CloudVault;
  private pairing?: PairingMaterial;
  private readonly now: () => number;
  private readonly requests = new Map<string, LoginRequestRecord>();
  private readonly challenges = new Map<string, PendingChallenge>();
  private readonly consumedGrants = new Set<string>();
  private lastHeartbeat = 0;
  private heartbeatPublicKey?: Uint8Array;

  constructor(opts: BrokerOptions) {
    this.mode = opts.mode;
    this.filler = opts.filler;
    this.localVault = opts.localVault;
    this.cloudVault = opts.cloudVault;
    this.pairing = opts.pairing;
    this.now = opts.now ?? Date.now;
    if (opts.mode === "cloud" && opts.pairing) {
      this.heartbeatPublicKey = opts.pairing.publicKey;
    }
  }

  setPairing(pairing: PairingMaterial): void {
    this.pairing = pairing;
    this.heartbeatPublicKey = pairing.publicKey;
  }

  heartbeat(publicKey?: Uint8Array): void {
    if (publicKey && this.pairing?.publicKey) {
      const expected = this.pairing.publicKey;
      if (publicKey.length !== expected.length) {
        throw new Error("companion public key mismatch");
      }
      let diff = 0;
      for (let i = 0; i < expected.length; i++) {
        diff |= (publicKey[i] ?? 0) ^ (expected[i] ?? 0);
      }
      if (diff !== 0) throw new Error("companion public key mismatch");
    }
    this.lastHeartbeat = this.now();
    if (publicKey) this.heartbeatPublicKey = publicKey;
  }

  companionStatus(): CompanionStatus {
    if (this.mode === "local") return "not_required";
    if (this.lastHeartbeat && this.now() - this.lastHeartbeat <= HEARTBEAT_STALE_MS) {
      return "paired";
    }
    return "missing";
  }

  health(): { httpStatus: number; body: HealthBody } {
    const companion = this.companionStatus();
    if (this.mode === "cloud" && companion !== "paired") {
      return {
        httpStatus: 503,
        body: {
          status: "fail_closed",
          mode: this.mode,
          companion: "missing",
          version: VERSION,
        },
      };
    }
    return {
      httpStatus: 200,
      body: {
        status: "ok",
        mode: this.mode,
        companion,
        version: VERSION,
      },
    };
  }

  listItems(): PublicItem[] {
    const l1 = this.mode === "local" ? this.localVault?.list() ?? [] : this.cloudVault?.list() ?? [];
    return [...l1, ...this.ephemeral.list()];
  }

  addLocalL1(input: {
    label: string;
    origin: string;
    username: string;
    password: string;
  }): Promise<PublicItem> {
    if (this.mode !== "local" || !this.localVault) {
      throw new Error("L1 add on disk is local-vault only; cloud L1 must be sealed by companion");
    }
    return this.localVault.addL1(input);
  }

  addLocalL0(input: {
    label: string;
    origin: string;
    username: string;
    password: string;
  }): PublicItem {
    if (this.mode !== "local") {
      throw new Error("plaintext L0 add is local-only");
    }
    const { username: _u, password: _p, ...pub } = this.ephemeral.addPlainLocal(input);
    return pub;
  }

  addSealedItem(item: SealedItem): PublicItem {
    if (this.mode !== "cloud") {
      throw new Error("sealed items are for cloud mode");
    }
    if (item.grade === "L0") {
      return this.ephemeral.add(item);
    }
    if (!this.cloudVault) throw new Error("cloud vault missing");
    return this.cloudVault.addSealed(item);
  }

  getLoginStatus(requestId: string): LoginRequestView {
    const rec = this.requests.get(requestId);
    if (!rec) {
      return { request_id: requestId, status: "expired", error: "not_found" };
    }
    this.expireIfNeeded(rec);
    return viewOf(rec);
  }

  async requestBrowserLogin(input: LoginRequestInput): Promise<LoginRequestView> {
    if (this.mode === "cloud" && this.companionStatus() !== "paired") {
      const request_id = randomUUID();
      const rec: LoginRequestRecord = {
        request_id,
        status: "denied",
        error: "companion_missing",
        purpose: input.purpose,
        url: input.url,
        item_id: input.item_id ?? "",
        grade: input.grade ?? "L1",
        created_at: this.now(),
        grant_expires_at: this.now(),
      };
      this.requests.set(request_id, rec);
      return viewOf(rec);
    }

    const origin = originOf(input.url);
    const resolved = this.resolveItem(origin, input.item_id, input.grade);
    if (!resolved) {
      const request_id = randomUUID();
      const rec: LoginRequestRecord = {
        request_id,
        status: "denied",
        error: "item_not_found",
        purpose: input.purpose,
        url: input.url,
        item_id: input.item_id ?? "",
        grade: input.grade ?? "L1",
        created_at: this.now(),
        grant_expires_at: this.now(),
      };
      this.requests.set(request_id, rec);
      return viewOf(rec);
    }

    const request_id = randomUUID();
    const ttl = Math.min(input.ttl_seconds ? input.ttl_seconds * 1000 : GRANT_TTL_MS, GRANT_TTL_MS);
    const rec: LoginRequestRecord = {
      request_id,
      status: "pending",
      purpose: input.purpose,
      url: input.url,
      item_id: resolved.id,
      grade: resolved.grade,
      created_at: this.now(),
      grant_expires_at: this.now() + ttl,
      confirm_code: confirmCode(),
    };
    this.requests.set(request_id, rec);

    if (this.mode === "local") {
      if (resolved.kind !== "local-plain") {
        rec.status = "denied";
        rec.error = "bad_item";
        return viewOf(rec);
      }
      void this.runLocalFill(rec, resolved).catch((err) => {
        rec.status = "denied";
        rec.error = "fill_failed";
        logInfo(`local fill error: ${err instanceof Error ? err.message : "unknown"}`);
      });
      return viewOf(rec);
    }

    if (resolved.kind !== "sealed") {
      rec.status = "denied";
      rec.error = "bad_item";
      return viewOf(rec);
    }
    void this.runCloudFill(rec, resolved, ttl).catch((err) => {
      if (rec.status === "pending") {
        rec.status = "denied";
        rec.error = err instanceof Error ? sanitizeErr(err.message) : "denied";
      }
    });
    return viewOf(rec);
  }

  pullChallenges(): UnwrapChallenge[] {
    const out: UnwrapChallenge[] = [];
    for (const ch of this.challenges.values()) {
      this.expireIfNeeded(ch.record);
      if (ch.record.status !== "pending") continue;
      out.push({
        request_id: ch.record.request_id,
        url: ch.record.url,
        purpose: ch.record.purpose,
        grade: ch.record.grade,
        expires_in: Math.max(0, Math.ceil((ch.record.grant_expires_at - this.now()) / 1000)),
        confirm_code: ch.record.confirm_code ?? "",
        sealed_dek: ch.sealed_dek,
      });
    }
    return out;
  }

  applyGrant(grant: CryptoGrant): LoginRequestView {
    const ch = this.challenges.get(grant.request_id);
    if (!ch) {
      return { request_id: grant.request_id, status: "expired", error: "no_challenge" };
    }
    clearTimeout(ch.waiter.timer);
    ch.waiter.resolve(grant);
    return viewOf(ch.record);
  }

  deny(requestId: string): LoginRequestView {
    const rec = this.requests.get(requestId);
    if (!rec) return { request_id: requestId, status: "expired", error: "not_found" };
    rec.status = "denied";
    rec.error = "user_denied";
    const ch = this.challenges.get(requestId);
    if (ch) {
      clearTimeout(ch.waiter.timer);
      ch.waiter.reject(new Error("user_denied"));
    }
    return viewOf(rec);
  }

  createCompanionGrant(challenge: UnwrapChallenge): CryptoGrant {
    if (!this.pairing?.privateKey) {
      throw new Error("companion private key missing — cloud must not unwrap locally");
    }
    return createGrant({
      pairingKey: this.pairing.pairingKey,
      publicKey: this.pairing.publicKey,
      privateKey: this.pairing.privateKey,
      sealedDekB64: challenge.sealed_dek,
      requestId: challenge.request_id,
      url: challenge.url,
      ttlMs: challenge.expires_in * 1000,
      now: this.now(),
    });
  }

  private resolveItem(
    origin: string,
    itemId?: string,
    grade?: "L0" | "L1",
  ):
    | { id: string; grade: "L0" | "L1"; kind: "local-plain"; username: string; password: string }
    | { id: string; grade: "L0" | "L1"; kind: "sealed"; sealed_dek: string; nonce: string; ciphertext: string; consumeL0: boolean }
    | undefined {
    if (this.mode === "local") {
      if (itemId) {
        const l0 = this.ephemeral.getPlain(itemId);
        if (l0) {
          return { id: itemId, grade: "L0", kind: "local-plain", ...l0 };
        }
        const l1 = this.localVault?.get(itemId);
        if (l1) {
          return { id: l1.id, grade: "L1", kind: "local-plain", username: l1.username, password: l1.password };
        }
        return undefined;
      }
      if (!grade || grade === "L0") {
        const l0item = this.ephemeral.findByOrigin(origin);
        if (l0item) {
          const plain = this.ephemeral.getPlain(l0item.id);
          if (plain) return { id: l0item.id, grade: "L0", kind: "local-plain", ...plain };
        }
      }
      if (!grade || grade === "L1") {
        const l1 = this.localVault?.findByOrigin(origin);
        if (l1) {
          return { id: l1.id, grade: "L1", kind: "local-plain", username: l1.username, password: l1.password };
        }
      }
      return undefined;
    }

    const sealed = itemId
      ? this.ephemeral.get(itemId) ?? this.cloudVault?.get(itemId)
      : (grade !== "L1" ? this.ephemeral.findByOrigin(origin) : undefined) ??
        (grade !== "L0" ? this.cloudVault?.findByOrigin(origin) : undefined);
    if (!sealed) return undefined;
    return {
      id: sealed.id,
      grade: sealed.grade,
      kind: "sealed",
      sealed_dek: sealed.sealed.sealed_dek,
      nonce: sealed.sealed.nonce,
      ciphertext: sealed.sealed.ciphertext,
      consumeL0: sealed.grade === "L0",
    };
  }

  private async runLocalFill(
    rec: LoginRequestRecord,
    resolved: { id: string; grade: "L0" | "L1"; kind: "local-plain"; username: string; password: string },
  ): Promise<void> {
    const result = await this.filler(rec.url, resolved.username, resolved.password);
    if (resolved.grade === "L0") {
      this.ephemeral.consume(resolved.id);
    }
    rec.status = result.ok ? "filled" : "denied";
    rec.error = result.ok ? undefined : result.error ?? "fill_failed";
  }

  private async runCloudFill(
    rec: LoginRequestRecord,
    resolved: {
      id: string;
      grade: "L0" | "L1";
      kind: "sealed";
      sealed_dek: string;
      nonce: string;
      ciphertext: string;
      consumeL0: boolean;
    },
    ttl: number,
  ): Promise<void> {
    if (!this.pairing) throw new Error("pairing material missing");
    const grant = await new Promise<CryptoGrant>((resolve, reject) => {
      const timer = setTimeout(() => {
        rec.status = "expired";
        rec.error = "grant_timeout";
        this.challenges.delete(rec.request_id);
        reject(new Error("grant_timeout"));
      }, ttl);
      this.challenges.set(rec.request_id, {
        record: rec,
        sealed_dek: resolved.sealed_dek,
        nonce: resolved.nonce,
        ciphertext: resolved.ciphertext,
        consumeL0: resolved.consumeL0,
        waiter: { resolve, reject, timer },
      });
    }).catch((err: Error) => {
      if (rec.status === "pending") {
        rec.status = err.message === "user_denied" ? "denied" : "expired";
        rec.error = err.message === "user_denied" ? "user_denied" : "grant_timeout";
      }
      return undefined;
    });

    const ch = this.challenges.get(rec.request_id);
    if (ch) {
      clearTimeout(ch.waiter.timer);
      this.challenges.delete(rec.request_id);
    }
    if (!grant || rec.status !== "pending") return;

    let dek: Uint8Array | undefined;
    let cred: ReturnType<typeof decryptItem> | undefined;
    try {
      dek = openGrant({
        pairingKey: this.pairing.pairingKey,
        grant,
        requestId: rec.request_id,
        url: rec.url,
        now: this.now(),
        consumed: this.consumedGrants,
      });
      cred = decryptItem(dek, resolved.nonce, resolved.ciphertext);
      const result = await this.filler(rec.url, cred.username, cred.password);
      rec.status = result.ok ? "filled" : "denied";
      rec.error = result.ok ? undefined : result.error ?? "fill_failed";
      if (resolved.consumeL0) {
        this.ephemeral.consume(resolved.id);
      }
    } catch (err) {
      rec.status = "denied";
      rec.error = sanitizeErr(err instanceof Error ? err.message : "unwrap_failed");
    } finally {
      memzero(dek);
      if (cred) zeroizeCredential(cred);
    }
  }

  private expireIfNeeded(rec: LoginRequestRecord): void {
    if (rec.status === "pending" && this.now() > rec.grant_expires_at) {
      rec.status = "expired";
      rec.error = rec.error ?? "expired";
      const ch = this.challenges.get(rec.request_id);
      if (ch) {
        clearTimeout(ch.waiter.timer);
        this.challenges.delete(rec.request_id);
      }
    }
  }
}

function viewOf(rec: LoginRequestRecord): LoginRequestView {
  const view: LoginRequestView = {
    request_id: rec.request_id,
    status: rec.status as RequestStatus,
  };
  if (rec.error) view.error = rec.error;
  return view;
}

function sanitizeErr(message: string): string {
  if (/mismatch|expired|already used|decrypt|sealed/i.test(message)) {
    return message.replace(/[A-Za-z0-9+/=]{16,}/g, "[redacted]");
  }
  return "unwrap_failed";
}

export function sealForCompanion(
  publicKey: Uint8Array,
  cred: { username: string; password: string },
): ReturnType<typeof sealCredential> {
  return sealCredential(publicKey, cred);
}
