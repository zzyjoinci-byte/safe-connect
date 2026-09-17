import { randomUUID } from "node:crypto";
import type { Grade, PublicItem, SealedItem } from "./types.js";

export interface EphemeralItem extends SealedItem {
  created_at: number;
}

/** L0 burn-after-use: process memory only. Never write to disk. */
export class EphemeralStore {
  private items = new Map<string, EphemeralItem>();

  add(item: Omit<SealedItem, "id" | "grade"> & { id?: string; grade?: Grade }): PublicItem {
    const id = item.id ?? randomUUID();
    const stored: EphemeralItem = {
      id,
      label: item.label,
      origin: item.origin,
      grade: "L0",
      sealed: item.sealed,
      created_at: Date.now(),
    };
    this.items.set(id, stored);
    return { id, label: stored.label, origin: stored.origin, grade: "L0" };
  }

  /** Local-mode helper: wrap plaintext into a sealed-shaped record held only in RAM. */
  addPlainLocal(input: {
    label: string;
    origin: string;
    username: string;
    password: string;
    id?: string;
  }): PublicItem & { username: string; password: string } {
    const id = input.id ?? randomUUID();
    const stored: EphemeralItem = {
      id,
      label: input.label,
      origin: input.origin,
      grade: "L0",
      sealed: { nonce: "", ciphertext: "", sealed_dek: "" },
      created_at: Date.now(),
    };
    this.items.set(id, stored);
    this.plain.set(id, { username: input.username, password: input.password });
    return { id, label: input.label, origin: input.origin, grade: "L0", username: input.username, password: input.password };
  }

  private plain = new Map<string, { username: string; password: string }>();

  getPlain(id: string): { username: string; password: string } | undefined {
    return this.plain.get(id);
  }

  takePlain(id: string): { username: string; password: string } | undefined {
    const v = this.plain.get(id);
    this.plain.delete(id);
    this.items.delete(id);
    return v;
  }

  get(id: string): EphemeralItem | undefined {
    return this.items.get(id);
  }

  findByOrigin(origin: string): EphemeralItem | undefined {
    return [...this.items.values()].find((e) => e.origin === origin);
  }

  list(): PublicItem[] {
    return [...this.items.values()].map(({ id, label, origin, grade }) => ({
      id,
      label,
      origin,
      grade,
    }));
  }

  consume(id: string): EphemeralItem | undefined {
    const item = this.items.get(id);
    this.items.delete(id);
    this.plain.delete(id);
    return item;
  }

  has(id: string): boolean {
    return this.items.has(id) || this.plain.has(id);
  }

  clear(): void {
    this.items.clear();
    this.plain.clear();
  }
}
