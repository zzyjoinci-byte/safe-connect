import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import type { Broker } from "../src/broker.js";
import type { LoginRequestView } from "../src/types.js";

export function testHome(prefix = "safe-connect-"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return dir;
}

export async function waitStatus(
  broker: Broker,
  requestId: string,
  timeoutMs = 4000,
): Promise<LoginRequestView> {
  const start = Date.now();
  for (;;) {
    const view = broker.getLoginStatus(requestId);
    if (view.status !== "pending") return view;
    if (Date.now() - start > timeoutMs) return view;
    await sleep(20);
  }
}

export function assertNoLeak(haystack: unknown, secret: string): void {
  const dumped = JSON.stringify(haystack);
  if (dumped.includes(secret)) {
    throw new Error("secret leaked into serialized payload");
  }
}
