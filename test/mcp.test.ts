import assert from "node:assert/strict";
import { before, test } from "node:test";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { mockFiller } from "../src/fill.js";
import { MCP_TOOLS, createMcpServer, brokerBackend } from "../src/mcp.js";

process.env.NODE_ENV = "test";

before(async () => {
  await cryptoReady();
});

test("MCP server exposes only login request/status tools", () => {
  assert.deepEqual([...MCP_TOOLS].sort(), ["get_login_status", "request_browser_login"]);
  const broker = new Broker({ mode: "local", filler: mockFiller({}) });
  createMcpServer(brokerBackend(broker));
});
