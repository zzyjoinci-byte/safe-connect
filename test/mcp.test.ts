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

test("MCP server exposes login and session tools, never get_password", () => {
  assert.deepEqual([...MCP_TOOLS].sort(), [
    "attach_session_credentials",
    "cancel_login_session",
    "continue_login_session",
    "create_login_session",
    "get_login_status",
    "get_session_status",
    "list_session_profiles",
    "request_browser_login",
  ]);
  assert.ok(!MCP_TOOLS.includes("get_password"));
  const broker = new Broker({ mode: "local", filler: mockFiller({}) });
  const server = createMcpServer(brokerBackend(broker));
  assert.ok(server);
});
