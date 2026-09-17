import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { Broker } from "./broker.js";
import { VERSION } from "./config.js";
import type { LoginRequestInput, LoginRequestView } from "./types.js";

const RequestShape = {
  purpose: z.string().min(1).describe("Why the agent needs this login"),
  url: z.string().url().describe("Login page URL to fill"),
  item_id: z.string().min(1).optional().describe("Vault item id"),
  grade: z.enum(["L0", "L1"]).optional().describe("Prefer L0 or L1 item"),
  ttl_seconds: z.number().int().positive().max(300).optional(),
};

export interface LoginBackend {
  requestBrowserLogin(input: LoginRequestInput): Promise<LoginRequestView>;
  getLoginStatus(requestId: string): LoginRequestView | Promise<LoginRequestView>;
  isFailClosed?: () => boolean;
}

export function brokerBackend(broker: Broker): LoginBackend {
  return {
    requestBrowserLogin: (input) => broker.requestBrowserLogin(input),
    getLoginStatus: (id) => broker.getLoginStatus(id),
    isFailClosed: () => broker.mode === "cloud" && broker.companionStatus() !== "paired",
  };
}

export function httpBackend(baseUrl: string): LoginBackend {
  const base = baseUrl.replace(/\/$/, "");
  return {
    async requestBrowserLogin(input) {
      const r = await fetch(`${base}/v1/request_browser_login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
      const json = (await r.json()) as LoginRequestView & { error?: string };
      if (r.status === 503) {
        return {
          request_id: json.request_id ?? "",
          status: "denied",
          error: json.error ?? "companion_missing",
        };
      }
      return json;
    },
    async getLoginStatus(requestId) {
      const r = await fetch(`${base}/v1/requests/${encodeURIComponent(requestId)}`);
      return (await r.json()) as LoginRequestView;
    },
  };
}

export const MCP_TOOLS = ["request_browser_login", "get_login_status"] as const;

export function createMcpServer(backend: LoginBackend): McpServer {
  const server = new McpServer(
    { name: "safe-connect", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.tool(
    "request_browser_login",
    "Ask Safe Connect to fill a browser login form. Returns request_id and status only. Never returns passwords or usernames.",
    RequestShape,
    async (args) => {
      if (backend.isFailClosed?.()) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ status: "denied", error: "companion_missing" }),
            },
          ],
          isError: true,
        };
      }
      const view = await backend.requestBrowserLogin(args);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              request_id: view.request_id,
              status: view.status,
              ...(view.error ? { error: view.error } : {}),
            }),
          },
        ],
      };
    },
  );

  server.tool(
    "get_login_status",
    "Poll a previous request_browser_login. Returns pending|filled|denied|expired. Never returns secrets.",
    { request_id: z.string().min(1) },
    async ({ request_id }) => {
      const view = await backend.getLoginStatus(request_id);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              request_id: view.request_id,
              status: view.status,
              ...(view.error ? { error: view.error } : {}),
            }),
          },
        ],
      };
    },
  );

  return server;
}

export async function serveMcpStdio(backend: LoginBackend): Promise<void> {
  const server = createMcpServer(backend);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
