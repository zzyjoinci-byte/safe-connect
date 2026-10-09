import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import type { Broker } from "./broker.js";
import { VERSION } from "./config.js";
import type { ProfileView, SessionView } from "./sessions.js";
import type { Grade, LoginRequestInput, LoginRequestView } from "./types.js";

const RequestShape = {
  purpose: z.string().min(1).describe("Why the agent needs this login"),
  url: z.string().url().describe("Login page URL to fill"),
  item_id: z.string().min(1).optional().describe("Vault item id"),
  grade: z.enum(["L0", "L1"]).optional().describe("Prefer L0 or L1 item"),
  ttl_seconds: z.number().int().positive().max(300).optional(),
};

export interface SessionBackend {
  listSessionProfiles(): Promise<{ profiles: ProfileView[] } | { error: string }>;
  createLoginSession(profileId: string): Promise<SessionView | { error: string }>;
  getSessionStatus(sessionId: string): Promise<SessionView | { error: string }>;
  attachSessionCredentials(sessionId: string, itemId: string, revision: number, grade?: Grade):
    Promise<SessionView | { error: string }>;
  continueLoginSession(sessionId: string, revision: number): Promise<SessionView | { error: string }>;
  cancelLoginSession(sessionId: string): Promise<SessionView | { error: string }>;
}

export interface LoginBackend {
  requestBrowserLogin(input: LoginRequestInput): Promise<LoginRequestView>;
  getLoginStatus(requestId: string): LoginRequestView | Promise<LoginRequestView>;
  isFailClosed?: () => boolean;
  sessions?: SessionBackend;
}

export function brokerBackend(broker: Broker): LoginBackend {
  return {
    requestBrowserLogin: (input) => broker.requestBrowserLogin(input),
    getLoginStatus: (id) => broker.getLoginStatus(id),
    isFailClosed: () => broker.mode === "cloud" && broker.companionStatus() !== "paired",
  };
}

async function sessionFetch(url: string, init?: RequestInit): Promise<SessionView | { error: string }> {
  const r = await fetch(url, init);
  const json = (await r.json()) as SessionView & { error?: string };
  if (!r.ok) return { error: json.error ?? `http_${r.status}` };
  const { control_token: _ignored, ...view } = json as SessionView & { control_token?: string };
  return view;
}

export function httpBackend(baseUrl: string): LoginBackend {
  const base = baseUrl.replace(/\/$/, "");
  const sessions: SessionBackend = {
    async listSessionProfiles() {
      const r = await fetch(`${base}/v1/session_profiles`);
      const json = (await r.json()) as { profiles?: ProfileView[]; error?: string };
      if (!r.ok) return { error: json.error ?? `http_${r.status}` };
      return { profiles: json.profiles ?? [] };
    },
    createLoginSession(profileId) {
      return sessionFetch(`${base}/v1/sessions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ profile_id: profileId }),
      });
    },
    getSessionStatus(sessionId) {
      return sessionFetch(`${base}/v1/sessions/${encodeURIComponent(sessionId)}`);
    },
    attachSessionCredentials(sessionId, itemId, revision, grade) {
      return sessionFetch(`${base}/v1/sessions/${encodeURIComponent(sessionId)}/credentials`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ revision, item_id: itemId, ...(grade ? { grade } : {}) }),
      });
    },
    continueLoginSession(sessionId, revision) {
      return sessionFetch(`${base}/v1/sessions/${encodeURIComponent(sessionId)}/continue`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ revision }),
      });
    },
    cancelLoginSession(sessionId) {
      return sessionFetch(`${base}/v1/sessions/${encodeURIComponent(sessionId)}/cancel`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
    },
  };
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
    sessions,
  };
}

export const MCP_TOOLS = [
  "request_browser_login",
  "get_login_status",
  "list_session_profiles",
  "create_login_session",
  "attach_session_credentials",
  "get_session_status",
  "continue_login_session",
  "cancel_login_session",
] as const;

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

  const sessionUnavailable = {
    content: [{ type: "text" as const, text: JSON.stringify({ error: "sessions_not_configured" }) }],
    isError: true,
  };

  const sessionResult = (view: SessionView | { error: string } | { profiles: ProfileView[] }) => ({
    content: [{ type: "text" as const, text: JSON.stringify(view) }],
    ...("error" in view ? { isError: true } : {}),
  });

  server.tool(
    "list_session_profiles",
    "List built-in controlled-session profile ids and origins. Never returns secrets or selectors.",
    {},
    async () => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.listSessionProfiles());
    },
  );

  server.tool(
    "create_login_session",
    "Open a controlled login session for a named profile (e.g. app-store-connect). Returns session_id and state only. Never returns secrets. Does not submit the form or complete 2FA.",
    { profile_id: z.string().min(1).max(64).describe("Trusted profile id, such as app-store-connect") },
    async ({ profile_id }) => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.createLoginSession(profile_id));
    },
  );

  server.tool(
    "attach_session_credentials",
    "Attach a vault item to a controlled session. Fills username and password only; never submits. Returns session state. Never returns secrets.",
    {
      session_id: z.string().min(1),
      item_id: z.string().min(1),
      revision: z.number().int().nonnegative(),
      grade: z.enum(["L0", "L1"]).optional(),
    },
    async ({ session_id, item_id, revision, grade }) => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.attachSessionCredentials(session_id, item_id, revision, grade));
    },
  );

  server.tool(
    "get_session_status",
    "Poll a controlled login session. Returns state such as awaiting_user_submit, manual_required, authenticated. Never returns secrets.",
    { session_id: z.string().min(1) },
    async ({ session_id }) => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.getSessionStatus(session_id));
    },
  );

  server.tool(
    "continue_login_session",
    "Inspect a controlled session for manual challenges or success evidence. Never submits a form and never returns secrets.",
    { session_id: z.string().min(1), revision: z.number().int().nonnegative() },
    async ({ session_id, revision }) => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.continueLoginSession(session_id, revision));
    },
  );

  server.tool(
    "cancel_login_session",
    "Cancel a controlled login session and destroy its browser context. Never returns secrets.",
    { session_id: z.string().min(1) },
    async ({ session_id }) => {
      if (!backend.sessions) return sessionUnavailable;
      return sessionResult(await backend.sessions.cancelLoginSession(session_id));
    },
  );

  return server;
}

export async function serveMcpStdio(backend: LoginBackend): Promise<void> {
  const server = createMcpServer(backend);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
