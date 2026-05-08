import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

const OPERATOR_ID = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GATEWAY_ID = "switchboard-az-02";
const ROUTE_STATE_TOKEN = "route-state-token";

let child: ChildProcessWithoutNullStreams | undefined;
let routeStateServer: HttpServer | undefined;

describe("gateway route-state polling", () => {
  afterEach(async () => {
    if (child) {
      await stopChild(child);
      child = undefined;
    }
    if (routeStateServer) {
      await closeHttp(routeStateServer);
      routeStateServer = undefined;
    }
  });

  it("renders polled desired routes and removes omitted routes after a grace window", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "switchboard-route-state-polling-"));
    const xdsDir = path.join(tempDir, "xds");
    const stateFile = path.join(tempDir, "route-intents.json");
    const route = {
      routeId: "polled-route-1",
      sessionId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      hostname: "poll.example.test",
      publicHostname: "poll.example.test",
      validationHostname: "validation.poll.example.test",
      hostnameRole: "ha_public",
      upstreamHost: "127.0.0.1",
      upstreamPort: 3443,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      source: {
        mode: "route-state-test",
        operatorId: OPERATOR_ID,
        gatewayId: GATEWAY_ID
      }
    };
    let desiredRoutes: Array<Record<string, unknown>> = [route];
    let observedAuthorization: string | undefined;
    routeStateServer = createHttpServer(async (request, response) => {
      if (request.method === "GET" && request.url === "/route-state") {
        observedAuthorization = request.headers.authorization;
        jsonHttpResponse(response, 200, {
          ok: true,
          version: 1,
          generatedAt: new Date().toISOString(),
          operatorId: OPERATOR_ID,
          gatewayId: GATEWAY_ID,
          routes: desiredRoutes,
          activeRoutes: desiredRoutes,
          routeCount: desiredRoutes.length
        });
        return;
      }
      jsonHttpResponse(response, 404, { error: "not_found" });
    });
    await listenHttp(routeStateServer);
    const routeStateAddress = routeStateServer.address();
    assert(routeStateAddress && typeof routeStateAddress !== "string");

    const gatewayPort = await freePort();
    child = spawn(process.execPath, ["--import", "tsx", "src/gateway-agent.ts"], {
      cwd: path.resolve(import.meta.dirname, ".."),
      env: {
        ...process.env,
        GATEWAY_AGENT_HOST: "127.0.0.1",
        GATEWAY_AGENT_PORT: String(gatewayPort),
        ENVOY_XDS_DIR: xdsDir,
        ROUTE_INTENT_STATE_FILE: stateFile,
        OPERATOR_ID,
        GATEWAY_ID,
        OPERATOR_PUBLIC_ADDRESS_MODE: "static",
        OPERATOR_PROCESSOR_DISCOVERY_ENABLED: "false",
        GATEWAY_ROUTE_STATE_URL: `http://127.0.0.1:${routeStateAddress.port}/route-state`,
        GATEWAY_ROUTE_STATE_TOKEN: ROUTE_STATE_TOKEN,
        GATEWAY_ROUTE_STATE_POLL_INTERVAL_MS: "100",
        GATEWAY_ROUTE_STATE_TIMEOUT_MS: "1000",
        GATEWAY_ROUTE_STATE_REMOVAL_GRACE_MS: "300",
        ROUTE_EXPIRY_SWEEP_MS: "1000"
      }
    });
    const output = collectChildOutput(child);

    await waitFor(async () => {
      const response = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
      return response.ok;
    }, 45_000, output);

    await waitFor(async () => {
      const rendered = JSON.parse(await readFile(path.join(xdsDir, "routes.json"), "utf8")) as { routes?: unknown[] };
      return rendered.routes?.length === 1;
    }, 30_000, output);
    assert.equal(observedAuthorization, `Bearer ${ROUTE_STATE_TOKEN}`);

    desiredRoutes = [];

    await sleep(150);
    {
      const rendered = JSON.parse(await readFile(path.join(xdsDir, "routes.json"), "utf8")) as { routes?: unknown[] };
      assert.equal(rendered.routes?.length, 1);
    }

    await waitFor(async () => {
      const rendered = JSON.parse(await readFile(path.join(xdsDir, "routes.json"), "utf8")) as { routes?: unknown[] };
      return rendered.routes?.length === 0;
    }, 30_000, output);
  });
});

function collectChildOutput(process: ChildProcessWithoutNullStreams): () => string {
  let output = "";
  process.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  process.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });
  process.on("error", (error) => {
    output += `\n[gateway-agent error] ${error.message}\n`;
  });
  process.on("exit", (code, signal) => {
    output += `\n[gateway-agent exit] code=${code ?? "null"} signal=${signal ?? "null"}\n`;
  });
  return () => output;
}

async function waitFor(predicate: () => Promise<boolean> | boolean, timeoutMs: number, output?: () => string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      if (await predicate()) {
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  const details = output ? `\n${output()}` : "";
  throw new Error(`Timed out waiting for condition${lastError instanceof Error ? `: ${lastError.message}` : ""}${details}`);
}

function jsonHttpResponse(response: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function listenHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1");
    server.once("listening", resolve);
    server.once("error", reject);
  });
}

function closeHttp(server: HttpServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function freePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Could not allocate port")));
        return;
      }
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(address.port);
      });
    });
  });
}

async function stopChild(process: ChildProcessWithoutNullStreams): Promise<void> {
  if (process.exitCode !== null || process.signalCode !== null) {
    return;
  }
  process.kill("SIGTERM");
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      process.kill("SIGKILL");
      resolve();
    }, 2_000);
    process.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}
