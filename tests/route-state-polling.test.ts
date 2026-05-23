import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { createServer, type Server as NetServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { ethers } from "ethers";

import {
  gatewayUpstreamAdmissionDigest,
  type GatewayUpstreamAdmissionPayload
} from "../src/gateway-upstream-admission.js";

const OPERATOR_ID = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GATEWAY_ID = "switchboard-az-02";
const ROUTE_STATE_TOKEN = "route-state-token";
const GATEWAY_REPORT_PRIVATE_KEY = "0x000000000000000000000000000000000000000000000000000000000000000a";

let child: ChildProcessWithoutNullStreams | undefined;
let routeStateServer: HttpServer | undefined;
let hungRpcServer: NetServer | undefined;
const hungRpcSockets = new Set<Socket>();

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
    if (hungRpcServer) {
      await closeNet(hungRpcServer);
      hungRpcServer = undefined;
    }
    hungRpcSockets.clear();
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
    let failRouteState = false;
    routeStateServer = createHttpServer(async (request, response) => {
      if (request.method === "GET" && request.url === "/route-state") {
        observedAuthorization = request.headers.authorization;
        if (failRouteState) {
          jsonHttpResponse(response, 500, { error: "route_state_unavailable" });
          return;
        }
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
        GATEWAY_ROUTE_STATE_WATCHDOG_MS: "500",
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
    {
      const health = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
      const body = await health.json() as { routeState?: Record<string, unknown>; processorDiscovery?: Record<string, unknown> };
      assert.equal(body.routeState?.enabled, true);
      assert.equal(body.routeState?.healthy, true);
      assert.equal(typeof body.routeState?.lastSuccessAt, "string");
      assert.equal(typeof body.routeState?.lastCompletedAt, "string");
      assert.equal(body.routeState?.consecutiveFailures, 0);
      assert.deepEqual(body.routeState?.lastAppliedRouteIds, ["polled-route-1"]);
      assert.deepEqual(body.routeState?.lastRemovedRouteIds, []);
      assert.equal(typeof body.routeState?.configVersion, "string");
      assert.equal(body.processorDiscovery?.enabled, false);
      assert.equal(body.processorDiscovery?.fresh, undefined);
      assert.equal(body.processorDiscovery?.checkAvailability, true);
      assert.equal(body.processorDiscovery?.maxAgeSeconds, 900);
      assert.equal(body.processorDiscovery?.durationMs, 300000);
    }

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
    {
      const health = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
      const body = await health.json() as { routeState?: Record<string, unknown> };
      assert.deepEqual(body.routeState?.lastRemovedRouteIds, ["polled-route-1"]);
      assert.equal(body.routeState?.lastRemovalReason, "route_state_omitted_after_grace");
    }

    failRouteState = true;
    await waitFor(async () => {
      const health = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
      const body = await health.json() as { routeState?: Record<string, unknown> };
      return body.routeState?.healthy === false && Number(body.routeState?.consecutiveFailures ?? 0) > 0;
    }, 30_000, output);
  });

  it("aborts a stale route-state poll and applies a newer generation", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "switchboard-route-state-watchdog-"));
    const xdsDir = path.join(tempDir, "xds");
    const stateFile = path.join(tempDir, "route-intents.json");
    const route = {
      routeId: "watchdog-route-1",
      sessionId: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      hostname: "watchdog.example.test",
      publicHostname: "watchdog.example.test",
      validationHostname: "validation.watchdog.example.test",
      upstreamHost: "127.0.0.1",
      upstreamPort: 3443,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      source: {
        mode: "route-state-watchdog-test",
        operatorId: OPERATOR_ID,
        gatewayId: GATEWAY_ID
      }
    };
    let requestCount = 0;
    routeStateServer = createHttpServer(async (request, response) => {
      if (request.method === "GET" && request.url === "/route-state") {
        requestCount += 1;
        if (requestCount === 1) {
          return;
        }
        jsonHttpResponse(response, 200, {
          ok: true,
          version: 1,
          generatedAt: new Date().toISOString(),
          operatorId: OPERATOR_ID,
          gatewayId: GATEWAY_ID,
          routes: [route],
          activeRoutes: [route],
          routeCount: 1
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
        GATEWAY_ROUTE_STATE_POLL_INTERVAL_MS: "50",
        GATEWAY_ROUTE_STATE_TIMEOUT_MS: "10000",
        GATEWAY_ROUTE_STATE_WATCHDOG_MS: "200",
        GATEWAY_ROUTE_STATE_REMOVAL_GRACE_MS: "300",
        ROUTE_EXPIRY_SWEEP_MS: "1000"
      }
    });
    const output = collectChildOutput(child);

    await waitFor(async () => {
      const rendered = JSON.parse(await readFile(path.join(xdsDir, "routes.json"), "utf8")) as { routes?: unknown[] };
      return rendered.routes?.length === 1;
    }, 45_000, output);

    const health = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
    const body = await health.json() as { routeState?: Record<string, unknown> };
    assert.equal(body.routeState?.healthy, true);
    assert.equal(body.routeState?.watchdogAbortCount, 1);
    assert.equal(body.routeState?.consecutiveFailures, 0);
    assert.equal(typeof body.routeState?.lastSuccessAt, "string");
    assert.equal(requestCount >= 2, true);
  });

  it("requires gateway-observed admission for deployment-intent route-state routes", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "switchboard-route-state-admission-"));
    const xdsDir = path.join(tempDir, "xds");
    const stateFile = path.join(tempDir, "route-intents.json");
    const runtimeWallet = new ethers.Wallet("0x000000000000000000000000000000000000000000000000000000000000000b");
    const requestPayload: GatewayUpstreamAdmissionPayload = {
      intentId: "di_gateway_admission_test",
      sessionId: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      runtimeSigner: runtimeWallet.address,
      operatorId: OPERATOR_ID,
      gatewayId: GATEWAY_ID,
      processorId: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      hostname: "admission.example.test",
      validationHostname: "admission.example.test",
      upstreamPort: 3443,
      nonce: `nonce-${Date.now()}`,
      deadline: String(Math.floor(Date.now() / 1000) + 600)
    };
    const route = {
      routeId: "admission-route-1",
      sessionId: requestPayload.sessionId,
      hostname: requestPayload.hostname,
      publicHostname: requestPayload.hostname,
      validationHostname: requestPayload.validationHostname,
      hostnameRole: "ha_public",
      upstreamHost: "169.254.169.254",
      upstreamPort: requestPayload.upstreamPort,
      expiresAt: Math.floor(Date.now() / 1000) + 600,
      source: {
        mode: "deployment-intent-route-reconciler",
        operatorId: OPERATOR_ID,
        gatewayId: GATEWAY_ID,
        processorId: requestPayload.processorId
      }
    };
    let desiredRoutes: Array<Record<string, unknown>> = [route];
    routeStateServer = createHttpServer(async (request, response) => {
      if (request.method === "GET" && request.url === "/route-state") {
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
        OPERATOR_REPORT_PRIVATE_KEY: GATEWAY_REPORT_PRIVATE_KEY,
        OPERATOR_PUBLIC_ADDRESS_MODE: "static",
        OPERATOR_PROCESSOR_DISCOVERY_ENABLED: "false",
        GATEWAY_ROUTE_STATE_URL: `http://127.0.0.1:${routeStateAddress.port}/route-state`,
        GATEWAY_ROUTE_STATE_POLL_INTERVAL_MS: "100",
        GATEWAY_ROUTE_STATE_TIMEOUT_MS: "1000",
        GATEWAY_ROUTE_STATE_WATCHDOG_MS: "500",
        GATEWAY_ROUTE_STATE_REMOVAL_GRACE_MS: "300",
        GATEWAY_UPSTREAM_ADMISSION_ALLOWED_CIDRS: "127.0.0.1/32",
        GATEWAY_UPSTREAM_ADMISSION_TLS_PROBE_ENABLED: "false",
        ROUTE_EXPIRY_SWEEP_MS: "1000"
      }
    });
    const output = collectChildOutput(child);

    await waitFor(async () => {
      const response = await fetch(`http://127.0.0.1:${gatewayPort}/health`);
      return response.ok;
    }, 45_000, output);

    await waitFor(async () => (await readRenderedRoutes(xdsDir)).length === 0, 30_000, output);

    const signature = runtimeWallet.signingKey.sign(gatewayUpstreamAdmissionDigest(requestPayload)).serialized;
    const admissionResponse = await fetch(`http://127.0.0.1:${gatewayPort}/v1/upstream-admissions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request: requestPayload, signature })
    });
    if (admissionResponse.status !== 201) {
      assert.fail(`unexpected upstream admission status ${admissionResponse.status}: ${await admissionResponse.text()}`);
    }
    const admissionBody = await admissionResponse.json() as {
      observation: { admissionId: string; observedIp: string };
    };
    assert.equal(admissionBody.observation.observedIp, "127.0.0.1");

    desiredRoutes = [{
      ...route,
      source: {
        ...route.source,
        upstreamAdmissionId: admissionBody.observation.admissionId
      }
    }];

    await waitFor(async () => {
      const rendered = await readRenderedRoutes(xdsDir);
      return rendered.length === 1 && rendered[0]?.upstreamHost === "127.0.0.1";
    }, 30_000, output);

    const rendered = await readRenderedRoutes(xdsDir);
    assert.equal(rendered[0]?.upstreamHost, "127.0.0.1");
    assert.notEqual(rendered[0]?.upstreamHost, "169.254.169.254");
  });

  it("times out stale processor discovery and clears in-flight health", async () => {
    const tempDir = await mkdtemp(path.join(tmpdir(), "switchboard-processor-discovery-watchdog-"));
    const xdsDir = path.join(tempDir, "xds");
    const stateFile = path.join(tempDir, "route-intents.json");

    hungRpcServer = createServer((socket) => {
      // Keep the TCP connection open without completing a WebSocket/RPC handshake.
      hungRpcSockets.add(socket);
      socket.once("close", () => hungRpcSockets.delete(socket));
    });
    await listenNet(hungRpcServer);
    const rpcAddress = hungRpcServer.address();
    assert(rpcAddress && typeof rpcAddress !== "string");

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
        OPERATOR_MANAGER_IDS: "9470",
        OPERATOR_PROCESSOR_DISCOVERY_ENABLED: "true",
        OPERATOR_PROCESSOR_DISCOVERY_INTERVAL_MS: "50",
        OPERATOR_PROCESSOR_DISCOVERY_TIMEOUT_MS: "150",
        ACURAST_RPC: `ws://127.0.0.1:${rpcAddress.port}`
      }
    });
    const output = collectChildOutput(child);

    await waitFor(async () => {
      const response = await fetchWithTimeout(`http://127.0.0.1:${gatewayPort}/health`, 500);
      if (!response.ok) {
        return false;
      }
      const body = await response.json() as { processorDiscovery?: Record<string, unknown> };
      return body.processorDiscovery?.refreshInFlight === false &&
        Number(body.processorDiscovery?.refreshTimedOutCount ?? 0) > 0 &&
        String(body.processorDiscovery?.lastError ?? "").includes("manager processor inventory refresh exceeded");
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

function listenNet(server: NetServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1");
    server.once("listening", resolve);
    server.once("error", reject);
  });
}

function closeNet(server: NetServer): Promise<void> {
  for (const socket of hungRpcSockets) {
    socket.destroy();
  }
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

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function readRenderedRoutes(xdsDir: string): Promise<Array<Record<string, unknown>>> {
  const rendered = JSON.parse(await readFile(path.join(xdsDir, "routes.json"), "utf8")) as { routes?: unknown[] };
  return Array.isArray(rendered.routes)
    ? rendered.routes.filter((route): route is Record<string, unknown> => Boolean(route) && typeof route === "object" && !Array.isArray(route))
    : [];
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
