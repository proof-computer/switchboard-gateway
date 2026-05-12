import { promises as fs } from "node:fs";
import path from "node:path";

import Fastify from "fastify";

import {
  acurastNetworkFrom,
  createAcurastApi,
  rpcForAcurastNetwork,
  selectReadyProcessors,
  discoverManagerProcessorsWithApi,
  type AcurastNetwork,
  type ManagerProcessorInventory
} from "./acurast-manager.js";
import { normalizeHostname, normalizeRouteIntent, routeHostnames, routeIsActive, type RouteIntent } from "./route-intent.js";
import { collectEnvoyRouteMetrics } from "./route-metrics.js";
import { buildRouteStatusReport, type RouteStatusReportFilters } from "./route-status-report.js";
import { renderFileXds } from "./xds.js";
import { processorRefToId, signGatewayCapabilityReport, type GatewayCapabilityReport } from "./operator-capability.js";
import { fetchWanIpv4, normalizeOperatorPublicAddressMode, type OperatorPublicAddressMode } from "./wan-ip.js";

const port = numberEnv("GATEWAY_AGENT_PORT", 18080);
const host = process.env.GATEWAY_AGENT_HOST ?? "0.0.0.0";
const xdsDir = process.env.ENVOY_XDS_DIR ?? "/var/lib/switchboard/xds";
const stateFile = process.env.ROUTE_INTENT_STATE_FILE ?? "/var/lib/switchboard/gateway-agent/route-intents.json";
const listenerName = process.env.ENVOY_LISTENER_NAME ?? "switchboard_https";
const listenerAddress = process.env.ENVOY_LISTENER_ADDRESS ?? "0.0.0.0";
const listenerPort = numberEnv("ENVOY_LISTENER_PORT", 10000);
const expirySweepMs = numberEnv("ROUTE_EXPIRY_SWEEP_MS", 10_000);
const operatorId = process.env.OPERATOR_ID;
const gatewayId = process.env.GATEWAY_ID;
const reportSigningSeed = process.env.OPERATOR_REPORT_SEED;
const legacyReportSigningPrivateKey = process.env.OPERATOR_REPORT_PRIVATE_KEY;
const reportSigningKey = reportSigningSeed ?? legacyReportSigningPrivateKey;
const reportSigningScheme = reportSigningSeed
  ? "substrate-sr25519"
  : legacyReportSigningPrivateKey
    ? "eip191-secp256k1"
    : undefined;
const reportSigningSs58Format = optionalNumberEnv("OPERATOR_REPORT_SS58_FORMAT");
const capabilityReportUrl = process.env.PROOF_OPERATOR_CAPABILITY_URL;
const capabilityReportToken = process.env.PROOF_OPERATOR_CAPABILITY_TOKEN;
const capabilityReportIntervalMs = numberEnv("OPERATOR_CAPABILITY_REPORT_INTERVAL_MS", 60_000);
const capabilityReportTtlSeconds = numberEnv("OPERATOR_CAPABILITY_REPORT_TTL_SECONDS", 180);
const routeIntentToken = process.env.GATEWAY_AGENT_ROUTE_INTENT_TOKEN;
const routeIntentUrl = optionalStringEnv("GATEWAY_AGENT_ROUTE_INTENT_URL");
const routeStateUrl = optionalStringEnv("GATEWAY_ROUTE_STATE_URL");
const routeStateToken = process.env.GATEWAY_ROUTE_STATE_TOKEN ?? process.env.PROOF_OPERATOR_CAPABILITY_TOKEN;
const routeStatePollIntervalMs = numberEnv("GATEWAY_ROUTE_STATE_POLL_INTERVAL_MS", 5_000);
const routeStateTimeoutMs = numberEnv("GATEWAY_ROUTE_STATE_TIMEOUT_MS", 5_000);
const routeStateRemovalGraceMs = numberEnv("GATEWAY_ROUTE_STATE_REMOVAL_GRACE_MS", 15_000);
const routeStateWatchdogMs = numberEnv(
  "GATEWAY_ROUTE_STATE_WATCHDOG_MS",
  Math.max(routeStateTimeoutMs * 3, routeStatePollIntervalMs * 3, 15_000)
);
const routeMetricsEnabled = boolEnv("GATEWAY_ROUTE_METRICS_ENABLED", true);
const routeMetricsStatsUrl =
  optionalStringEnv("GATEWAY_ENVOY_STATS_URL") ??
  optionalStringEnv("ENVOY_ADMIN_STATS_URL") ??
  "http://envoy:9901/stats/prometheus";
const routeMetricsTimeoutMs = numberEnv("GATEWAY_ROUTE_METRICS_TIMEOUT_MS", 1500);
const routeMetricsMaxRoutes = numberEnv("GATEWAY_ROUTE_METRICS_MAX_ROUTES", 200);
const routeCapacity = numberEnv("GATEWAY_ROUTE_CAPACITY", 500);
const staticPublicAddresses = splitCsv(process.env.OPERATOR_PUBLIC_ADDRESSES ?? process.env.GATEWAY_PUBLIC_ADDRESSES ?? "");
const publicAddressMode = normalizeOperatorPublicAddressMode(process.env.OPERATOR_PUBLIC_ADDRESS_MODE, staticPublicAddresses);
const wanIpUrl = process.env.OPERATOR_WAN_IP_URL ?? "https://ifconfig.me/ip";
const wanIpPollIntervalMs = numberEnv("OPERATOR_WAN_IP_POLL_INTERVAL_MS", 60_000);
const wanIpTimeoutMs = numberEnv("OPERATOR_WAN_IP_TIMEOUT_MS", 5_000);
const validationHostname = optionalStringEnv("OPERATOR_VALIDATION_HOSTNAME");
const supportedClasses = splitCsv(process.env.OPERATOR_SUPPORTED_CLASSES ?? "node-webserver");
const advertisedProcessors = splitCsv(process.env.OPERATOR_PROCESSORS ?? "");
const advertisedManagerIds = uniqueStrings([
  ...splitCsv(process.env.OPERATOR_MANAGER_IDS ?? ""),
  ...splitCsv(process.env.OPERATOR_MANAGER_ID ?? ""),
  ...splitCsv(process.env.ACURAST_MANAGER_ID ?? "")
]);
const excludedProcessors = splitCsv(process.env.OPERATOR_EXCLUDED_PROCESSORS ?? process.env.OPERATOR_PROCESSOR_EXCLUDES ?? "");
const acurastNetwork = acurastNetworkFrom(process.env.ACURAST_NETWORK);
const acurastRpcUrl = acurastNetwork === "canary" ? optionalStringEnv("ACURAST_CANARY_RPC") : optionalStringEnv("ACURAST_RPC");
const processorDiscoveryEnabled = boolEnv("OPERATOR_PROCESSOR_DISCOVERY_ENABLED", advertisedManagerIds.length > 0);
const processorDiscoveryIntervalMs = numberEnv("OPERATOR_PROCESSOR_DISCOVERY_INTERVAL_MS", 60_000);
const processorDiscoveryMaxAgeSeconds = numberEnv("OPERATOR_PROCESSOR_MAX_AGE_SECONDS", 900);
const processorDiscoveryLimit = numberEnv("OPERATOR_PROCESSOR_LIMIT", 0);
const processorDiscoveryAvailability = boolEnv("OPERATOR_PROCESSOR_DISCOVERY_CHECK_AVAILABILITY", true);
const processorDiscoveryStartDelayMs = numberEnv("OPERATOR_PROCESSOR_DISCOVERY_START_DELAY_MS", 120_000);
const processorDiscoveryDurationMs = numberEnv("OPERATOR_PROCESSOR_DISCOVERY_DURATION_MS", 300_000);
const floorPricePerMinute = optionalStringEnv("OPERATOR_FLOOR_PRICE_PER_MINUTE");
const payoutAddress = optionalStringEnv("OPERATOR_PAYOUT_ADDRESS");
const supportedAssets = splitCsv(process.env.OPERATOR_SUPPORTED_ASSETS ?? "");

let configVersion = 0;
const routes = new Map<string, RouteIntent>();
const routeStateOmittedSince = new Map<string, number>();
const managerInventories = new Map<string, ManagerProcessorInventory>();
let managerInventoryError: string | undefined;
let managerInventoryRefreshedAt: string | undefined;
let managerInventoryRefreshStartedAt = 0;
let managerInventoryRefresh: Promise<void> | undefined;
let publicAddressRefresh: Promise<void> | undefined;
interface RouteStateStatus {
  enabled: boolean;
  url?: string;
  lastCheckedAt?: string;
  lastAppliedAt?: string;
  lastSuccessAt?: string;
  lastCompletedAt?: string;
  lastError?: string;
  polledRouteCount?: number;
  desiredRouteCount?: number;
  lastAppliedRouteIds?: string[];
  lastRemovedRouteIds?: string[];
  lastRemovalReason?: string;
  configVersion?: string;
  consecutiveFailures: number;
  inFlightStartedAt?: string;
  inFlightAgeMs?: number;
  watchdogAbortCount: number;
  healthy: boolean;
  staleAfterMs: number;
}

let routeStateGeneration = 0;
let routeStateInFlight:
  | {
      generation: number;
      startedAtMs: number;
      startedAt: string;
      abortController: AbortController;
      promise: Promise<void>;
    }
  | undefined;
let routeStateStatus: RouteStateStatus = {
  enabled: Boolean(routeStateUrl),
  url: routeStateUrl,
  consecutiveFailures: 0,
  watchdogAbortCount: 0,
  healthy: !routeStateUrl,
  staleAfterMs: routeStateWatchdogMs
};
let publicAddressState: {
  mode: OperatorPublicAddressMode;
  publicAddresses: string[];
  source?: string;
  observedAt?: string;
  lastChangedAt?: string;
  probeError?: string;
} = {
  mode: publicAddressMode,
  publicAddresses: staticPublicAddresses,
  source: staticPublicAddresses.length > 0 ? "env" : undefined,
  observedAt: staticPublicAddresses.length > 0 ? new Date().toISOString() : undefined
};

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? "info"
  }
});

app.get("/health", async () => ({
  ok: true,
  routeCount: activeRoutes().length,
  storedRouteCount: routes.size,
  configVersion: configVersion.toString(),
  reportSigningEnabled: Boolean(reportSigningKey),
  reportSigningScheme,
  routeState: routeStateHealthStatus(),
  publicAddress: publicAddressState,
  processorDiscovery: processorDiscoveryHealth(),
  routeMetrics: {
    enabled: routeMetricsEnabled,
    statsUrl: routeMetricsEnabled ? routeMetricsStatsUrl : undefined,
    maxRoutes: routeMetricsMaxRoutes
  },
  xdsDir
}));

app.get("/route-intents", async (request, reply) => legacyRouteIntentState(request.headers.authorization, reply));

app.get("/internal/route-intents", async (request, reply) => legacyRouteIntentState(request.headers.authorization, reply));

app.get("/reports/route-status", async (request, reply) => {
  if (!routeIntentAuthorized(request.headers.authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  return buildRouteStatusReport({
    routes: [...routes.values()],
    xdsDir,
    configVersion: configVersion.toString(),
    listenerName,
    listenerAddress,
    listenerPort,
    operatorId,
    gatewayId,
    signingKey: reportSigningKey,
    signingScheme: reportSigningScheme,
    signingSs58Format: reportSigningSs58Format,
    filters: routeStatusReportFilters(request.query)
  });
});

app.get("/reports/gateway-capability", async (request, reply) => {
  try {
    return await buildSignedGatewayCapabilityReport();
  } catch (error) {
    return reply.code(503).send({
      error: "gateway_capability_unavailable",
      reason: error instanceof Error ? error.message : String(error)
    });
  }
});

app.get("/operator-signal-summary", async (request, reply) => {
  try {
    return await buildOperatorSignalSummary(operatorSignalSummaryQuery(request.query));
  } catch (error) {
    return reply.code(503).send({
      ok: false,
      sampledAt: new Date().toISOString(),
      source: "gateway-agent",
      error: error instanceof Error ? error.message : String(error)
    });
  }
});

app.post("/route-intents", async (request, reply) => {
  return legacyRouteIntentUpsert(request.headers.authorization, request.body, reply);
});

app.post("/internal/route-intents", async (request, reply) => legacyRouteIntentUpsert(request.headers.authorization, request.body, reply));

app.delete("/route-intents/:routeId", async (request, reply) => {
  const { routeId } = request.params as { routeId: string };
  return legacyRouteIntentDelete(request.headers.authorization, routeId, reply);
});

app.delete("/internal/route-intents/:routeId", async (request, reply) => {
  const { routeId } = request.params as { routeId: string };
  return legacyRouteIntentDelete(request.headers.authorization, routeId, reply);
});

async function legacyRouteIntentState(authorization: string | undefined, reply: any) {
  if (!routeIntentAuthorized(authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  return routeIntentStateResponse();
}

async function legacyRouteIntentUpsert(authorization: string | undefined, body: unknown, reply: any) {
  if (!routeIntentAuthorized(authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  const route = normalizeRouteIntent(body as Parameters<typeof normalizeRouteIntent>[0]);
  routes.set(route.routeId, route);
  await persistAndRender();

  app.log.info(
    {
      routeId: route.routeId,
      sessionId: route.sessionId,
      hostname: route.hostname,
      hostnames: routeHostnames(route),
      upstream: `${route.upstreamHost}:${route.upstreamPort}`,
      expiresAt: route.expiresAt
    },
    "route intent upserted"
  );

  return reply.code(202).send({
    ok: true,
    route,
    configVersion: configVersion.toString()
  });
}

async function legacyRouteIntentDelete(authorization: string | undefined, routeId: string, reply: any) {
  if (!routeIntentAuthorized(authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  const deleted = routes.delete(routeId);
  await persistAndRender();

  return reply.send({
    ok: true,
    deleted,
    configVersion: configVersion.toString()
  });
}

function routeIntentStateResponse() {
  return {
    routes: [...routes.values()],
    activeRoutes: activeRoutes(),
    configVersion: configVersion.toString()
  };
}

await loadState();
if (routeStateUrl && (!operatorId || !gatewayId)) {
  throw new Error("GATEWAY_ROUTE_STATE_URL requires OPERATOR_ID and GATEWAY_ID");
}
await persistAndRender();

setInterval(() => {
  const before = activeRoutes().length;
  void persistAndRender().then(() => {
    const after = activeRoutes().length;
    if (before !== after) {
      app.log.info({ before, after }, "route expiry sweep updated xds");
    }
  });
}, expirySweepMs).unref();

if (capabilityReportUrl) {
  setInterval(() => {
    void submitGatewayCapabilityReport();
  }, capabilityReportIntervalMs).unref();
  void submitGatewayCapabilityReport();
}

if (routeStateUrl) {
  setInterval(() => {
    void pollRouteState();
  }, routeStatePollIntervalMs).unref();
  void pollRouteState();
}

if (publicAddressMode === "auto") {
  setInterval(() => {
    void refreshPublicAddress();
  }, wanIpPollIntervalMs).unref();
  void refreshPublicAddress();
}

if (processorDiscoveryEnabled && advertisedManagerIds.length > 0) {
  setInterval(() => {
    void refreshManagerInventories();
  }, processorDiscoveryIntervalMs).unref();
  void refreshManagerInventories();
}

await app.listen({ host, port });

async function submitGatewayCapabilityReport(): Promise<void> {
  try {
    const report = await buildSignedGatewayCapabilityReport();
    const response = await fetch(capabilityReportUrl!, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(capabilityReportToken ? { authorization: `Bearer ${capabilityReportToken}` } : {})
      },
      body: JSON.stringify(report)
    });
    if (!response.ok) {
      throw new Error(`capability post failed: ${response.status} ${await response.text()}`);
    }
    app.log.info(
      {
        operatorId,
        gatewayId,
        reportId: report.report.reportId,
        expiresAt: report.report.expiresAt
      },
      "gateway capability report submitted"
    );
  } catch (error) {
    app.log.warn(
      {
        error: error instanceof Error ? error.message : String(error)
      },
      "gateway capability report submission failed"
    );
  }
}

async function buildSignedGatewayCapabilityReport() {
  if (!operatorId || !/^0x[0-9a-fA-F]{64}$/.test(operatorId)) {
    throw new Error("OPERATOR_ID must be a bytes32 hex string for gateway capability reports");
  }
  if (!gatewayId) {
    throw new Error("GATEWAY_ID is required for gateway capability reports");
  }
  if (!reportSigningKey || !reportSigningScheme) {
    throw new Error("OPERATOR_REPORT_SEED or OPERATOR_REPORT_PRIVATE_KEY is required for gateway capability reports");
  }
  const publicAddressReport = await gatewayPublicAddressReportState();
  const routeMetrics = await gatewayRouteMetricsForReport();

  const now = new Date();
  const nowUnixSeconds = Math.floor(now.getTime() / 1000);
  const report: GatewayCapabilityReport = {
    version: 1,
    kind: "switchboard.operator.capability",
    reportId: `gateway-capability-${nowUnixSeconds}-${configVersion}`,
    reportedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + capabilityReportTtlSeconds * 1000).toISOString(),
    operator: {
      operatorId: operatorId.toLowerCase(),
      gatewayId,
      managerIds: advertisedManagerIds.length > 0 ? advertisedManagerIds : undefined
    },
    gateway: {
      publicAddresses: publicAddressReport.publicAddresses,
      publicAddressMode: publicAddressReport.mode,
      publicAddressSource: publicAddressReport.source,
      publicAddressObservedAt: publicAddressReport.observedAt,
      publicAddressLastChangedAt: publicAddressReport.lastChangedAt,
      publicAddressProbeError: publicAddressReport.probeError,
      validationHostname,
      routeStateUrl,
      routeIntentUrl,
      activeRouteCount: activeRoutes().length,
      routeCapacity,
      softwareVersion: process.env.PROOF_OPERATOR_SOFTWARE_VERSION,
      supportedClasses,
      routeStateHealthy: routeStateUrl ? routeStateHealthy() : undefined,
      routeStateLastSuccessAt: routeStateStatus.lastSuccessAt,
      routeState: routeStateHealthStatus(),
      routeMetrics: routeMetrics.length > 0 ? routeMetrics : undefined
    },
    processorScopes: await capabilityProcessorScopes(),
    economics:
      floorPricePerMinute || payoutAddress || supportedAssets.length > 0
        ? {
            floorPricePerMinute,
            payoutAddress,
            supportedAssets
          }
        : undefined
  };

  return signGatewayCapabilityReport(report, reportSigningKey, {
    scheme: reportSigningScheme,
    ss58Format: reportSigningSs58Format
  });
}

async function gatewayRouteMetricsForReport(): Promise<NonNullable<GatewayCapabilityReport["gateway"]["routeMetrics"]>> {
  if (!routeMetricsEnabled) {
    return [];
  }
  try {
    return await collectEnvoyRouteMetrics({
      routes: activeRoutes(),
      statsUrl: routeMetricsStatsUrl,
      timeoutMs: routeMetricsTimeoutMs,
      maxRoutes: routeMetricsMaxRoutes
    });
  } catch (error) {
    app.log.debug(
      {
        error: error instanceof Error ? error.message : String(error),
        statsUrl: routeMetricsStatsUrl
      },
      "gateway route metrics unavailable"
    );
    return [];
  }
}

async function gatewayPublicAddressReportState(): Promise<typeof publicAddressState> {
  if (publicAddressMode === "auto" && publicAddressState.publicAddresses.length === 0) {
    await refreshPublicAddress();
  }
  return publicAddressState;
}

async function refreshPublicAddress(): Promise<void> {
  if (publicAddressMode !== "auto") {
    return;
  }
  if (publicAddressRefresh) {
    await publicAddressRefresh;
    return;
  }
  publicAddressRefresh = doRefreshPublicAddress().finally(() => {
    publicAddressRefresh = undefined;
  });
  await publicAddressRefresh;
}

async function doRefreshPublicAddress(): Promise<void> {
  const observedAt = new Date().toISOString();
  try {
    const nextIp = await fetchWanIpv4({ url: wanIpUrl, timeoutMs: wanIpTimeoutMs });
    const previousIp = publicAddressState.publicAddresses[0];
    const changed = previousIp !== nextIp;
    publicAddressState = {
      mode: "auto",
      publicAddresses: [nextIp],
      source: wanIpUrl,
      observedAt,
      lastChangedAt: changed ? observedAt : publicAddressState.lastChangedAt,
      probeError: undefined
    };
    if (changed) {
      app.log.info(
        {
          previousIp,
          nextIp,
          source: wanIpUrl
        },
        "gateway WAN IP changed"
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    publicAddressState = {
      ...publicAddressState,
      observedAt,
      probeError: message
    };
    app.log.warn(
      {
        error: message,
        source: wanIpUrl
      },
      "gateway WAN IP probe failed"
    );
  }
}

function routeIntentAuthorized(authorization: string | undefined): boolean {
  if (!routeIntentToken) {
    return true;
  }
  return authorization === `Bearer ${routeIntentToken}`;
}

async function buildOperatorSignalSummary(query: {
  sessionId?: string;
  hostname?: string;
  processorId?: string;
  publicAddress?: string;
}) {
  const sampledAt = new Date();
  const active = activeRoutes();
  const route = findSignalRoute(query, active);
  const processorId = query.processorId ? processorRefToId(query.processorId) : undefined;
  let capability:
    | {
        available: boolean;
        reportId?: string;
        signer?: string;
        reportedAt?: string;
        expiresAt?: string;
        operatorId?: string;
        gatewayId?: string;
        managerIds?: string[];
        routeCapacity?: number;
        activeRouteCount?: number;
        publicAddresses?: string[];
        publicAddressMode?: string;
        publicAddressSource?: string;
        publicAddressObservedAt?: string;
        publicAddressLastChangedAt?: string;
        publicAddressProbeError?: string;
        processorMatched?: boolean;
        publicAddressMatched?: boolean;
        error?: string;
      }
    | undefined;

  try {
    const signed = await buildSignedGatewayCapabilityReport();
    capability = {
      available: true,
      reportId: signed.report.reportId,
      signer: signed.signature.signer,
      reportedAt: signed.report.reportedAt,
      expiresAt: signed.report.expiresAt,
      operatorId: signed.report.operator.operatorId,
      gatewayId: signed.report.operator.gatewayId,
      managerIds: signed.report.operator.managerIds,
      routeCapacity: signed.report.gateway.routeCapacity,
      activeRouteCount: signed.report.gateway.activeRouteCount,
      publicAddresses: signed.report.gateway.publicAddresses,
      publicAddressMode: signed.report.gateway.publicAddressMode,
      publicAddressSource: signed.report.gateway.publicAddressSource,
      publicAddressObservedAt: signed.report.gateway.publicAddressObservedAt,
      publicAddressLastChangedAt: signed.report.gateway.publicAddressLastChangedAt,
      publicAddressProbeError: signed.report.gateway.publicAddressProbeError,
      processorMatched: processorId ? capabilityReportIncludesProcessor(signed.report, processorId) : undefined,
      publicAddressMatched: query.publicAddress ? signed.report.gateway.publicAddresses.includes(query.publicAddress) : undefined
    };
  } catch (error) {
    capability = {
      available: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }

  return {
    ok: true,
    sampledAt: sampledAt.toISOString(),
    source: "gateway-agent",
    capability,
    gateway: {
      reachable: true,
      operatorId,
      gatewayId,
      configVersion: configVersion.toString(),
      routeInstalled: Boolean(route),
      routeActive: route ? routeIsActive(route) : undefined,
      routeExpiresAt: route ? new Date(route.expiresAt * 1000).toISOString() : undefined,
      matchedHostnames: route ? routeHostnames(route).serverNames : undefined,
      activeRouteCount: active.length,
      storedRouteCount: routes.size,
      processorDiscoveryFresh: managerInventoryFresh(),
      reportedProcessorCount: reportedProcessorCount()
    }
  };
}

async function capabilityProcessorScopes(): Promise<GatewayCapabilityReport["processorScopes"]> {
  if (advertisedManagerIds.length > 0) {
    await ensureManagerInventoriesFresh();
    return advertisedManagerIds.map((managerId) => ({
      kind: "manager",
      managerId,
      processors: processorsForManagerScope(managerId),
      excludeProcessors: excludedProcessors.length > 0 ? excludedProcessors : undefined
    }));
  }
  if (advertisedProcessors.length > 0) {
    return [
      {
        kind: "explicit",
        processors: advertisedProcessors
      }
    ];
  }
  return [];
}

async function ensureManagerInventoriesFresh(): Promise<void> {
  if (!processorDiscoveryEnabled || advertisedManagerIds.length === 0) {
    return;
  }
  const stale = Date.now() - managerInventoryRefreshStartedAt >= processorDiscoveryIntervalMs;
  if (managerInventories.size > 0 && !stale) {
    return;
  }
  await refreshManagerInventories();
}

async function refreshManagerInventories(): Promise<void> {
  if (!processorDiscoveryEnabled || advertisedManagerIds.length === 0) {
    return;
  }
  if (managerInventoryRefresh) {
    await managerInventoryRefresh;
    return;
  }

  managerInventoryRefreshStartedAt = Date.now();
  managerInventoryRefresh = doRefreshManagerInventories().finally(() => {
    managerInventoryRefresh = undefined;
  });
  await managerInventoryRefresh;
}

async function doRefreshManagerInventories(): Promise<void> {
  const rpcUrl = rpcForAcurastNetwork(acurastNetwork, acurastRpcUrl);
  const api = await createAcurastApi({ network: acurastNetwork, rpcUrl });
  try {
    const next = new Map<string, ManagerProcessorInventory>();
    for (const managerId of advertisedManagerIds) {
      next.set(
        managerId,
        await discoverManagerProcessorsWithApi(api, {
          network: acurastNetwork,
          managerId,
          rpcUrl,
          maxAgeSeconds: processorDiscoveryMaxAgeSeconds,
          checkAvailability: processorDiscoveryAvailability,
          startDelayMs: processorDiscoveryStartDelayMs,
          durationMs: processorDiscoveryDurationMs,
          processorFilter: processorDiscoveryFilter
        })
      );
    }
    managerInventories.clear();
    for (const [managerId, inventory] of next) {
      managerInventories.set(managerId, inventory);
    }
    managerInventoryError = undefined;
    managerInventoryRefreshedAt = new Date().toISOString();
    app.log.info(
      {
        managers: [...managerInventories.values()].map((inventory) => ({
          managerId: inventory.managerId,
          totalProcessors: inventory.totalProcessors,
          recentProcessors: inventory.recentProcessors,
          reportedProcessors: processorsForManagerScope(inventory.managerId)?.length ?? 0
        }))
      },
      "manager processor inventory refreshed"
    );
  } catch (error) {
    managerInventoryError = error instanceof Error ? error.message : String(error);
    app.log.warn(
      {
        error: managerInventoryError
      },
      "manager processor inventory refresh failed"
    );
  } finally {
    await api.disconnect();
  }
}

function processorsForManagerScope(managerId: string): string[] | undefined {
  const inventory = managerInventories.get(managerId);
  if (!inventory) {
    return undefined;
  }
  const processors = processorsForInventory(inventory);
  return processors.length > 0 ? processors : undefined;
}

function processorsForInventory(inventory: ManagerProcessorInventory): string[] {
  return selectReadyProcessors(inventory.processors, {
    maxAgeSeconds: processorDiscoveryMaxAgeSeconds,
    requireAvailability: processorDiscoveryAvailability,
    limit: processorDiscoveryLimit,
    includeProcessors: advertisedProcessors,
    excludeProcessors: excludedProcessors
  })
    .map((processor) => processor.processor);
}

function processorDiscoveryFilter(processors: string[]): string[] {
  let selected = processors;
  if (advertisedProcessors.length > 0) {
    selected = selected.filter((processor) => processorRefSetHas(advertisedProcessors, processor));
  }
  if (excludedProcessors.length > 0) {
    selected = selected.filter((processor) => !processorRefSetHas(excludedProcessors, processor));
  }
  return selected;
}

function processorRefSetHas(refs: string[], processor: string): boolean {
  const processorId = processorRefToId(processor);
  return refs.some((ref) => ref === processor || (processorId && processorRefToId(ref) === processorId));
}

function processorDiscoveryHealth() {
  return {
    enabled: processorDiscoveryEnabled,
    network: acurastNetwork,
    rpcUrl: processorDiscoveryEnabled ? rpcForAcurastNetwork(acurastNetwork, acurastRpcUrl) : undefined,
    managerIds: advertisedManagerIds,
    maxAgeSeconds: processorDiscoveryMaxAgeSeconds,
    checkAvailability: processorDiscoveryAvailability,
    refreshedAt: managerInventoryRefreshedAt,
    error: managerInventoryError,
    inventories: [...managerInventories.values()].map((inventory) => ({
      managerId: inventory.managerId,
      totalProcessors: inventory.totalProcessors,
      recentProcessors: inventory.recentProcessors,
      availableProcessors: inventory.availableProcessors,
      recentAvailableProcessors: inventory.recentAvailableProcessors,
      reportedProcessors: processorsForManagerScope(inventory.managerId)?.length ?? 0
    }))
  };
}

function operatorSignalSummaryQuery(query: unknown): {
  sessionId?: string;
  hostname?: string;
  processorId?: string;
  publicAddress?: string;
} {
  if (!query || typeof query !== "object") {
    return {};
  }
  const record = query as Record<string, unknown>;
  return {
    sessionId: stringQueryField(record, "sessionId"),
    hostname: optionalNormalizedHostname(stringQueryField(record, "hostname")),
    processorId: stringQueryField(record, "processorId"),
    publicAddress: stringQueryField(record, "publicAddress")
  };
}

function findSignalRoute(query: { sessionId?: string; hostname?: string }, active: RouteIntent[]): RouteIntent | undefined {
  if (query.sessionId) {
    const bySession = active.find((route) => route.sessionId.toLowerCase() === query.sessionId?.toLowerCase());
    if (bySession) {
      return bySession;
    }
  }
  if (query.hostname) {
    return active.find((route) => routeHostnames(route).serverNames.includes(query.hostname as string));
  }
  return undefined;
}

function capabilityReportIncludesProcessor(report: GatewayCapabilityReport, processorId: string): boolean {
  return report.processorScopes.some((scope) =>
    [...(scope.processors ?? []), ...(scope.includeProcessors ?? [])].some((processor) => processorRefToId(processor) === processorId)
  );
}

function managerInventoryFresh(): boolean | undefined {
  if (!processorDiscoveryEnabled) {
    return undefined;
  }
  if (!managerInventoryRefreshedAt) {
    return false;
  }
  return Date.now() - Date.parse(managerInventoryRefreshedAt) <= processorDiscoveryIntervalMs + 30_000;
}

function reportedProcessorCount(): number | undefined {
  if (!processorDiscoveryEnabled) {
    return undefined;
  }
  return [...managerInventories.values()].reduce((total, inventory) => total + processorsForInventory(inventory).length, 0);
}

async function loadState(): Promise<void> {
  try {
    const raw = await fs.readFile(stateFile, "utf8");
    const parsed = JSON.parse(raw) as { routes?: unknown[] };
    for (const item of parsed.routes ?? []) {
      const route = normalizeRouteIntent(item as Parameters<typeof normalizeRouteIntent>[0]);
      routes.set(route.routeId, route);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
  }
}

function pollRouteState(): void {
  if (!routeStateUrl) {
    return;
  }
  const nowMs = Date.now();
  if (routeStateInFlight) {
    const ageMs = nowMs - routeStateInFlight.startedAtMs;
    if (ageMs <= routeStateWatchdogMs) {
      return;
    }
    const staleGeneration = routeStateInFlight.generation;
    routeStateInFlight.abortController.abort();
    routeStateInFlight = undefined;
    routeStateStatus = {
      ...routeStateStatus,
      lastError: `route state poll generation ${staleGeneration} exceeded watchdog ${routeStateWatchdogMs}ms`,
      lastCompletedAt: new Date(nowMs).toISOString(),
      consecutiveFailures: routeStateStatus.consecutiveFailures + 1,
      watchdogAbortCount: routeStateStatus.watchdogAbortCount + 1
    };
    app.log.warn(
      {
        generation: staleGeneration,
        ageMs,
        watchdogMs: routeStateWatchdogMs,
        url: routeStateUrl
      },
      "gateway route state poll watchdog aborted stale generation"
    );
  }
  const generation = routeStateGeneration + 1;
  routeStateGeneration = generation;
  const startedAtMs = Date.now();
  const abortController = new AbortController();
  routeStateInFlight = {
    generation,
    startedAtMs,
    startedAt: new Date(startedAtMs).toISOString(),
    abortController,
    promise: doPollRouteState(generation, abortController.signal).finally(() => {
      if (routeStateInFlight?.generation === generation) {
        routeStateInFlight = undefined;
      }
    })
  };
}

async function doPollRouteState(generation: number, signal: AbortSignal): Promise<void> {
  const checkedAt = new Date().toISOString();
  try {
    const state = await fetchRouteState(signal);
    if (!routeStateGenerationCurrent(generation)) {
      return;
    }
    const polledRoutes = desiredRoutesFromRouteState(state);
    const desiredRoutes = routesWithRemovalGrace(polledRoutes, Date.now());
    const beforeIds = [...routes.keys()].sort();
    const afterIds = [...desiredRoutes.keys()].sort();
    const removedIds = beforeIds.filter((routeId) => !desiredRoutes.has(routeId));
    const completedAt = new Date().toISOString();
    if (!routeMapsEqual(routes, desiredRoutes)) {
      routes.clear();
      for (const route of desiredRoutes.values()) {
        routes.set(route.routeId, route);
      }
      await persistAndRender();
      if (!routeStateGenerationCurrent(generation)) {
        return;
      }
      routeStateStatus = {
        ...routeStateStatus,
        lastCheckedAt: checkedAt,
        lastAppliedAt: completedAt,
        lastSuccessAt: completedAt,
        lastCompletedAt: completedAt,
        lastError: undefined,
        polledRouteCount: polledRoutes.size,
        desiredRouteCount: desiredRoutes.size,
        lastAppliedRouteIds: afterIds,
        lastRemovedRouteIds: removedIds,
        lastRemovalReason: removedIds.length > 0 ? "route_state_omitted_after_grace" : undefined,
        configVersion: configVersion.toString(),
        consecutiveFailures: 0
      };
      app.log.info({ routeCount: desiredRoutes.size, polledRouteCount: polledRoutes.size, url: routeStateUrl }, "gateway route state applied");
      return;
    }
    routeStateStatus = {
      ...routeStateStatus,
      lastCheckedAt: checkedAt,
      lastSuccessAt: completedAt,
      lastCompletedAt: completedAt,
      lastError: undefined,
      polledRouteCount: polledRoutes.size,
      desiredRouteCount: desiredRoutes.size,
      configVersion: configVersion.toString(),
      consecutiveFailures: 0
    };
  } catch (error) {
    if (!routeStateGenerationCurrent(generation)) {
      return;
    }
    const message = error instanceof Error ? error.message : String(error);
    routeStateStatus = {
      ...routeStateStatus,
      lastCheckedAt: checkedAt,
      lastCompletedAt: new Date().toISOString(),
      lastError: message,
      consecutiveFailures: routeStateStatus.consecutiveFailures + 1
    };
    app.log.warn({ error: message, url: routeStateUrl }, "gateway route state poll failed");
  }
}

function routeStateGenerationCurrent(generation: number): boolean {
  return generation === routeStateGeneration;
}

function routeStateHealthStatus(): RouteStateStatus {
  const inFlight = routeStateInFlight;
  const nowMs = Date.now();
  const inFlightAgeMs = inFlight ? nowMs - inFlight.startedAtMs : undefined;
  return {
    ...routeStateStatus,
    inFlightStartedAt: inFlight?.startedAt,
    inFlightAgeMs,
    healthy: routeStateHealthy(nowMs, inFlightAgeMs)
  };
}

function routeStateHealthy(nowMs = Date.now(), inFlightAgeMs?: number): boolean {
  if (!routeStateUrl) {
    return true;
  }
  if (inFlightAgeMs !== undefined && inFlightAgeMs > routeStateWatchdogMs) {
    return false;
  }
  if (!routeStateStatus.lastSuccessAt) {
    return false;
  }
  return nowMs - Date.parse(routeStateStatus.lastSuccessAt) <= routeStateWatchdogMs;
}

async function fetchRouteState(signal: AbortSignal): Promise<Record<string, unknown>> {
  const abortController = new AbortController();
  const timeout = setTimeout(() => abortController.abort(), routeStateTimeoutMs);
  const abortFromCaller = () => abortController.abort();
  signal.addEventListener("abort", abortFromCaller, { once: true });
  try {
    const response = await fetch(routeStateUrl!, {
      method: "GET",
      signal: abortController.signal,
      headers: routeStateToken ? { authorization: `Bearer ${routeStateToken}` } : undefined
    });
    const body = await response.text();
    if (!response.ok) {
      throw new Error(`route state GET failed: ${response.status} ${body}`);
    }
    return objectRecord(JSON.parse(body), "route state response");
  } finally {
    clearTimeout(timeout);
    signal.removeEventListener("abort", abortFromCaller);
  }
}

function routesWithRemovalGrace(polledRoutes: Map<string, RouteIntent>, nowMs: number): Map<string, RouteIntent> {
  const desired = new Map(polledRoutes);
  for (const routeId of polledRoutes.keys()) {
    routeStateOmittedSince.delete(routeId);
  }
  for (const [routeId, route] of routes.entries()) {
    if (desired.has(routeId)) {
      continue;
    }
    if (!routeIsActive(route) || routeStateRemovalGraceMs <= 0) {
      routeStateOmittedSince.delete(routeId);
      continue;
    }
    const omittedSince = routeStateOmittedSince.get(routeId) ?? nowMs;
    routeStateOmittedSince.set(routeId, omittedSince);
    if (nowMs - omittedSince < routeStateRemovalGraceMs) {
      desired.set(routeId, route);
    } else {
      routeStateOmittedSince.delete(routeId);
    }
  }
  return desired;
}

function desiredRoutesFromRouteState(input: Record<string, unknown>): Map<string, RouteIntent> {
  if (input.ok !== true) {
    throw new Error("route state response ok must be true");
  }
  if (input.version !== 1) {
    throw new Error("route state response version must be 1");
  }
  const responseOperatorId = stringField(input, "operatorId").toLowerCase();
  const responseGatewayId = stringField(input, "gatewayId");
  if (!operatorId || responseOperatorId !== operatorId.toLowerCase()) {
    throw new Error("route state operatorId mismatch");
  }
  if (!gatewayId || responseGatewayId !== gatewayId) {
    throw new Error("route state gatewayId mismatch");
  }
  if (typeof input.generatedAt !== "string" || input.generatedAt.length === 0) {
    throw new Error("route state generatedAt missing");
  }
  if (!Array.isArray(input.routes)) {
    throw new Error("route state routes must be an array");
  }

  const desired = new Map<string, RouteIntent>();
  for (const item of input.routes) {
    const route = normalizeRouteIntent(item as Parameters<typeof normalizeRouteIntent>[0]);
    if (!routeIsActive(route)) {
      continue;
    }
    const source = route.source && typeof route.source === "object" && !Array.isArray(route.source)
      ? route.source as Record<string, unknown>
      : {};
    const routeOperatorId = typeof source.operatorId === "string" ? source.operatorId.toLowerCase() : responseOperatorId;
    const routeGatewayId = typeof source.gatewayId === "string" ? source.gatewayId : responseGatewayId;
    if (routeOperatorId !== responseOperatorId || routeGatewayId !== responseGatewayId) {
      continue;
    }
    desired.set(route.routeId, route);
  }
  return desired;
}

function routeMapsEqual(left: Map<string, RouteIntent>, right: Map<string, RouteIntent>): boolean {
  return JSON.stringify(sortedRoutes(left)) === JSON.stringify(sortedRoutes(right));
}

function sortedRoutes(input: Map<string, RouteIntent>): RouteIntent[] {
  return [...input.values()].sort((left, right) => left.routeId.localeCompare(right.routeId));
}

async function persistAndRender(): Promise<void> {
  await fs.mkdir(path.dirname(stateFile), { recursive: true });
  await fs.writeFile(
    stateFile,
    `${JSON.stringify(
      {
        updatedAt: new Date().toISOString(),
        routes: [...routes.values()]
      },
      null,
      2
    )}\n`
  );

  configVersion += 1;
  await renderFileXds(activeRoutes(), {
    outputDir: xdsDir,
    version: configVersion.toString(),
    listenerName,
    listenerAddress,
    listenerPort
  });
}

function activeRoutes(): RouteIntent[] {
  return [...routes.values()].filter((route) => routeIsActive(route));
}

function routeStatusReportFilters(query: unknown): RouteStatusReportFilters | undefined {
  if (!query || typeof query !== "object") {
    return undefined;
  }
  const record = query as Record<string, unknown>;
  return {
    routeId: stringQueryField(record, "routeId"),
    sessionId: stringQueryField(record, "sessionId"),
    hostname: optionalNormalizedHostname(stringQueryField(record, "hostname"))
  };
}

function stringQueryField(record: Record<string, unknown>, name: string): string | undefined {
  const value = record[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function optionalNormalizedHostname(value: string | undefined): string | undefined {
  return value ? normalizeHostname(value) : undefined;
}

function optionalStringEnv(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function objectRecord(input: unknown, label: string): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} must be an object`);
  }
  return input as Record<string, unknown>;
}

function stringField(input: Record<string, unknown>, name: string): string {
  const value = input[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`route state ${name} missing`);
  }
  return value;
}

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))];
}

function boolEnv(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value == null || value === "") {
    return fallback;
  }
  if (["true", "1", "yes", "on"].includes(value.toLowerCase())) {
    return true;
  }
  if (["false", "0", "no", "off"].includes(value.toLowerCase())) {
    return false;
  }

  throw new Error(`${name} must be a boolean`);
}

function numberEnv(name: string, fallback: number): number {
  const value = process.env[name];
  if (value == null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }

  return parsed;
}

function optionalNumberEnv(name: string): number | undefined {
  const value = process.env[name];
  if (value == null || value === "") {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }

  return parsed;
}
