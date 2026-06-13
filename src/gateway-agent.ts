import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import https from "node:https";
import { isIP } from "node:net";
import path from "node:path";
import tls from "node:tls";

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
import {
  connectParachain,
  deriveGatewayObservations,
  publishGatewayObservations
} from "./parachain-observations.js";
import { signReportPayload, verifyReportSignature } from "./report-signing.js";
import type { ApiPromise } from "@polkadot/api";
import { renderFileXds } from "./xds.js";
import {
  gatewayCapabilityReportId,
  processorRefToId,
  signGatewayCapabilityReport,
  type GatewayCapabilityReport
} from "./operator-capability.js";
import { fetchWanIpv4, normalizeOperatorPublicAddressMode, type OperatorPublicAddressMode } from "./wan-ip.js";
import {
  GATEWAY_UPSTREAM_OBSERVATION_DOMAIN,
  gatewayUpstreamAdmissionDigest,
  gatewayUpstreamAdmissionId,
  normalizeGatewayUpstreamAdmissionPayload,
  normalizeGatewayUpstreamObservationPayload,
  normalizeGatewayUpstreamProbeResponsePayload,
  normalizeSecp256k1SignatureForDigest,
  recoverGatewayUpstreamProbeResponseSigner,
  type GatewayUpstreamAdmissionPayload,
  type SignedGatewayUpstreamObservation
} from "./gateway-upstream-admission.js";

const SWITCHBOARD_UPSTREAM_ADMISSION_PATH = "/.well-known/proofcomputer/upstream-admission";

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
// PROOF Ingress parachain gateway observations. The gateway signs Serving/Stopped
// acks for its bound route generations with its sr25519 operational key
// (OPERATOR_REPORT_SEED). Off by default; enabled when a parachain endpoint and a
// numeric on-chain gateway id are configured.
const proofIngressWsUrl = optionalStringEnv("PROOF_INGRESS_WS_URL");
const proofIngressGatewayId = optionalNumberEnv("PROOF_INGRESS_GATEWAY_ID");
const proofIngressObservationIntervalMs = numberEnv("PROOF_INGRESS_OBSERVATION_INTERVAL_MS", 60_000);
const proofIngressObservationBatchMax = numberEnv("PROOF_INGRESS_OBSERVATION_BATCH_MAX", 256);
const proofIngressVerifyBindings = boolEnv("PROOF_INGRESS_OBSERVATION_VERIFY_BINDINGS", true);
const proofIngressEnabled =
  Boolean(proofIngressWsUrl) &&
  reportSigningScheme === "substrate-sr25519" &&
  Boolean(reportSigningKey) &&
  proofIngressGatewayId !== undefined;
let proofIngressApi: ApiPromise | null = null;
let proofIngressConnecting: Promise<ApiPromise> | null = null;
const routeIntentToken = process.env.GATEWAY_AGENT_ROUTE_INTENT_TOKEN;
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
const upstreamAdmissionTtlSeconds = numberEnv("GATEWAY_UPSTREAM_ADMISSION_TTL_SECONDS", 7_200);
const upstreamAdmissionAllowedCidrs = splitCsv(process.env.GATEWAY_UPSTREAM_ADMISSION_ALLOWED_CIDRS ?? "");
const upstreamAdmissionTlsProbeEnabled = boolEnv("GATEWAY_UPSTREAM_ADMISSION_TLS_PROBE_ENABLED", true);
const upstreamAdmissionTlsProbeTimeoutMs = numberEnv("GATEWAY_UPSTREAM_ADMISSION_TLS_PROBE_TIMEOUT_MS", 3_000);
const upstreamAdmissionCaFile = optionalStringEnv("GATEWAY_UPSTREAM_ADMISSION_CA_FILE");
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
const processorDiscoveryTimeoutMs = numberEnv(
  "OPERATOR_PROCESSOR_DISCOVERY_TIMEOUT_MS",
  Math.max(processorDiscoveryIntervalMs * 2, 120_000)
);
const floorPricePerMinute = optionalStringEnv("OPERATOR_FLOOR_PRICE_PER_MINUTE");
const payoutAddress = optionalStringEnv("OPERATOR_PAYOUT_ADDRESS");
const supportedAssets = splitCsv(process.env.OPERATOR_SUPPORTED_ASSETS ?? "");

let configVersion = 0;
const routes = new Map<string, RouteIntent>();
const upstreamAdmissions = new Map<string, StoredGatewayUpstreamAdmission>();
const upstreamAdmissionNonces = new Map<string, number>();
const routeStateOmittedSince = new Map<string, number>();
const managerInventories = new Map<string, ManagerProcessorInventory>();
let managerInventoryError: string | undefined;
let managerInventoryRefreshedAt: string | undefined;
let managerInventoryRefreshGeneration = 0;
let managerInventoryRefresh:
  | {
      generation: number;
      startedAtMs: number;
      startedAt: string;
      promise: Promise<void>;
    }
  | undefined;
let managerInventoryRefreshTimedOutCount = 0;
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
  pendingUpstreamAdmissionRequestCount?: number;
  acceptedUpstreamAdmissionCount?: number;
  processedUpstreamAdmissionRequestCount?: number;
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

interface StoredGatewayUpstreamAdmission extends SignedGatewayUpstreamObservation {
  requestSignature: string;
}

interface PulledGatewayUpstreamAdmissionRequest {
  requestDigest: string;
  request: GatewayUpstreamAdmissionPayload;
  requestSignature: string;
  candidateUpstreamIps: string[];
}

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? "info"
  }
});

app.get("/health", async () => ({
  ok: true,
  routeCount: activeRoutes().length,
  storedRouteCount: routes.size,
  upstreamAdmissionCount: freshUpstreamAdmissions().length,
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

app.post("/v1/upstream-admissions", async (request, reply) => {
  try {
    const admission = await admitGatewayUpstream(request.body, request.raw.socket.remoteAddress, request.raw.socket.remotePort);
    await persistAndRender();
    app.log.info(
      {
        admissionId: admission.observation.admissionId,
        intentId: admission.observation.request.intentId,
        observedIp: admission.observation.observedIp,
        upstreamPort: admission.observation.request.upstreamPort
      },
      "gateway upstream admitted"
    );
    return reply.code(201).send({
      ok: true,
      request: admission.observation.request,
      requestSignature: admission.requestSignature,
      observation: admission.observation,
      observationSignature: admission.signature
    });
  } catch (error) {
    const statusCode = error instanceof GatewayUpstreamAdmissionError ? error.statusCode : 400;
    return reply.code(statusCode).send({
      error: error instanceof GatewayUpstreamAdmissionError ? error.code : "invalid_upstream_admission",
      reason: error instanceof Error ? error.message : String(error)
    });
  }
});

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

class GatewayUpstreamAdmissionError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string
  ) {
    super(message);
  }
}

async function admitGatewayUpstream(
  body: unknown,
  remoteAddress: string | undefined,
  remotePort: number | undefined
): Promise<StoredGatewayUpstreamAdmission> {
  if (!operatorId || !gatewayId) {
    throw new GatewayUpstreamAdmissionError(503, "gateway_identity_unavailable", "OPERATOR_ID and GATEWAY_ID are required");
  }
  if (!reportSigningKey || !reportSigningScheme) {
    throw new GatewayUpstreamAdmissionError(503, "gateway_observation_signing_unavailable", "gateway report signing is required");
  }
  const record = objectRecord(body, "upstream admission request");
  const request = normalizeGatewayUpstreamAdmissionPayload(parseGatewayUpstreamAdmissionPayload(record.request));
  const requestSignature = stringField(record, "signature");
  if (request.operatorId.toLowerCase() !== operatorId.toLowerCase()) {
    throw new GatewayUpstreamAdmissionError(422, "operator_id_mismatch", "admission operatorId does not match this gateway");
  }
  if (request.gatewayId !== gatewayId) {
    throw new GatewayUpstreamAdmissionError(422, "gateway_id_mismatch", "admission gatewayId does not match this gateway");
  }
  if (Number(request.deadline) <= Math.floor(Date.now() / 1000)) {
    throw new GatewayUpstreamAdmissionError(422, "admission_expired", "admission deadline has expired");
  }
  const digest = gatewayUpstreamAdmissionDigest(request);
  const normalizedRequestSignature = normalizeSecp256k1SignatureForDigest(requestSignature, digest, request.runtimeSigner);
  const observedIp = normalizeObservedIp(remoteAddress);
  if (!observedIp) {
    throw new GatewayUpstreamAdmissionError(422, "observed_ip_unavailable", "gateway could not identify an IPv4 peer address");
  }
  if (!observedIpAllowed(observedIp)) {
    throw new GatewayUpstreamAdmissionError(403, "observed_ip_not_allowed", `observed upstream IP ${observedIp} is not allowed`);
  }
  const nonceKey = `${request.runtimeSigner.toLowerCase()}:${request.intentId}:${request.nonce}`;
  pruneUpstreamAdmissionNonces();
  if (upstreamAdmissionNonces.has(nonceKey)) {
    throw new GatewayUpstreamAdmissionError(409, "nonce_replay", "upstream admission nonce has already been used");
  }

  const tlsResult = await verifyUpstreamTls(request, observedIp);
  return signAndStoreGatewayUpstreamAdmission({
    request,
    requestDigest: digest,
    requestSignature: normalizedRequestSignature,
    observedIp,
    ...(remotePort === undefined ? {} : { observedPort: remotePort }),
    tls: tlsResult
  });
}

async function signAndStoreGatewayUpstreamAdmission(input: {
  request: GatewayUpstreamAdmissionPayload;
  requestDigest: string;
  requestSignature: string;
  observedIp: string;
  observedPort?: number;
  tls: StoredGatewayUpstreamAdmission["observation"]["tls"];
}): Promise<StoredGatewayUpstreamAdmission> {
  if (!reportSigningKey || !reportSigningScheme) {
    throw new GatewayUpstreamAdmissionError(503, "gateway_observation_signing_unavailable", "gateway report signing is required");
  }
  const nonceKey = `${input.request.runtimeSigner.toLowerCase()}:${input.request.intentId}:${input.request.nonce}`;
  pruneUpstreamAdmissionNonces();
  if (upstreamAdmissionNonces.has(nonceKey)) {
    throw new GatewayUpstreamAdmissionError(409, "nonce_replay", "upstream admission nonce has already been used");
  }
  const now = new Date();
  const expiresAt = new Date(Math.min(
    now.getTime() + upstreamAdmissionTtlSeconds * 1000,
    Number(input.request.deadline) * 1000
  )).toISOString();
  const unsignedObservation = {
    version: 1 as const,
    kind: "switchboard.gateway-upstream-observation" as const,
    request: input.request,
    requestDigest: input.requestDigest,
    observedIp: input.observedIp,
    ...(input.observedPort === undefined ? {} : { observedPort: input.observedPort }),
    observedAt: now.toISOString(),
    expiresAt,
    tls: input.tls
  };
  const observation = {
    ...unsignedObservation,
    admissionId: gatewayUpstreamAdmissionId(unsignedObservation)
  };
  const signature = await signReportPayload(reportSigningKey, GATEWAY_UPSTREAM_OBSERVATION_DOMAIN, observation, {
    scheme: reportSigningScheme,
    ss58Format: reportSigningSs58Format
  });
  const admission: StoredGatewayUpstreamAdmission = {
    observation,
    signature,
    requestSignature: input.requestSignature
  };
  upstreamAdmissions.set(observation.admissionId, admission);
  upstreamAdmissionNonces.set(nonceKey, Date.parse(expiresAt));
  return admission;
}

function parseGatewayUpstreamAdmissionPayload(input: unknown): GatewayUpstreamAdmissionPayload {
  const record = objectRecord(input, "upstream admission payload");
  return {
    intentId: stringField(record, "intentId"),
    sessionId: stringField(record, "sessionId"),
    runtimeSigner: stringField(record, "runtimeSigner"),
    operatorId: stringField(record, "operatorId"),
    gatewayId: stringField(record, "gatewayId"),
    processorId: stringField(record, "processorId"),
    hostname: stringField(record, "hostname"),
    validationHostname: optionalStringRecordField(record, "validationHostname"),
    upstreamPort: numberRecordField(record, "upstreamPort"),
    nonce: stringField(record, "nonce"),
    deadline: stringField(record, "deadline")
  };
}

async function legacyRouteIntentUpsert(authorization: string | undefined, body: unknown, reply: any) {
  if (!routeIntentAuthorized(authorization)) {
    return reply.code(401).send({ error: "unauthorized" });
  }
  const parsedRoute = normalizeRouteIntent(body as Parameters<typeof normalizeRouteIntent>[0]);
  const route = routeWithGatewayUpstreamAdmission(parsedRoute);
  if (!route) {
    return reply.code(409).send({ error: "gateway_upstream_admission_required" });
  }
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

if (proofIngressEnabled) {
  setInterval(() => {
    void publishProofIngressObservations();
  }, proofIngressObservationIntervalMs).unref();
  void publishProofIngressObservations();
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

async function proofIngressConnection(): Promise<ApiPromise> {
  if (proofIngressApi && proofIngressApi.isConnected) {
    return proofIngressApi;
  }
  if (!proofIngressConnecting) {
    proofIngressConnecting = connectParachain(proofIngressWsUrl!)
      .then((api) => {
        proofIngressApi = api;
        return api;
      })
      .finally(() => {
        proofIngressConnecting = null;
      });
  }
  return proofIngressConnecting;
}

async function publishProofIngressObservations(): Promise<void> {
  try {
    const observations = deriveGatewayObservations([...routes.values()], proofIngressGatewayId!);
    if (observations.length === 0) {
      return;
    }
    const api = await proofIngressConnection();
    const result = await publishGatewayObservations({
      api,
      signingKey: reportSigningKey!,
      ss58Format: reportSigningSs58Format,
      gatewayId: proofIngressGatewayId!,
      observations,
      batchMax: proofIngressObservationBatchMax,
      verifyBindings: proofIngressVerifyBindings
    });
    if (result.submitted > 0) {
      app.log.info(
        { gatewayId: proofIngressGatewayId, submitted: result.submitted, batches: result.batches },
        "gateway observations submitted to parachain"
      );
    }
  } catch (error) {
    app.log.warn(
      { error: error instanceof Error ? error.message : String(error) },
      "gateway observation submission failed"
    );
  }
}

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
  const report: GatewayCapabilityReport = {
    version: 1,
    kind: "switchboard.operator.capability",
    reportId: gatewayCapabilityReportId({ gatewayId, reportedAt: now, configVersion }),
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
      activeRouteCount: activeRoutes().length,
      routeCapacity,
      processorDiscoveryFresh: managerInventoryFresh(),
      reportedProcessorCount: reportedProcessorCount(),
      softwareVersion: process.env.PROOF_OPERATOR_SOFTWARE_VERSION,
      supportedClasses,
      upstreamAdmissionModes: ["direct-post", "relay-pull"],
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
  expireStaleManagerInventoryRefresh();
  const stale = managerInventoryRefreshedAt
    ? Date.now() - Date.parse(managerInventoryRefreshedAt) >= processorDiscoveryIntervalMs
    : true;
  if (managerInventories.size > 0 && !stale) {
    return;
  }
  await refreshManagerInventories();
}

async function refreshManagerInventories(): Promise<void> {
  if (!processorDiscoveryEnabled || advertisedManagerIds.length === 0) {
    return;
  }
  expireStaleManagerInventoryRefresh();
  if (managerInventoryRefresh) {
    await managerInventoryRefresh.promise;
    return;
  }

  const generation = managerInventoryRefreshGeneration + 1;
  managerInventoryRefreshGeneration = generation;
  const startedAtMs = Date.now();
  const refresh = {
    generation,
    startedAtMs,
    startedAt: new Date(startedAtMs).toISOString(),
    promise: runManagerInventoryRefreshWithTimeout(generation)
  };
  refresh.promise = refresh.promise.finally(() => {
    if (managerInventoryRefresh?.generation === generation) {
      managerInventoryRefresh = undefined;
    }
  });
  managerInventoryRefresh = refresh;
  await refresh.promise;
}

async function runManagerInventoryRefreshWithTimeout(generation: number): Promise<void> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<void>((_, reject) => {
    timeout = setTimeout(() => {
      reject(new Error(`manager processor inventory refresh exceeded ${processorDiscoveryTimeoutMs}ms`));
    }, processorDiscoveryTimeoutMs);
    timeout.unref();
  });
  try {
    await Promise.race([doRefreshManagerInventories(generation), timeoutPromise]);
  } catch (error) {
    if (!managerInventoryRefreshGenerationCurrent(generation)) {
      return;
    }
    managerInventoryRefreshGeneration += 1;
    managerInventoryError = error instanceof Error ? error.message : String(error);
    managerInventoryRefreshTimedOutCount += 1;
    app.log.warn(
      {
        generation,
        error: managerInventoryError,
        timeoutMs: processorDiscoveryTimeoutMs
      },
      "manager processor inventory refresh timed out"
    );
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

async function doRefreshManagerInventories(generation: number): Promise<void> {
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
    if (!managerInventoryRefreshGenerationCurrent(generation)) {
      return;
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
    if (!managerInventoryRefreshGenerationCurrent(generation)) {
      return;
    }
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

function expireStaleManagerInventoryRefresh(nowMs = Date.now()): void {
  if (!managerInventoryRefresh) {
    return;
  }
  const ageMs = nowMs - managerInventoryRefresh.startedAtMs;
  if (ageMs <= processorDiscoveryTimeoutMs) {
    return;
  }
  const staleGeneration = managerInventoryRefresh.generation;
  managerInventoryRefresh = undefined;
  managerInventoryRefreshGeneration += 1;
  managerInventoryError = `manager processor inventory refresh generation ${staleGeneration} exceeded ${processorDiscoveryTimeoutMs}ms`;
  managerInventoryRefreshTimedOutCount += 1;
  app.log.warn(
    {
      generation: staleGeneration,
      ageMs,
      timeoutMs: processorDiscoveryTimeoutMs
    },
    "manager processor inventory refresh expired stale generation"
  );
}

function managerInventoryRefreshGenerationCurrent(generation: number): boolean {
  return generation === managerInventoryRefreshGeneration;
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
  const refreshedAtMs = managerInventoryRefreshedAt ? Date.parse(managerInventoryRefreshedAt) : undefined;
  const fresh = managerInventoryFresh();
  const refresh = managerInventoryRefresh;
  const nowMs = Date.now();
  return {
    enabled: processorDiscoveryEnabled,
    network: acurastNetwork,
    rpcUrl: processorDiscoveryEnabled ? rpcForAcurastNetwork(acurastNetwork, acurastRpcUrl) : undefined,
    managerIds: advertisedManagerIds,
    fresh,
    maxAgeSeconds: processorDiscoveryMaxAgeSeconds,
    intervalMs: processorDiscoveryIntervalMs,
    checkAvailability: processorDiscoveryAvailability,
    startDelayMs: processorDiscoveryStartDelayMs,
    durationMs: processorDiscoveryDurationMs,
    timeoutMs: processorDiscoveryTimeoutMs,
    limit: processorDiscoveryLimit,
    includeProcessors: advertisedProcessors,
    excludeProcessors: excludedProcessors,
    refreshInFlight: Boolean(refresh),
    refreshStartedAt: refresh?.startedAt,
    refreshAgeMs: refresh ? nowMs - refresh.startedAtMs : undefined,
    refreshTimedOutCount: managerInventoryRefreshTimedOutCount,
    refreshedAt: managerInventoryRefreshedAt,
    staleAfterMs: refreshedAtMs === undefined ? undefined : Math.max(0, refreshedAtMs + processorDiscoveryIntervalMs + 30_000 - nowMs),
    error: managerInventoryError,
    lastError: managerInventoryError,
    inventories: [...managerInventories.values()].map((inventory) => ({
      managerId: inventory.managerId,
      totalProcessors: inventory.totalProcessors,
      recentProcessors: inventory.recentProcessors,
      availableProcessors: inventory.availableProcessors,
      recentAvailableProcessors: inventory.recentAvailableProcessors,
      reportedProcessors: processorsForManagerScope(inventory.managerId)?.length ?? 0,
      availabilityWindow: inventory.availabilityWindow
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
    const parsed = JSON.parse(raw) as { routes?: unknown[]; upstreamAdmissions?: unknown[] };
    for (const item of parsed.routes ?? []) {
      const route = normalizeRouteIntent(item as Parameters<typeof normalizeRouteIntent>[0]);
      routes.set(route.routeId, route);
    }
    for (const item of parsed.upstreamAdmissions ?? []) {
      const admission = item as StoredGatewayUpstreamAdmission;
      if (admission?.observation?.admissionId && Date.parse(admission.observation.expiresAt) > Date.now()) {
        upstreamAdmissions.set(admission.observation.admissionId, admission);
      }
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
    const acceptedUpstreamAdmissionCount = Array.isArray(state.acceptedUpstreamAdmissions) ? state.acceptedUpstreamAdmissions.length : 0;
    const pendingUpstreamAdmissionRequestCount = Array.isArray(state.upstreamAdmissionRequests) ? state.upstreamAdmissionRequests.length : 0;
    const hydratedAdmissionCount = await hydrateAcceptedUpstreamAdmissions(state);
    const processedUpstreamAdmissionRequestCount = await processPulledUpstreamAdmissionRequests(state);
    if (!routeStateGenerationCurrent(generation)) {
      return;
    }
    const polledRoutes = desiredRoutesFromRouteState(state);
    const desiredRoutes = routesWithRemovalGrace(polledRoutes, Date.now());
    const beforeIds = [...routes.keys()].sort();
    const afterIds = [...desiredRoutes.keys()].sort();
    const removedIds = beforeIds.filter((routeId) => !desiredRoutes.has(routeId));
    const completedAt = new Date().toISOString();
    const admissionCacheChanged = hydratedAdmissionCount > 0 || processedUpstreamAdmissionRequestCount > 0;
    if (!routeMapsEqual(routes, desiredRoutes) || admissionCacheChanged) {
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
        pendingUpstreamAdmissionRequestCount,
        acceptedUpstreamAdmissionCount,
        processedUpstreamAdmissionRequestCount,
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
      pendingUpstreamAdmissionRequestCount,
      acceptedUpstreamAdmissionCount,
      processedUpstreamAdmissionRequestCount,
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

async function hydrateAcceptedUpstreamAdmissions(input: Record<string, unknown>): Promise<number> {
  if (!Array.isArray(input.acceptedUpstreamAdmissions)) {
    return 0;
  }
  let hydrated = 0;
  for (const item of input.acceptedUpstreamAdmissions) {
    try {
      const admission = await parseAcceptedUpstreamAdmission(item);
      if (!gatewayUpstreamAdmissionMatchesThisGateway(admission.observation.request)) {
        continue;
      }
      if (Date.parse(admission.observation.expiresAt) <= Date.now()) {
        continue;
      }
      if (upstreamAdmissions.has(admission.observation.admissionId)) {
        continue;
      }
      upstreamAdmissions.set(admission.observation.admissionId, admission);
      hydrated += 1;
    } catch (error) {
      app.log.warn(
        { error: error instanceof Error ? error.message : String(error) },
        "gateway ignored invalid accepted upstream admission from route state"
      );
    }
  }
  return hydrated;
}

async function processPulledUpstreamAdmissionRequests(input: Record<string, unknown>): Promise<number> {
  if (!Array.isArray(input.upstreamAdmissionRequests)) {
    return 0;
  }
  let processed = 0;
  for (const item of input.upstreamAdmissionRequests) {
    let pulled: PulledGatewayUpstreamAdmissionRequest;
    try {
      pulled = parsePulledUpstreamAdmissionRequest(item);
    } catch (error) {
      app.log.warn(
        { error: error instanceof Error ? error.message : String(error) },
        "gateway ignored invalid upstream admission request from route state"
      );
      continue;
    }
    if (!gatewayUpstreamAdmissionMatchesThisGateway(pulled.request)) {
      continue;
    }
    if (Number(pulled.request.deadline) <= Math.floor(Date.now() / 1000)) {
      continue;
    }
    const existing = freshUpstreamAdmissionForRequestDigest(pulled.requestDigest);
    if (existing) {
      try {
        await submitGatewayPulledUpstreamAdmission(existing);
        processed += 1;
      } catch (error) {
        app.log.warn(
          {
            requestDigest: pulled.requestDigest,
            error: error instanceof Error ? error.message : String(error)
          },
          "gateway failed to resubmit cached upstream admission"
        );
      }
      continue;
    }

    const candidateIps = pulled.candidateUpstreamIps.filter((candidateIp) => observedIpAllowed(candidateIp));
    if (candidateIps.length === 0) {
      app.log.warn(
        { requestDigest: pulled.requestDigest, candidateUpstreamIps: pulled.candidateUpstreamIps },
        "gateway upstream admission request had no allowed candidate IPs"
      );
      continue;
    }
    for (const candidateIp of candidateIps) {
      try {
        const admission = await admitPulledGatewayUpstream(pulled, candidateIp);
        await submitGatewayPulledUpstreamAdmission(admission);
        processed += 1;
        app.log.info(
          {
            admissionId: admission.observation.admissionId,
            requestDigest: pulled.requestDigest,
            observedIp: admission.observation.observedIp,
            upstreamPort: pulled.request.upstreamPort
          },
          "gateway pulled upstream admission accepted"
        );
        break;
      } catch (error) {
        app.log.warn(
          {
            requestDigest: pulled.requestDigest,
            candidateIp,
            error: error instanceof Error ? error.message : String(error)
          },
          "gateway upstream admission candidate failed"
        );
      }
    }
  }
  return processed;
}

async function parseAcceptedUpstreamAdmission(input: unknown): Promise<StoredGatewayUpstreamAdmission> {
  const record = objectRecord(input, "accepted upstream admission");
  const request = normalizeGatewayUpstreamAdmissionPayload(parseGatewayUpstreamAdmissionPayload(record.request));
  const requestDigest = gatewayUpstreamAdmissionDigest(request);
  const requestSignature = normalizeSecp256k1SignatureForDigest(
    stringField(record, "requestSignature"),
    requestDigest,
    request.runtimeSigner
  );
  const observation = normalizeGatewayUpstreamObservationPayload(
    objectRecord(record.observation, "upstream admission observation") as unknown as SignedGatewayUpstreamObservation["observation"]
  );
  if (observation.requestDigest.toLowerCase() !== requestDigest.toLowerCase()) {
    throw new Error("accepted upstream admission request digest mismatch");
  }
  if (JSON.stringify(observation.request) !== JSON.stringify(request)) {
    throw new Error("accepted upstream admission request mismatch");
  }
  const signature = objectRecord(record.observationSignature, "upstream admission observation signature") as SignedGatewayUpstreamObservation["signature"];
  if (signature.domain !== GATEWAY_UPSTREAM_OBSERVATION_DOMAIN) {
    throw new Error(`accepted upstream admission signature domain mismatch: ${signature.domain}`);
  }
  await verifyReportSignature(observation, signature);
  return {
    requestSignature,
    observation,
    signature
  };
}

function parsePulledUpstreamAdmissionRequest(input: unknown): PulledGatewayUpstreamAdmissionRequest {
  const record = objectRecord(input, "upstream admission request");
  const request = normalizeGatewayUpstreamAdmissionPayload(parseGatewayUpstreamAdmissionPayload(record.request));
  const requestDigest = stringField(record, "requestDigest");
  const actualDigest = gatewayUpstreamAdmissionDigest(request);
  if (requestDigest.toLowerCase() !== actualDigest.toLowerCase()) {
    throw new Error("upstream admission request digest mismatch");
  }
  const requestSignature = normalizeSecp256k1SignatureForDigest(
    stringField(record, "requestSignature"),
    actualDigest,
    request.runtimeSigner
  );
  return {
    requestDigest: actualDigest,
    request,
    requestSignature,
    candidateUpstreamIps: normalizeCandidateUpstreamIps(record.candidateUpstreamIps)
  };
}

async function admitPulledGatewayUpstream(
  pulled: PulledGatewayUpstreamAdmissionRequest,
  observedIp: string
): Promise<StoredGatewayUpstreamAdmission> {
  if (!observedIpAllowed(observedIp)) {
    throw new GatewayUpstreamAdmissionError(403, "observed_ip_not_allowed", `observed upstream IP ${observedIp} is not allowed`);
  }
  const tlsResult = await verifyUpstreamTls(pulled.request, observedIp);
  await verifyRuntimeUpstreamProbe(pulled.request, pulled.requestDigest, observedIp);
  return signAndStoreGatewayUpstreamAdmission({
    request: pulled.request,
    requestDigest: pulled.requestDigest,
    requestSignature: pulled.requestSignature,
    observedIp,
    tls: tlsResult
  });
}

async function submitGatewayPulledUpstreamAdmission(admission: StoredGatewayUpstreamAdmission): Promise<void> {
  if (!routeStateUrl || !operatorId || !gatewayId) {
    throw new Error("route-state relay endpoint is unavailable");
  }
  const submitUrl = new URL(
    `/v1/operators/${encodeURIComponent(operatorId.toLowerCase())}/gateways/${encodeURIComponent(gatewayId)}/upstream-admissions`,
    routeStateUrl
  );
  const response = await fetch(submitUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(routeStateToken ? { authorization: `Bearer ${routeStateToken}` } : {})
    },
    body: JSON.stringify({
      request: admission.observation.request,
      requestSignature: admission.requestSignature,
      observation: admission.observation,
      observationSignature: admission.signature
    })
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`upstream admission submit failed: ${response.status} ${body}`);
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
    const admittedRoute = routeWithGatewayUpstreamAdmission(route);
    if (!admittedRoute) {
      continue;
    }
    desired.set(admittedRoute.routeId, admittedRoute);
  }
  return desired;
}

function routeWithGatewayUpstreamAdmission(route: RouteIntent): RouteIntent | undefined {
  const source = route.source && typeof route.source === "object" && !Array.isArray(route.source)
    ? route.source as Record<string, unknown>
    : {};
  if (source.mode !== "deployment-intent-route-reconciler") {
    return route;
  }
  const admissionId = typeof source.upstreamAdmissionId === "string" ? source.upstreamAdmissionId : undefined;
  if (!admissionId) {
    return undefined;
  }
  const admission = upstreamAdmissions.get(admissionId);
  if (!admission || Date.parse(admission.observation.expiresAt) <= Date.now()) {
    upstreamAdmissions.delete(admissionId);
    return undefined;
  }
  const request = admission.observation.request;
  if (
    request.sessionId.toLowerCase() !== route.sessionId.toLowerCase() ||
    request.gatewayId !== gatewayId ||
    request.operatorId.toLowerCase() !== String(operatorId).toLowerCase() ||
    request.upstreamPort !== route.upstreamPort
  ) {
    return undefined;
  }
  return normalizeRouteIntent({
    ...route,
    upstreamHost: admission.observation.observedIp,
    source: {
      ...source,
      gatewayObservedIp: admission.observation.observedIp,
      gatewayObservedAt: admission.observation.observedAt
    }
  });
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
        routes: [...routes.values()],
        upstreamAdmissions: freshUpstreamAdmissions()
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

function freshUpstreamAdmissions(nowMs = Date.now()): StoredGatewayUpstreamAdmission[] {
  const fresh = [];
  for (const [admissionId, admission] of upstreamAdmissions.entries()) {
    if (Date.parse(admission.observation.expiresAt) <= nowMs) {
      upstreamAdmissions.delete(admissionId);
      continue;
    }
    fresh.push(admission);
  }
  return fresh;
}

function freshUpstreamAdmissionForRequestDigest(requestDigest: string, nowMs = Date.now()): StoredGatewayUpstreamAdmission | undefined {
  const normalizedDigest = requestDigest.toLowerCase();
  return freshUpstreamAdmissions(nowMs).find((admission) =>
    admission.observation.requestDigest.toLowerCase() === normalizedDigest
  );
}

function pruneUpstreamAdmissionNonces(nowMs = Date.now()): void {
  for (const [nonceKey, expiresAtMs] of upstreamAdmissionNonces.entries()) {
    if (expiresAtMs <= nowMs) {
      upstreamAdmissionNonces.delete(nonceKey);
    }
  }
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

function normalizeObservedIp(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.startsWith("::ffff:") ? value.slice("::ffff:".length) : value;
  return isIP(normalized) === 4 ? normalized : undefined;
}

function gatewayUpstreamAdmissionMatchesThisGateway(request: GatewayUpstreamAdmissionPayload): boolean {
  return Boolean(
    operatorId &&
    gatewayId &&
    request.operatorId.toLowerCase() === operatorId.toLowerCase() &&
    request.gatewayId === gatewayId
  );
}

function observedIpAllowed(value: string): boolean {
  if (upstreamAdmissionAllowedCidrs.length > 0) {
    return upstreamAdmissionAllowedCidrs.some((cidr) => ipv4InCidr(value, cidr));
  }
  return publicIpv4Address(value) || privateIpv4Address(value);
}

function privateIpv4Address(value: string): boolean {
  const octets = ipv4Octets(value);
  if (!octets) return false;
  const [a, b] = octets;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function publicIpv4Address(value: string): boolean {
  const octets = ipv4Octets(value);
  if (!octets) return false;
  const [a, b, c, d] = octets;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false;
  if (a === 255 && b === 255 && c === 255 && d === 255) return false;
  return true;
}

function ipv4InCidr(value: string, cidr: string): boolean {
  const [range, rawPrefix] = cidr.split("/");
  const prefix = rawPrefix === undefined ? 32 : Number(rawPrefix);
  const ip = ipv4ToUint32(value);
  const base = ipv4ToUint32(range);
  if (ip === undefined || base === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ip & mask) === (base & mask);
}

function ipv4ToUint32(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const octets = ipv4Octets(value);
  if (!octets) return undefined;
  return (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
}

function ipv4Octets(value: string): [number, number, number, number] | undefined {
  if (isIP(value) !== 4) return undefined;
  const octets = value.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return undefined;
  }
  return octets as [number, number, number, number];
}

async function verifyRuntimeUpstreamProbe(
  request: GatewayUpstreamAdmissionPayload,
  requestDigest: string,
  observedIp: string
): Promise<void> {
  const gatewayNonce = randomBytes(16).toString("hex");
  const responseBody = objectRecord(
    await postRuntimeUpstreamProbe(request, requestDigest, gatewayNonce, observedIp),
    "upstream admission probe response"
  );
  if (responseBody.ok !== true) {
    throw new GatewayUpstreamAdmissionError(
      422,
      "upstream_probe_rejected",
      typeof responseBody.error === "string" ? responseBody.error : "runtime rejected upstream probe"
    );
  }
  const probe = normalizeGatewayUpstreamProbeResponsePayload(
    objectRecord(responseBody.probe, "upstream admission probe payload") as unknown as Parameters<typeof normalizeGatewayUpstreamProbeResponsePayload>[0]
  );
  const signature = stringField(responseBody, "signature");
  if (probe.requestDigest.toLowerCase() !== requestDigest.toLowerCase()) {
    throw new GatewayUpstreamAdmissionError(422, "upstream_probe_digest_mismatch", "runtime probe requestDigest mismatch");
  }
  if (probe.gatewayNonce !== gatewayNonce) {
    throw new GatewayUpstreamAdmissionError(422, "upstream_probe_nonce_mismatch", "runtime probe nonce mismatch");
  }
  if (probe.intentId !== request.intentId || probe.sessionId.toLowerCase() !== request.sessionId.toLowerCase()) {
    throw new GatewayUpstreamAdmissionError(422, "upstream_probe_context_mismatch", "runtime probe context mismatch");
  }
  if (probe.upstreamPort !== request.upstreamPort) {
    throw new GatewayUpstreamAdmissionError(422, "upstream_probe_port_mismatch", "runtime probe upstreamPort mismatch");
  }
  const signer = recoverGatewayUpstreamProbeResponseSigner(probe, signature);
  if (signer.toLowerCase() !== request.runtimeSigner.toLowerCase()) {
    throw new GatewayUpstreamAdmissionError(422, "upstream_probe_signature_mismatch", "runtime probe signature signer mismatch");
  }
}

async function postRuntimeUpstreamProbe(
  request: GatewayUpstreamAdmissionPayload,
  requestDigest: string,
  gatewayNonce: string,
  observedIp: string
): Promise<unknown> {
  const ca = upstreamAdmissionCaFile ? await fs.readFile(upstreamAdmissionCaFile, "utf8") : undefined;
  const servername = request.validationHostname ?? request.hostname;
  const payload = JSON.stringify({
    request,
    requestDigest,
    gatewayNonce
  });
  return new Promise((resolve, reject) => {
    const probeRequest = https.request({
      hostname: observedIp,
      port: request.upstreamPort,
      method: "POST",
      path: SWITCHBOARD_UPSTREAM_ADMISSION_PATH,
      servername,
      ca,
      rejectUnauthorized: upstreamAdmissionTlsProbeEnabled,
      timeout: upstreamAdmissionTlsProbeTimeoutMs,
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload).toString(),
        host: servername
      }
    }, (response) => {
      let raw = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        raw += chunk;
        if (raw.length > 64_000) {
          probeRequest.destroy(new Error("upstream probe response exceeded 64KB"));
        }
      });
      response.on("end", () => {
        if ((response.statusCode ?? 0) < 200 || (response.statusCode ?? 0) >= 300) {
          reject(new GatewayUpstreamAdmissionError(422, "upstream_probe_failed", `runtime probe failed: ${response.statusCode} ${raw}`));
          return;
        }
        try {
          resolve(JSON.parse(raw));
        } catch (error) {
          reject(new GatewayUpstreamAdmissionError(
            422,
            "upstream_probe_invalid_json",
            error instanceof Error ? error.message : String(error)
          ));
        }
      });
    });
    probeRequest.once("timeout", () => {
      probeRequest.destroy(new GatewayUpstreamAdmissionError(504, "upstream_probe_timeout", "runtime upstream probe timed out"));
    });
    probeRequest.once("error", (error) => {
      reject(error instanceof GatewayUpstreamAdmissionError
        ? error
        : new GatewayUpstreamAdmissionError(422, "upstream_probe_failed", error.message));
    });
    probeRequest.write(payload);
    probeRequest.end();
  });
}

async function verifyUpstreamTls(
  request: GatewayUpstreamAdmissionPayload,
  observedIp: string
): Promise<StoredGatewayUpstreamAdmission["observation"]["tls"]> {
  const servername = request.validationHostname ?? request.hostname;
  if (!upstreamAdmissionTlsProbeEnabled) {
    return { verified: false, servername, skipped: true };
  }
  const ca = upstreamAdmissionCaFile ? await fs.readFile(upstreamAdmissionCaFile, "utf8") : undefined;
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: observedIp,
      port: request.upstreamPort,
      servername,
      ca,
      rejectUnauthorized: true,
      timeout: upstreamAdmissionTlsProbeTimeoutMs
    });
    socket.once("secureConnect", () => {
      const authorizationError = socket.authorizationError ? String(socket.authorizationError) : undefined;
      const verified = socket.authorized === true;
      socket.destroy();
      if (!verified) {
        reject(new GatewayUpstreamAdmissionError(422, "upstream_tls_unverified", authorizationError ?? "upstream TLS was not authorized"));
        return;
      }
      resolve({ verified, servername });
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new GatewayUpstreamAdmissionError(504, "upstream_tls_probe_timeout", "upstream TLS probe timed out"));
    });
    socket.once("error", (error) => {
      reject(new GatewayUpstreamAdmissionError(422, "upstream_tls_probe_failed", error.message));
    });
  });
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

function optionalStringRecordField(input: Record<string, unknown>, name: string): string | undefined {
  const value = input[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberRecordField(input: Record<string, unknown>, name: string): number {
  const value = input[name];
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error(`${name} must be an integer`);
  }
  return value;
}

function normalizeCandidateUpstreamIps(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return uniqueStrings(
    input
      .filter((value): value is string => typeof value === "string")
      .map((value) => value.trim())
      .filter((value) => isIP(value) === 4)
  );
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
