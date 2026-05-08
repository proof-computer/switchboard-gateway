import { promises as fs } from "node:fs";
import path from "node:path";

import { ethers } from "ethers";
import { z } from "zod";

import { INGRESS_REGISTRY_NATIVE_PAYMENT_ABI } from "./ingress-contract.js";
import { discoverRegistryWatchTargets, fallbackResult, type RegistryDiscoveryResult, type RegistryWatchTarget } from "./registry-discovery.js";
import { hostnameRoleSchema, normalizeRouteIntent, type RouteIntentInput } from "./route-intent.js";

const routeMetadataSchema = z.object({
  sessionId: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  hostname: z.string().min(1),
  publicHostname: z.string().min(1).optional(),
  validationHostname: z.string().min(1).optional(),
  customerHostnames: z.array(z.string().min(1)).optional(),
  hostnameRole: hostnameRoleSchema.optional(),
  upstreamHost: z.string().min(1),
  upstreamPort: z.number().int().min(1).max(65535),
  routeId: z.string().min(1).optional()
});

type RouteMetadata = z.output<typeof routeMetadataSchema>;

interface WatcherState {
  lastProcessedBlock?: number;
  registries?: Record<string, { lastProcessedBlock: number }>;
}

const rpcUrl = requiredEnv("HUB_ETH_RPC_URL", process.env.POLKADOT_HUB_RPC_URL);
const fallbackRegistryAddress = ethers.getAddress(requiredEnv("INGRESS_REGISTRY_ADDRESS", process.env.INGRESS_CONTRACT_ADDRESS));
const operatorId = optionalLowerHex(process.env.OPERATOR_ID);
const startBlock = numberEnv("HUB_WATCH_START_BLOCK", 0);
const confirmations = numberEnv("HUB_CONFIRMATIONS", 12);
const pollIntervalMs = numberEnv("HUB_POLL_INTERVAL_MS", 5_000);
const maxBlockRange = numberEnv("HUB_WATCH_MAX_BLOCK_RANGE", 1_000);
const chainProfile = process.env.HUB_CHAIN_PROFILE ?? process.env.PROOF_INGRESS_TARGET ?? "polkadot-hub";
const stateFile = process.env.HUB_WATCHER_STATE_FILE ?? "/var/lib/switchboard/hub-watcher/state.json";
const routeMetadataFile = process.env.ROUTE_METADATA_FILE ?? "/etc/switchboard/routes.json";
const routeIntentOutputUrl = process.env.ROUTE_INTENT_OUTPUT_URL ?? "http://gateway-agent:18080/route-intents";
const routeIntentOutputToken = process.env.ROUTE_INTENT_OUTPUT_TOKEN;
const manifestUrl = optionalEnv("PROOF_NETWORK_MANIFEST_URL");
const manifestSigner = optionalEnv("PROOF_NETWORK_MANIFEST_SIGNER");
const manifestAllowUnpinned = process.env.PROOF_NETWORK_MANIFEST_ALLOW_UNPINNED === "true";
const manifestRefreshMs = numberEnv("PROOF_NETWORK_MANIFEST_REFRESH_MS", 60_000);

const provider = new ethers.JsonRpcProvider(rpcUrl);
const iface = new ethers.Interface(INGRESS_REGISTRY_NATIVE_PAYMENT_ABI);
const routeMetadata = await loadRouteMetadata(routeMetadataFile);
let state = await loadState();
let cachedDiscovery: RegistryDiscoveryResult | undefined;
let cachedDiscoveryAt = 0;

console.log(
  JSON.stringify({
    level: "info",
    event: "hub-watcher-started",
    fallbackRegistryAddress,
    manifestUrl,
    manifestSignerConfigured: Boolean(manifestSigner),
    operatorId,
    startBlock,
    confirmations,
    routeMetadataCount: routeMetadata.size,
    routeIntentOutputUrl
  })
);

while (true) {
  try {
    await pollOnce();
  } catch (error) {
    console.error(
      JSON.stringify({
        level: "error",
        event: "hub-watcher-poll-failed",
        error: error instanceof Error ? error.message : String(error)
      })
    );
  }

  await sleep(pollIntervalMs);
}

async function pollOnce(): Promise<void> {
  const latestBlock = await provider.getBlockNumber();
  const targetBlock = latestBlock - confirmations;
  const discovery = await registryDiscovery();

  for (const target of discovery.targets) {
    await pollRegistry(target, targetBlock);
  }
}

async function pollRegistry(target: RegistryWatchTarget, targetBlock: number): Promise<void> {
  const registryAddress = ethers.getAddress(target.address);
  const lastProcessedBlock = lastProcessedBlockFor(registryAddress, target.fromBlock ?? startBlock);
  if (targetBlock <= lastProcessedBlock) {
    return;
  }

  const registry = new ethers.Contract(registryAddress, INGRESS_REGISTRY_NATIVE_PAYMENT_ABI, provider);
  let fromBlock = lastProcessedBlock + 1;
  while (fromBlock <= targetBlock) {
    const toBlock = Math.min(targetBlock, fromBlock + maxBlockRange - 1);
    const logs = await provider.getLogs({
      address: registryAddress,
      fromBlock,
      toBlock
    });

    for (const log of logs) {
      await processLog(log, target, registry);
    }

    state = setLastProcessedBlock(state, registryAddress, toBlock);
    await saveState(state);
    fromBlock = toBlock + 1;
  }
}

async function processLog(log: ethers.Log, target: RegistryWatchTarget, registry: ethers.Contract): Promise<void> {
  let parsed: ethers.LogDescription | null = null;
  try {
    parsed = iface.parseLog(log);
  } catch {
    return;
  }

  if (parsed == null) {
    return;
  }

  if (parsed.name === "SessionFunded" || parsed.name === "SessionFundedWithQuote") {
    console.log(
      JSON.stringify({
        level: "info",
        event: parsed.name === "SessionFundedWithQuote" ? "session-funded-with-quote-observed" : "session-funded-observed",
        sessionId: parsed.args.sessionId,
        quoteId: parsed.args.quoteId,
        policyHash: parsed.args.policyHash,
        registryAddress: target.address,
        registryStatus: target.status,
        blockNumber: log.blockNumber,
        transactionHash: log.transactionHash
      })
    );
    await postRouteForSession(target, registry, String(parsed.args.sessionId), {
      blockNumber: log.blockNumber,
      transactionHash: log.transactionHash,
      logIndex: log.index,
      trigger: parsed.name,
      quoteId: parsed.args.quoteId,
      policyHash: parsed.args.policyHash
    });
    return;
  }

  if (parsed.name !== "IngressRegistered") {
    return;
  }

  const observedOperatorId = String(parsed.args.operatorId).toLowerCase();
  if (operatorId != null && observedOperatorId !== operatorId) {
    return;
  }

  await postRouteForSession(target, registry, String(parsed.args.sessionId), {
    blockNumber: log.blockNumber,
    transactionHash: log.transactionHash,
    logIndex: log.index,
    trigger: "IngressRegistered",
    jobSigner: parsed.args.jobSigner,
    operatorId: parsed.args.operatorId,
    processorId: parsed.args.processorId
  });
}

async function postRouteForSession(
  target: RegistryWatchTarget,
  registry: ethers.Contract,
  rawSessionId: string,
  eventRef: {
    blockNumber: number;
    transactionHash: string;
    logIndex: number;
    trigger: string;
    quoteId?: unknown;
    policyHash?: unknown;
    jobSigner?: unknown;
    operatorId?: unknown;
    processorId?: unknown;
  }
): Promise<void> {
  const sessionId = rawSessionId.toLowerCase();
  const metadata = routeMetadata.get(sessionId);
  if (metadata == null) {
    console.log(
      JSON.stringify({
        level: "warn",
        event: "registration-metadata-missing",
        sessionId,
        registryAddress: target.address,
        registryStatus: target.status,
        blockNumber: eventRef.blockNumber,
        transactionHash: eventRef.transactionHash
      })
    );
    return;
  }

  const session = await registry.getSession(sessionId);
  if (!session.registered) {
    return;
  }

  const sessionOperatorId = String(session.operatorId).toLowerCase();
  if (operatorId != null && sessionOperatorId !== operatorId) {
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const activeExpiresAt = Number(session.expiresAt);
  const activationDeadline = Number(session.activationDeadline ?? 0);
  const expiresAt = activeExpiresAt > now ? activeExpiresAt : activationDeadline;
  if (expiresAt <= now) {
    console.log(
      JSON.stringify({
        level: "warn",
        event: "registration-not-routeable-before-expiry",
        sessionId,
        registryAddress: target.address,
        registryStatus: target.status,
        expiresAt: activeExpiresAt,
        activationDeadline,
        blockNumber: eventRef.blockNumber,
        transactionHash: eventRef.transactionHash
      })
    );
    return;
  }

  const route = normalizeRouteIntent({
    routeId: metadata.routeId ?? sessionId,
    sessionId,
    hostname: metadata.hostname,
    publicHostname: metadata.publicHostname,
    validationHostname: metadata.validationHostname,
    customerHostnames: metadata.customerHostnames,
    hostnameRole: metadata.hostnameRole,
    upstreamHost: metadata.upstreamHost,
    upstreamPort: metadata.upstreamPort,
    expiresAt,
    source: {
      chain: target.chainName ?? chainProfile,
      chainId: target.chainId,
      contractAddress: ethers.getAddress(target.address),
      registryStatus: target.status,
      manifestSequence: target.manifestSequence,
      blockNumber: eventRef.blockNumber,
      transactionHash: eventRef.transactionHash,
      logIndex: eventRef.logIndex,
      trigger: eventRef.trigger,
      quoteId: eventRef.quoteId ?? session.quoteId,
      policyHash: eventRef.policyHash ?? session.policyHash,
      serviceAmount: session.serviceAmount?.toString(),
      setupFee: session.setupFee?.toString(),
      validationFeeCap: session.validationFeeCap?.toString(),
      amountPaid: session.amountPaid?.toString(),
      paidSeconds: session.paidSeconds?.toString(),
      jobSigner: eventRef.jobSigner ?? session.expectedJobSigner,
      operatorId: eventRef.operatorId ?? session.operatorId,
      processorId: eventRef.processorId ?? session.processorId
    }
  } satisfies RouteIntentInput);

  await postRouteIntent(route);
  console.log(
    JSON.stringify({
      level: "info",
      event: "route-intent-posted",
      sessionId,
      hostname: route.hostname,
      publicHostname: route.publicHostname,
      validationHostname: route.validationHostname,
      registryAddress: target.address,
      registryStatus: target.status,
      upstream: `${route.upstreamHost}:${route.upstreamPort}`,
      expiresAt,
      blockNumber: eventRef.blockNumber,
      transactionHash: eventRef.transactionHash,
      trigger: eventRef.trigger
    })
  );
}

async function postRouteIntent(route: RouteIntentInput): Promise<void> {
  const response = await fetch(routeIntentOutputUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(routeIntentOutputToken ? { authorization: `Bearer ${routeIntentOutputToken}` } : {})
    },
    body: JSON.stringify(route)
  });

  if (!response.ok) {
    throw new Error(`route intent post failed: ${response.status} ${await response.text()}`);
  }
}

async function loadRouteMetadata(filePath: string): Promise<Map<string, RouteMetadata>> {
  const raw = await fs.readFile(filePath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  const routes = Array.isArray(parsed) ? parsed : (parsed as { routes?: unknown[] }).routes ?? [];
  const result = new Map<string, RouteMetadata>();

  for (const item of routes) {
    const route = routeMetadataSchema.parse(item);
    result.set(route.sessionId.toLowerCase(), route);
  }

  return result;
}

async function loadState(): Promise<WatcherState> {
  try {
    const raw = await fs.readFile(stateFile, "utf8");
    const parsed = JSON.parse(raw) as WatcherState;
    return {
      lastProcessedBlock: parsed.lastProcessedBlock,
      registries: parsed.registries
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }

    return { registries: {} };
  }
}

async function saveState(nextState: WatcherState): Promise<void> {
  await fs.mkdir(path.dirname(stateFile), { recursive: true });
  await fs.writeFile(stateFile, `${JSON.stringify(nextState, null, 2)}\n`);
}

function requiredEnv(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (value == null || value === "") {
    throw new Error(`${name} is required`);
  }

  return value;
}

function optionalEnv(name: string): string | undefined {
  const value = process.env[name];
  return value && value.length > 0 ? value : undefined;
}

function optionalLowerHex(value: string | undefined): string | undefined {
  if (value == null || value === "") {
    return undefined;
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("OPERATOR_ID must be a bytes32 hex string");
  }

  return value.toLowerCase();
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

async function registryDiscovery(): Promise<RegistryDiscoveryResult> {
  const now = Date.now();
  if (cachedDiscovery && now - cachedDiscoveryAt < manifestRefreshMs) {
    return cachedDiscovery;
  }

  try {
    cachedDiscovery = await discoverRegistryWatchTargets({
      fallbackRegistryAddress,
      manifestUrl,
      expectedManifestSigner: manifestSigner,
      allowUnpinnedManifestSigner: manifestAllowUnpinned,
      expectedChainId: process.env.HUB_CHAIN_ID ?? process.env.CHAIN_ID
    });
    cachedDiscoveryAt = now;
    console.log(
      JSON.stringify({
        level: "info",
        event: "registry-discovery-updated",
        source: cachedDiscovery.source,
        manifestSequence: cachedDiscovery.manifest?.sequence,
        manifestSigner: cachedDiscovery.signer,
        targets: cachedDiscovery.targets.map((target) => ({
          address: target.address,
          status: target.status,
          fromBlock: target.fromBlock
        }))
      })
    );
    return cachedDiscovery;
  } catch (error) {
    const fallback = cachedDiscovery ?? fallbackResult(fallbackRegistryAddress);
    cachedDiscovery = fallback;
    cachedDiscoveryAt = now;
    console.error(
      JSON.stringify({
        level: "warn",
        event: "registry-discovery-fallback",
        error: error instanceof Error ? error.message : String(error),
        targets: fallback.targets.map((target) => ({
          address: target.address,
          status: target.status
        }))
      })
    );
    return fallback;
  }
}

function lastProcessedBlockFor(registryAddress: string, registryStartBlock: number): number {
  const normalized = ethers.getAddress(registryAddress).toLowerCase();
  return state.registries?.[normalized]?.lastProcessedBlock ?? state.lastProcessedBlock ?? Math.max(0, registryStartBlock - 1);
}

function setLastProcessedBlock(nextState: WatcherState, registryAddress: string, lastProcessedBlock: number): WatcherState {
  const normalized = ethers.getAddress(registryAddress).toLowerCase();
  return {
    registries: {
      ...(nextState.registries ?? {}),
      [normalized]: {
        lastProcessedBlock
      }
    }
  };
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
