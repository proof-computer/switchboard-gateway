import { ApiPromise, HttpProvider, WsProvider } from "@polkadot/api";

export type AcurastNetwork = "mainnet" | "canary";

export interface ProcessorInfo {
  processor: string;
  heartbeatMs: number | null;
  heartbeatIso: string | null;
  heartbeatAgeSeconds: number | null;
  version: unknown;
  availability?: ProcessorAvailability;
}

export interface ProcessorAvailability {
  proposedStartIso: string;
  proposedEndIso: string;
  matches: number;
  conflicts: number;
  conflictingJobs: Array<{
    jobId: unknown;
    status: unknown;
    startIso: string;
    endIso: string;
  }>;
}

export interface ManagerProcessorInventory {
  network: AcurastNetwork;
  managerId: string;
  rpcUrl: string;
  chainTimestampIso: string;
  chainLagSeconds: number;
  processors: ProcessorInfo[];
  totalProcessors: number;
  recentProcessors: number;
  availableProcessors?: number;
  recentAvailableProcessors?: number;
  availabilityWindow?: {
    proposedStartIso: string;
    proposedEndIso: string;
  };
}

export interface DiscoverManagerProcessorsOptions {
  network: AcurastNetwork;
  managerId: string;
  rpcUrl?: string;
  maxAgeSeconds?: number;
  checkAvailability?: boolean;
  startDelayMs?: number;
  durationMs?: number;
  processorFilter?: (processors: string[]) => string[];
}

export interface SelectReadyProcessorsOptions {
  maxAgeSeconds: number;
  requireAvailability?: boolean;
  limit?: number;
  includeProcessors?: string[];
  excludeProcessors?: string[];
}

export type ProcessorReadinessStatus = "ready" | "offline_stale" | "schedule_conflicted";

export interface ProcessorReadiness {
  status: ProcessorReadinessStatus;
  reasons: string[];
}

export const DEFAULT_ACURAST_MAINNET_RPC = "wss://archive.mainnet.acurast.com";
export const DEFAULT_ACURAST_CANARY_RPC = "wss://canarynet-ws-1.acurast-h-server-2.papers.tech";

export async function createAcurastApi(input: { network: AcurastNetwork; rpcUrl?: string }): Promise<ApiPromise> {
  const rpcUrl = input.rpcUrl ?? rpcForAcurastNetwork(input.network);
  return ApiPromise.create({ provider: providerForAcurastRpc(rpcUrl) });
}

export async function discoverManagerProcessors(options: DiscoverManagerProcessorsOptions): Promise<ManagerProcessorInventory> {
  const rpcUrl = options.rpcUrl ?? rpcForAcurastNetwork(options.network);
  const api = await createAcurastApi({ network: options.network, rpcUrl });
  try {
    return await discoverManagerProcessorsWithApi(api, {
      ...options,
      rpcUrl
    });
  } finally {
    await api.disconnect();
  }
}

export async function discoverManagerProcessorsWithApi(
  api: ApiPromise,
  options: DiscoverManagerProcessorsOptions & { rpcUrl: string }
): Promise<ManagerProcessorInventory> {
  const maxAgeSeconds = options.maxAgeSeconds ?? 900;
  const chainTimestampMs = Number((await (api.query as any).timestamp.now()).toJSON());
  const chainTimestampIso = new Date(chainTimestampMs).toISOString();
  const chainLagSeconds = Math.floor((Date.now() - chainTimestampMs) / 1000);
  const allProcessors = await listManagerProcessors(api, options.managerId);
  const processors = options.processorFilter ? options.processorFilter(allProcessors) : allProcessors;
  const checkAvailability = options.checkAvailability ?? false;
  const proposedStartMs = chainTimestampMs + (options.startDelayMs ?? 120_000);
  const proposedEndMs = proposedStartMs + (options.durationMs ?? 300_000) + 1;

  const details = await Promise.all(
    processors.map(async (processor) => {
      const info = await processorInfo(api, processor);
      if (checkAvailability) {
        info.availability = await processorAvailability(api, processor, proposedStartMs, proposedEndMs);
      }
      return info;
    })
  );
  const ranked = rankProcessors(details, { preferAvailability: checkAvailability });
  const recent = ranked.filter(
    (processor) => processor.heartbeatAgeSeconds !== null && processor.heartbeatAgeSeconds <= maxAgeSeconds
  );
  const available = checkAvailability ? ranked.filter((processor) => processor.availability?.conflicts === 0) : undefined;
  const recentAvailable = checkAvailability
    ? recent.filter((processor) => processor.availability?.conflicts === 0)
    : undefined;

  return {
    network: options.network,
    managerId: options.managerId,
    rpcUrl: options.rpcUrl,
    chainTimestampIso,
    chainLagSeconds,
    processors: ranked,
    totalProcessors: allProcessors.length,
    recentProcessors: recent.length,
    availableProcessors: available?.length,
    recentAvailableProcessors: recentAvailable?.length,
    availabilityWindow: checkAvailability
      ? {
          proposedStartIso: new Date(proposedStartMs).toISOString(),
          proposedEndIso: new Date(proposedEndMs).toISOString()
        }
      : undefined
  };
}

export async function listManagerProcessors(api: ApiPromise, managerId: string): Promise<string[]> {
  const pallet = (api.query as any).acurastProcessorManager;
  if (!pallet?.managedProcessors) {
    throw new Error("Acurast processor manager pallet is unavailable on this network");
  }

  const entries = await pallet.managedProcessors.entries(managerId);
  return entries.map(([key]: any) => key.args[1].toString()).sort();
}

export async function processorInfo(api: ApiPromise, processor: string, nowMs = Date.now()): Promise<ProcessorInfo> {
  const pallet = (api.query as any).acurastProcessorManager;
  const heartbeatCodec = await pallet.processorHeartbeat(processor);
  const versionCodec = await pallet.processorVersion(processor);
  const heartbeatJson = heartbeatCodec.toJSON();
  const heartbeatMs = typeof heartbeatJson === "number" ? heartbeatJson : null;
  const heartbeatAgeSeconds = heartbeatMs ? Math.max(0, Math.floor((nowMs - heartbeatMs) / 1000)) : null;

  return {
    processor,
    heartbeatMs,
    heartbeatIso: heartbeatMs ? new Date(heartbeatMs).toISOString() : null,
    heartbeatAgeSeconds,
    version: versionCodec.toJSON()
  };
}

export async function processorAvailability(
  api: ApiPromise,
  processor: string,
  proposedStartMs: number,
  proposedEndMs: number
): Promise<ProcessorAvailability> {
  const marketplace = (api.query as any).acurastMarketplace;
  const acurast = (api.query as any).acurast;
  const matches = await marketplace.storedMatches.entries(processor);
  const conflictingJobs: ProcessorAvailability["conflictingJobs"] = [];

  for (const [key] of matches) {
    const jobId = key.args[1];
    const [origin, sequence] = jobId.toJSON() as [unknown, unknown];
    const registration = await acurast.storedJobRegistration(origin, sequence);
    const registrationJson = registration.toJSON() as { schedule?: { startTime?: unknown; endTime?: unknown } } | null;
    const startTime = numericCodecJson(registrationJson?.schedule?.startTime);
    const endTime = numericCodecJson(registrationJson?.schedule?.endTime);
    if (startTime === null || endTime === null) {
      continue;
    }

    if (startTime < proposedEndMs && proposedStartMs < endTime) {
      const status = await marketplace.storedJobStatus(origin, sequence);
      conflictingJobs.push({
        jobId: jobId.toJSON(),
        status: status.toJSON(),
        startIso: new Date(startTime).toISOString(),
        endIso: new Date(endTime).toISOString()
      });
    }
  }

  return {
    proposedStartIso: new Date(proposedStartMs).toISOString(),
    proposedEndIso: new Date(proposedEndMs).toISOString(),
    matches: matches.length,
    conflicts: conflictingJobs.length,
    conflictingJobs
  };
}

export function selectReadyProcessors(processors: ProcessorInfo[], options: SelectReadyProcessorsOptions): ProcessorInfo[] {
  const includeSet = new Set((options.includeProcessors ?? []).filter((item) => item.length > 0));
  const excludeSet = new Set((options.excludeProcessors ?? []).filter((item) => item.length > 0));
  const ranked = rankProcessors(processors, { preferAvailability: options.requireAvailability ?? false });
  const selected = ranked.filter((processor) => {
    if (includeSet.size > 0 && !includeSet.has(processor.processor)) {
      return false;
    }
    if (excludeSet.has(processor.processor)) {
      return false;
    }
    return classifyProcessorReadiness(processor, {
      maxAgeSeconds: options.maxAgeSeconds,
      requireAvailability: options.requireAvailability
    }).status === "ready";
  });

  return options.limit && options.limit > 0 ? selected.slice(0, options.limit) : selected;
}

export function classifyProcessorReadiness(
  processor: ProcessorInfo,
  options: { maxAgeSeconds: number; requireAvailability?: boolean }
): ProcessorReadiness {
  const reasons: string[] = [];
  if (processor.heartbeatAgeSeconds === null) {
    reasons.push("processor heartbeat is unknown");
    return {
      status: "offline_stale",
      reasons
    };
  }
  if (processor.heartbeatAgeSeconds > options.maxAgeSeconds) {
    reasons.push(`processor heartbeat is older than ${options.maxAgeSeconds}s`);
    return {
      status: "offline_stale",
      reasons
    };
  }
  if (options.requireAvailability && processor.availability && processor.availability.conflicts > 0) {
    reasons.push("processor has a conflicting Acurast schedule in the requested window");
    return {
      status: "schedule_conflicted",
      reasons
    };
  }

  reasons.push("processor heartbeat is fresh");
  if (options.requireAvailability) {
    reasons.push("processor has no conflicting Acurast schedule in the requested window");
  }
  return {
    status: "ready",
    reasons
  };
}

export function rankProcessors(
  processors: ProcessorInfo[],
  options: { preferAvailability?: boolean } = {}
): ProcessorInfo[] {
  return [...processors].sort((left, right) => {
    if (options.preferAvailability) {
      const conflictDiff = (left.availability?.conflicts ?? 0) - (right.availability?.conflicts ?? 0);
      if (conflictDiff !== 0) {
        return conflictDiff;
      }

      const matchDiff = (left.availability?.matches ?? 0) - (right.availability?.matches ?? 0);
      if (matchDiff !== 0) {
        return matchDiff;
      }
    }

    return (right.heartbeatMs ?? 0) - (left.heartbeatMs ?? 0);
  });
}

export function rpcForAcurastNetwork(network: AcurastNetwork, rpcOverride?: string): string {
  if (rpcOverride) {
    return rpcOverride;
  }
  if (network === "mainnet") {
    return process.env.ACURAST_RPC ?? DEFAULT_ACURAST_MAINNET_RPC;
  }

  return process.env.ACURAST_CANARY_RPC ?? DEFAULT_ACURAST_CANARY_RPC;
}

export function providerForAcurastRpc(rpcUrl: string): WsProvider | HttpProvider {
  return rpcUrl.startsWith("http://") || rpcUrl.startsWith("https://") ? new HttpProvider(rpcUrl) : new WsProvider(rpcUrl);
}

export function acurastNetworkFrom(value: string | undefined): AcurastNetwork {
  const network = value ?? "mainnet";
  if (network !== "mainnet" && network !== "canary") {
    throw new Error(`Unsupported Acurast network: ${network}`);
  }

  return network;
}

function numericCodecJson(value: unknown): number | null {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string" && /^[0-9]+$/.test(value)) {
    return Number(value);
  }

  return null;
}
