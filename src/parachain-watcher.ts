// PROOF Ingress parachain route watcher (read path).
//
// This is the parachain-backed replacement for `hub-watcher`: instead of
// reading route truth from the Hub EVM registry, it derives `RouteIntent`s
// from the PROOF Ingress parachain and feeds them to the gateway-agent's
// `/route-intents` endpoint. Public authority flows only through
// `promote_route_generation`: a route is rendered active only when its active
// generation is Promoted, bound to THIS gateway, and not expired.
//
// Aggregate truth is on chain (route status, generation binding, epochs); the
// serving DETAIL (hostname, upstream host/port) lives in the off-chain
// assignment document referenced by `assignment_hash`. In the local lab the
// document store is a directory the broker/harness writes to.
//
// The watcher stamps each emitted RouteIntent with the on-chain binding under
// `source.proofIngress = { routeId, generationId, gatewayId }`, which is what
// `parachain-observations` reads back to submit Serving/Stopped observations.

import { promises as fs } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import type { ApiPromise } from "@polkadot/api";
import { z } from "zod";

import { connectParachain } from "./parachain-observations.js";
import { normalizeRouteIntent, type RouteIntent, type RouteIntentInput } from "./route-intent.js";

export type RouteStatus = "Created" | "Active" | "Retired";
export type GenerationStatus = "Assigned" | "Promoted";

export interface RouteRecordView {
  status: RouteStatus;
  hostnameHash: string;
  paidUntilEpoch: number;
}

export interface RouteGenerationView {
  assignmentHash: string;
  primaryGatewayId: number;
  validFromEpoch: number;
  expiresAtEpoch: number;
  status: GenerationStatus;
}

export const assignmentDocumentSchema = z.object({
  hostname: z.string().min(1),
  upstreamHost: z.string().min(1),
  upstreamPort: z.number().int().min(1).max(65535),
  gatewayId: z.number().int().nonnegative(),
  publicHostname: z.string().optional(),
  validationHostname: z.string().optional(),
  customerHostnames: z.array(z.string()).optional()
});

export type AssignmentDocument = z.infer<typeof assignmentDocumentSchema>;

// --- Pure decoding of polkadot-js `.toJSON()` storage values ---------------

const numericSchema = z.union([z.number(), z.string()]).transform((value) => Number(value));

const routeRecordJsonSchema = z.object({
  status: z.unknown(),
  hostnameHash: z.string(),
  paidUntilEpoch: numericSchema
});

const routeGenerationJsonSchema = z.object({
  assignmentHash: z.string(),
  primaryGatewayId: numericSchema,
  validFromEpoch: numericSchema,
  expiresAtEpoch: numericSchema,
  status: z.unknown()
});

function parseRouteStatus(value: unknown): RouteStatus | null {
  switch (enumName(value)) {
    case "created":
      return "Created";
    case "active":
      return "Active";
    case "retired":
      return "Retired";
    default:
      return null;
  }
}

function parseGenerationStatus(value: unknown): GenerationStatus | null {
  switch (enumName(value)) {
    case "assigned":
      return "Assigned";
    case "promoted":
      return "Promoted";
    default:
      return null;
  }
}

/** polkadot-js renders a fieldless enum as its variant name, occasionally as
 * a single-key object; reduce both to a lowercased name. */
function enumName(value: unknown): string | null {
  if (typeof value === "string") {
    return value.toLowerCase();
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>);
    if (keys.length === 1) {
      return keys[0].toLowerCase();
    }
  }
  return null;
}

export function decodeRouteRecord(json: unknown): RouteRecordView | null {
  const parsed = routeRecordJsonSchema.safeParse(json);
  if (!parsed.success) {
    return null;
  }
  const status = parseRouteStatus(parsed.data.status);
  if (!status) {
    return null;
  }
  return {
    status,
    hostnameHash: parsed.data.hostnameHash,
    paidUntilEpoch: parsed.data.paidUntilEpoch
  };
}

export function decodeRouteGeneration(json: unknown): RouteGenerationView | null {
  const parsed = routeGenerationJsonSchema.safeParse(json);
  if (!parsed.success) {
    return null;
  }
  const status = parseGenerationStatus(parsed.data.status);
  if (!status) {
    return null;
  }
  return {
    assignmentHash: parsed.data.assignmentHash,
    primaryGatewayId: parsed.data.primaryGatewayId,
    validFromEpoch: parsed.data.validFromEpoch,
    expiresAtEpoch: parsed.data.expiresAtEpoch,
    status
  };
}

// --- Pure serving decision + RouteIntent construction ----------------------

export type ServingDecision = "serve" | "withdraw";

export interface ServingDecisionInput {
  route: RouteRecordView | null;
  activeGenerationId: number | null;
  generation: RouteGenerationView | null;
  gatewayId: number;
  currentEpoch: number;
}

/** Mirror of the pallet's serving gate: serve only an Active route whose
 * active generation is Promoted, bound to this gateway, and unexpired. */
export function routeServingDecision(input: ServingDecisionInput): ServingDecision {
  const { route, activeGenerationId, generation, gatewayId, currentEpoch } = input;
  if (!route || route.status !== "Active") {
    return "withdraw";
  }
  if (activeGenerationId === null || !generation) {
    return "withdraw";
  }
  if (generation.status !== "Promoted") {
    return "withdraw";
  }
  if (generation.primaryGatewayId !== gatewayId) {
    return "withdraw";
  }
  if (currentEpoch >= generation.expiresAtEpoch) {
    return "withdraw";
  }
  return "serve";
}

/** Epoch boundaries are timestamp-derived (epoch = now_ms / epoch_ms), so an
 * epoch number maps back to the unix-seconds RouteIntent lease deadline. */
export function epochToUnixSeconds(epoch: number, epochDurationMillis: number): number {
  return Math.floor((epoch * epochDurationMillis) / 1000);
}

export interface BuildRouteIntentInput {
  routeId: `0x${string}`;
  generationId: number;
  gatewayId: number;
  generation: RouteGenerationView;
  document: AssignmentDocument;
  epochDurationMillis: number;
}

export function buildRouteIntent(input: BuildRouteIntentInput): RouteIntent {
  const { routeId, generationId, gatewayId, generation, document, epochDurationMillis } = input;
  const intent: RouteIntentInput = {
    routeId,
    sessionId: routeId,
    hostname: document.hostname,
    publicHostname: document.publicHostname,
    validationHostname: document.validationHostname,
    customerHostnames: document.customerHostnames,
    upstreamHost: document.upstreamHost,
    upstreamPort: document.upstreamPort,
    expiresAt: epochToUnixSeconds(generation.expiresAtEpoch, epochDurationMillis),
    source: {
      proofIngress: { routeId, generationId, gatewayId }
    }
  };
  return normalizeRouteIntent(intent);
}

// --- Off-chain assignment document store -----------------------------------

export interface AssignmentDocumentStore {
  read(assignmentHash: string): Promise<AssignmentDocument | null>;
}

export class LocalAssignmentDocumentStore implements AssignmentDocumentStore {
  constructor(private readonly dir: string) {}

  async read(assignmentHash: string): Promise<AssignmentDocument | null> {
    const file = path.join(this.dir, `${stripHexPrefix(assignmentHash)}.json`);
    try {
      const raw = await fs.readFile(file, "utf8");
      const parsed = assignmentDocumentSchema.safeParse(JSON.parse(raw));
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }
}

// --- Route intent sink (gateway-agent client) ------------------------------

export interface RouteIntentSink {
  upsert(intent: RouteIntent): Promise<void>;
  withdraw(routeId: string): Promise<void>;
}

export class HttpRouteIntentSink implements RouteIntentSink {
  constructor(private readonly url: string, private readonly token?: string) {}

  async upsert(intent: RouteIntent): Promise<void> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(intent)
    });
    if (!response.ok) {
      throw new Error(`route intent post failed: ${response.status} ${await response.text()}`);
    }
  }

  async withdraw(routeId: string): Promise<void> {
    const response = await fetch(`${this.url}/${encodeURIComponent(routeId)}`, {
      method: "DELETE",
      headers: this.headers()
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`route intent withdraw failed: ${response.status} ${await response.text()}`);
    }
  }

  private headers(): Record<string, string> {
    return {
      "content-type": "application/json",
      ...(this.token ? { authorization: `Bearer ${this.token}` } : {})
    };
  }
}

// --- Event-driven watcher shell --------------------------------------------

const WATCHED_EVENTS = new Set([
  "RouteLeaseCreated",
  "RouteGenerationAssigned",
  "RouteGenerationPromoted",
  "RouteActivated",
  "RouteRetired"
]);

const hex32Pattern = /^0x[0-9a-fA-F]{64}$/;

export interface ParachainWatcherOptions {
  api: ApiPromise;
  gatewayId: number;
  documentStore: AssignmentDocumentStore;
  sink: RouteIntentSink;
  epochDurationMillis?: number;
  logger?: (message: string) => void;
}

export class ParachainWatcher {
  private readonly served = new Set<string>();
  private unsubscribe?: () => void;
  private epochDurationMillis = 0;

  constructor(private readonly options: ParachainWatcherOptions) {}

  async start(seedRouteIds: string[] = []): Promise<void> {
    this.epochDurationMillis =
      this.options.epochDurationMillis ??
      Number(this.options.api.consts.proofIngress.epochDurationMillis.toString());

    for (const routeId of seedRouteIds) {
      await this.reconcile(routeId);
    }

    this.unsubscribe = (await this.options.api.query.system.events((records: unknown) => {
      for (const routeId of collectRouteIds(records as Iterable<FrameSystemEventRecord>)) {
        void this.reconcile(routeId).catch((error: unknown) => {
          this.log(`reconcile ${routeId} failed: ${errorMessage(error)}`);
        });
      }
    })) as unknown as () => void;
  }

  async stop(): Promise<void> {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  /** Re-evaluate one route against chain state and reconcile the agent. */
  async reconcile(routeId: string): Promise<void> {
    const { api, gatewayId } = this.options;
    const route = decodeRouteRecord((await api.query.proofIngress.routes(routeId)).toJSON());
    const activeGenerationRaw = (await api.query.proofIngress.activeGeneration(routeId)).toJSON();
    const activeGenerationId =
      activeGenerationRaw === null || activeGenerationRaw === undefined
        ? null
        : Number(activeGenerationRaw);
    const generation =
      activeGenerationId === null
        ? null
        : decodeRouteGeneration(
            (await api.query.proofIngress.routeGenerations(routeId, activeGenerationId)).toJSON()
          );
    const currentEpoch = await this.currentEpoch();

    const decision = routeServingDecision({
      route,
      activeGenerationId,
      generation,
      gatewayId,
      currentEpoch
    });

    if (decision === "serve" && generation && activeGenerationId !== null) {
      const document = await this.options.documentStore.read(generation.assignmentHash);
      if (!document) {
        this.log(`no assignment document for ${routeId} (${generation.assignmentHash})`);
        return;
      }
      const intent = buildRouteIntent({
        routeId: routeId as `0x${string}`,
        generationId: activeGenerationId,
        gatewayId,
        generation,
        document,
        epochDurationMillis: this.epochDurationMillis
      });
      await this.options.sink.upsert(intent);
      this.served.add(routeId);
      this.log(`serving ${routeId} generation ${activeGenerationId}`);
      return;
    }

    if (this.served.has(routeId)) {
      await this.options.sink.withdraw(routeId);
      this.served.delete(routeId);
      this.log(`withdrew ${routeId}`);
    }
  }

  private async currentEpoch(): Promise<number> {
    const nowMillis = BigInt((await this.options.api.query.timestamp.now()).toString());
    return Number(nowMillis / BigInt(this.epochDurationMillis));
  }

  private log(message: string): void {
    this.options.logger?.(`[parachain-watcher] ${message}`);
  }
}

/** Extract the H256 route ids touched by watched proofIngress events. */
export function collectRouteIds(records: Iterable<FrameSystemEventRecord>): string[] {
  const routeIds = new Set<string>();
  for (const record of records) {
    const { event } = record;
    if (event.section !== "proofIngress" || !WATCHED_EVENTS.has(event.method)) {
      continue;
    }
    for (const datum of event.data) {
      const hex = toHex(datum);
      if (hex && hex32Pattern.test(hex)) {
        routeIds.add(hex);
        break;
      }
    }
  }
  return [...routeIds];
}

interface FrameSystemEventRecord {
  event: {
    section: string;
    method: string;
    data: ArrayLike<unknown> & Iterable<unknown>;
  };
}

function toHex(value: unknown): string | null {
  if (value && typeof (value as { toHex?: () => string }).toHex === "function") {
    return (value as { toHex: () => string }).toHex();
  }
  return null;
}

function stripHexPrefix(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// --- Entrypoint ------------------------------------------------------------

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

export async function main(): Promise<void> {
  const wsUrl = requireEnv("PROOF_INGRESS_WS_URL");
  const gatewayId = Number(requireEnv("PROOF_INGRESS_GATEWAY_ID"));
  const documentDir = requireEnv("PROOF_INGRESS_ASSIGNMENT_DOC_DIR");
  const routeIntentUrl =
    process.env.ROUTE_INTENT_OUTPUT_URL ?? "http://gateway-agent:18080/route-intents";
  const routeIntentToken = process.env.ROUTE_INTENT_OUTPUT_TOKEN;
  const seedRouteIds = (process.env.PROOF_INGRESS_SEED_ROUTE_IDS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  const api = await connectParachain(wsUrl);
  const watcher = new ParachainWatcher({
    api,
    gatewayId,
    documentStore: new LocalAssignmentDocumentStore(documentDir),
    sink: new HttpRouteIntentSink(routeIntentUrl, routeIntentToken),
    logger: (message) => console.log(message)
  });
  await watcher.start(seedRouteIds);
  console.log(`[parachain-watcher] watching ${wsUrl} as gateway ${gatewayId}`);
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main().catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
}
