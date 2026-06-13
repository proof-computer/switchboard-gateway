// PROOF Ingress parachain gateway observations.
//
// The gateway is the data-plane edge. The parachain's `record_gateway_observation`
// extrinsic lets a gateway attest, signing with its own operational key, that it
// is (or has stopped) serving specific route generations. These observations are
// advisory liveness/corroboration: they never gate activation and never touch
// settlement (the protocol's money/health split). This module turns the agent's
// live route state into a signed, batched observation submission.
//
// A route is observed only when its placement carries the on-chain binding the
// broker assigned to THIS gateway, under `route.source.proofIngress`:
//
//   { "proofIngress": { "routeId": "0x..32 bytes..", "generationId": 7, "gatewayId": 3 } }
//
// Routes without that binding (legacy/Hub placements) are skipped.

import { ApiPromise, WsProvider } from "@polkadot/api";
import { Keyring } from "@polkadot/keyring";
import { cryptoWaitReady } from "@polkadot/util-crypto";
import { z } from "zod";

import { routeIsActive, type RouteIntent } from "./route-intent.js";

export type GatewayObservationStatus = "Serving" | "Stopped";

export interface GatewayObservation {
  routeId: `0x${string}`;
  generationId: number;
  status: GatewayObservationStatus;
}

const proofIngressBindingSchema = z.object({
  routeId: z.string().regex(/^0x[0-9a-fA-F]{64}$/),
  generationId: z.number().int().nonnegative(),
  gatewayId: z.number().int().nonnegative()
});

export type ProofIngressRouteBinding = z.infer<typeof proofIngressBindingSchema>;

/** Parse the on-chain binding a broker placed on a route, or null if absent/invalid. */
export function readRouteBinding(route: RouteIntent): ProofIngressRouteBinding | null {
  const candidate = (route.source as Record<string, unknown> | undefined)?.proofIngress;
  if (!candidate) {
    return null;
  }
  const parsed = proofIngressBindingSchema.safeParse(candidate);
  return parsed.success ? parsed.data : null;
}

/**
 * Derive the gateway observation set from the agent's current route map. Pure:
 * a route bound to this gateway is `Serving` while its lease is live and
 * `Stopped` once it expires (the agent keeps freshly-expired routes briefly,
 * so the gateway can ack the stop before they are swept). Routes bound to
 * other gateways or without a binding are skipped. Last write per
 * (routeId, generationId) wins.
 */
export function deriveGatewayObservations(
  routes: RouteIntent[],
  gatewayId: number,
  nowSeconds = Math.floor(Date.now() / 1000)
): GatewayObservation[] {
  const byKey = new Map<string, GatewayObservation>();
  for (const route of routes) {
    const binding = readRouteBinding(route);
    if (!binding || binding.gatewayId !== gatewayId) {
      continue;
    }
    const status: GatewayObservationStatus = routeIsActive(route, nowSeconds) ? "Serving" : "Stopped";
    byKey.set(`${binding.routeId}:${binding.generationId}`, {
      routeId: binding.routeId as `0x${string}`,
      generationId: binding.generationId,
      status
    });
  }
  return [...byKey.values()];
}

export async function connectParachain(wsUrl: string): Promise<ApiPromise> {
  const api = await ApiPromise.create({
    provider: new WsProvider(wsUrl),
    noInitWarn: true,
    throwOnConnect: true
  });
  await api.isReady;
  return api;
}

/**
 * Keep only observations whose generation is actually bound to this gateway on
 * chain (`RouteGenerations[routeId, generationId].primaryGatewayId == gatewayId`).
 * This is the spec's "learn whether it is my generation from chain state" check;
 * it is bounded by the gateway's own routes, never the global route set.
 */
export async function confirmBoundGenerations(
  api: ApiPromise,
  observations: GatewayObservation[],
  gatewayId: number
): Promise<GatewayObservation[]> {
  const confirmed: GatewayObservation[] = [];
  for (const observation of observations) {
    const record = await api.query.proofIngress.routeGenerations(observation.routeId, observation.generationId);
    if (record.isEmpty) {
      continue;
    }
    const json = record.toJSON() as { primaryGatewayId?: number } | null;
    if (json && Number(json.primaryGatewayId) === gatewayId) {
      confirmed.push(observation);
    }
  }
  return confirmed;
}

export interface PublishGatewayObservationsInput {
  api: ApiPromise;
  /** sr25519 operational key URI/seed — must match the gateway's registered signing key. */
  signingKey: string;
  ss58Format?: number;
  gatewayId: number;
  observations: GatewayObservation[];
  /** Max items per `record_gateway_observation` call (must be <= the runtime's MaxGatewayObservationBatch). */
  batchMax?: number;
  /** Filter to generations on-chain-bound to this gateway before submitting (default true). */
  verifyBindings?: boolean;
}

export interface PublishGatewayObservationsResult {
  submitted: number;
  batches: number;
}

/** Sign with the gateway operational key and submit the observations in bounded batches. */
export async function publishGatewayObservations(
  input: PublishGatewayObservationsInput
): Promise<PublishGatewayObservationsResult> {
  const batchMax = Math.max(1, input.batchMax ?? 256);
  let observations = input.observations;
  if (input.verifyBindings ?? true) {
    observations = await confirmBoundGenerations(input.api, observations, input.gatewayId);
  }
  if (observations.length === 0) {
    return { submitted: 0, batches: 0 };
  }

  await cryptoWaitReady();
  const keyring = new Keyring({ type: "sr25519", ss58Format: input.ss58Format });
  const pair = keyring.addFromUri(input.signingKey);

  const batches = chunk(observations, batchMax);
  for (const batch of batches) {
    const items = batch.map((observation) => [observation.routeId, observation.generationId, observation.status]);
    await submitInBlock(input.api, input.api.tx.proofIngress.recordGatewayObservation(items), pair);
  }
  return { submitted: observations.length, batches: batches.length };
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    out.push(items.slice(index, index + size));
  }
  return out;
}

async function submitInBlock(
  api: ApiPromise,
  tx: ReturnType<ApiPromise["tx"]["proofIngress"]["recordGatewayObservation"]>,
  pair: ReturnType<Keyring["addFromUri"]>
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    tx.signAndSend(pair, { nonce: -1 }, (result) => {
      if (result.dispatchError) {
        let message = result.dispatchError.toString();
        if (result.dispatchError.isModule) {
          const decoded = api.registry.findMetaError(result.dispatchError.asModule);
          message = `${decoded.section}.${decoded.name}`;
        }
        reject(new Error(`record_gateway_observation failed: ${message}`));
      } else if (result.status.isInBlock || result.status.isFinalized) {
        resolve();
      } else if (result.isError) {
        reject(new Error(`record_gateway_observation tx error: ${result.status.toString()}`));
      }
    }).catch(reject);
  });
}
