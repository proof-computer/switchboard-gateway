import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { deriveGatewayObservations, readRouteBinding } from "../src/parachain-observations.js";
import {
  buildRouteIntent,
  collectRouteIds,
  decodeRouteGeneration,
  decodeRouteRecord,
  epochToUnixSeconds,
  routeServingDecision,
  type AssignmentDocument,
  type RouteGenerationView,
  type RouteRecordView
} from "../src/parachain-watcher.js";

const ROUTE_ID = ("0x" + "a1".repeat(32)) as `0x${string}`;
const ASSIGNMENT_HASH = "0x" + "77".repeat(32);
const GATEWAY_ID = 3;
const EPOCH_MS = 30_000;

function generation(overrides: Partial<RouteGenerationView> = {}): RouteGenerationView {
  return {
    assignmentHash: ASSIGNMENT_HASH,
    primaryGatewayId: GATEWAY_ID,
    validFromEpoch: 10,
    expiresAtEpoch: 20,
    status: "Promoted",
    ...overrides
  };
}

function route(overrides: Partial<RouteRecordView> = {}): RouteRecordView {
  return {
    status: "Active",
    hostnameHash: "0x" + "cc".repeat(32),
    paidUntilEpoch: 20,
    ...overrides
  };
}

const document: AssignmentDocument = {
  hostname: "app.lab.test",
  upstreamHost: "127.0.0.1",
  upstreamPort: 8080,
  gatewayId: GATEWAY_ID
};

describe("routeServingDecision", () => {
  it("serves an active, promoted, bound, unexpired generation", () => {
    assert.equal(
      routeServingDecision({
        route: route(),
        activeGenerationId: 1,
        generation: generation(),
        gatewayId: GATEWAY_ID,
        currentEpoch: 15
      }),
      "serve"
    );
  });

  it("withdraws when the route is not active", () => {
    assert.equal(
      routeServingDecision({
        route: route({ status: "Retired" }),
        activeGenerationId: 1,
        generation: generation(),
        gatewayId: GATEWAY_ID,
        currentEpoch: 15
      }),
      "withdraw"
    );
  });

  it("withdraws an assigned-but-not-promoted generation", () => {
    assert.equal(
      routeServingDecision({
        route: route(),
        activeGenerationId: 1,
        generation: generation({ status: "Assigned" }),
        gatewayId: GATEWAY_ID,
        currentEpoch: 15
      }),
      "withdraw"
    );
  });

  it("withdraws a generation bound to another gateway", () => {
    assert.equal(
      routeServingDecision({
        route: route(),
        activeGenerationId: 1,
        generation: generation({ primaryGatewayId: GATEWAY_ID + 1 }),
        gatewayId: GATEWAY_ID,
        currentEpoch: 15
      }),
      "withdraw"
    );
  });

  it("withdraws an expired generation", () => {
    assert.equal(
      routeServingDecision({
        route: route(),
        activeGenerationId: 1,
        generation: generation(),
        gatewayId: GATEWAY_ID,
        currentEpoch: 20
      }),
      "withdraw"
    );
  });

  it("withdraws when there is no active generation", () => {
    assert.equal(
      routeServingDecision({
        route: route(),
        activeGenerationId: null,
        generation: null,
        gatewayId: GATEWAY_ID,
        currentEpoch: 15
      }),
      "withdraw"
    );
  });
});

describe("epochToUnixSeconds", () => {
  it("maps a timestamp epoch back to its lease deadline in seconds", () => {
    assert.equal(epochToUnixSeconds(20, EPOCH_MS), 600);
  });
});

describe("buildRouteIntent", () => {
  it("emits an intent the observations path can bind back to this gateway", () => {
    const intent = buildRouteIntent({
      routeId: ROUTE_ID,
      generationId: 7,
      gatewayId: GATEWAY_ID,
      generation: generation(),
      document,
      epochDurationMillis: EPOCH_MS
    });

    assert.equal(intent.routeId, ROUTE_ID);
    assert.equal(intent.sessionId, ROUTE_ID);
    assert.equal(intent.hostname, "app.lab.test");
    assert.equal(intent.upstreamHost, "127.0.0.1");
    assert.equal(intent.upstreamPort, 8080);
    assert.equal(intent.expiresAt, 600);

    const binding = readRouteBinding(intent);
    assert.deepEqual(binding, { routeId: ROUTE_ID, generationId: 7, gatewayId: GATEWAY_ID });

    const observations = deriveGatewayObservations([intent], GATEWAY_ID, 0);
    assert.equal(observations.length, 1);
    assert.equal(observations[0].status, "Serving");
    assert.equal(observations[0].generationId, 7);
  });
});

describe("decodeRouteRecord / decodeRouteGeneration", () => {
  it("decodes polkadot-js toJSON storage shapes", () => {
    const record = decodeRouteRecord({
      owner: "0x" + "00".repeat(32),
      status: "Active",
      hostnameHash: "0x" + "cc".repeat(32),
      paidUntilEpoch: 20
    });
    assert.equal(record?.status, "Active");
    assert.equal(record?.paidUntilEpoch, 20);

    const decoded = decodeRouteGeneration({
      assignmentHash: ASSIGNMENT_HASH,
      primaryGatewayId: GATEWAY_ID,
      validFromEpoch: 10,
      expiresAtEpoch: 20,
      status: "Promoted"
    });
    assert.equal(decoded?.status, "Promoted");
    assert.equal(decoded?.primaryGatewayId, GATEWAY_ID);
    assert.equal(decoded?.expiresAtEpoch, 20);

    assert.equal(decodeRouteRecord({ status: "Active" }), null);
    assert.equal(decodeRouteGeneration({ status: "Bogus" }), null);
  });
});

describe("collectRouteIds", () => {
  it("extracts route ids from watched proofIngress events only", () => {
    const records = [
      eventRecord("proofIngress", "RouteGenerationPromoted", [ROUTE_ID, 7]),
      eventRecord("proofIngress", "RouteRetired", [ROUTE_ID]),
      eventRecord("proofIngress", "EvidenceBucketCommitted", [ROUTE_ID]),
      eventRecord("balances", "Transfer", [ROUTE_ID])
    ];
    assert.deepEqual(collectRouteIds(records), [ROUTE_ID]);
  });
});

function eventRecord(section: string, method: string, data: Array<string | number>) {
  return {
    event: {
      section,
      method,
      data: data.map((value) =>
        typeof value === "string" ? { toHex: () => value } : { toHex: () => `0x${value}` }
      )
    }
  };
}
