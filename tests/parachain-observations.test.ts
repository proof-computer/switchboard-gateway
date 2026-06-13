import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { normalizeRouteIntent, type RouteIntentInput } from "../src/route-intent.js";
import { deriveGatewayObservations, readRouteBinding } from "../src/parachain-observations.js";

const SESSION = "0x" + "11".repeat(32);
const ROUTE_A = "0x" + "a1".repeat(32);
const ROUTE_B = "0x" + "b2".repeat(32);

function route(overrides: Partial<RouteIntentInput> & { source?: Record<string, unknown> }): ReturnType<typeof normalizeRouteIntent> {
  return normalizeRouteIntent({
    sessionId: SESSION,
    hostname: "app.example.com",
    upstreamHost: "10.0.0.1",
    upstreamPort: 8443,
    expiresAt: 9_999_999_999,
    ...overrides
  });
}

function binding(routeId: string, generationId: number, gatewayId: number) {
  return { source: { proofIngress: { routeId, generationId, gatewayId } } };
}

describe("parachain gateway observations", () => {
  it("reads a valid binding and rejects missing/invalid ones", () => {
    assert.deepEqual(readRouteBinding(route(binding(ROUTE_A, 7, 3))), {
      routeId: ROUTE_A,
      generationId: 7,
      gatewayId: 3
    });
    assert.equal(readRouteBinding(route({})), null);
    assert.equal(readRouteBinding(route({ source: { proofIngress: { routeId: "nope", generationId: 1, gatewayId: 3 } } })), null);
    assert.equal(readRouteBinding(route({ source: { proofIngress: { routeId: ROUTE_A, generationId: 7 } } })), null);
  });

  it("emits Serving for live bound routes and Stopped for expired ones", () => {
    const now = 1_000;
    const observations = deriveGatewayObservations(
      [
        route({ ...binding(ROUTE_A, 7, 3), expiresAt: now + 100 }),
        route({ ...binding(ROUTE_B, 2, 3), expiresAt: now - 100 })
      ],
      3,
      now
    );
    assert.deepEqual(
      observations.sort((a, b) => a.routeId.localeCompare(b.routeId)),
      [
        { routeId: ROUTE_A, generationId: 7, status: "Serving" },
        { routeId: ROUTE_B, generationId: 2, status: "Stopped" }
      ]
    );
  });

  it("skips routes bound to other gateways or with no binding", () => {
    const observations = deriveGatewayObservations(
      [
        route(binding(ROUTE_A, 7, 5)), // other gateway
        route({}) // no binding
      ],
      3
    );
    assert.deepEqual(observations, []);
  });

  it("dedupes by (routeId, generationId) with last write winning", () => {
    const now = 1_000;
    const observations = deriveGatewayObservations(
      [
        route({ ...binding(ROUTE_A, 7, 3), expiresAt: now + 100 }), // Serving
        route({ ...binding(ROUTE_A, 7, 3), expiresAt: now - 100 }) // Stopped (later, wins)
      ],
      3,
      now
    );
    assert.deepEqual(observations, [{ routeId: ROUTE_A, generationId: 7, status: "Stopped" }]);
  });
});
