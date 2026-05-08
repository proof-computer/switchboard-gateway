import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  parseOperatorProfiles,
  reportSignerAllowedByProfile,
  selectOperatorCapabilityCandidate,
  signGatewayCapabilityReport,
  verifySignedGatewayCapabilityReport,
  type GatewayCapabilityReport,
  type OperatorProfile,
  type StoredGatewayCapabilityReport
} from "../src/operator-capability.js";

const OPERATOR_ID = "0x1111111111111111111111111111111111111111111111111111111111111111";
const PROCESSOR_ID = "0x2222222222222222222222222222222222222222222222222222222222222222";
const ATTACKER_PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_SIGNER = "0x0000000000000000000000000000000000000001";

function sampleProfile(overrides: Partial<OperatorProfile> = {}): OperatorProfile {
  return {
    operatorId: OPERATOR_ID,
    status: "active",
    reportSigners: [],
    gatewayIds: [],
    managerIds: [],
    processorIds: [],
    ...overrides
  };
}

function sampleReport(): GatewayCapabilityReport {
  return {
    version: 1,
    kind: "switchboard.operator.capability",
    reportId: "operator-capability-signer-regression",
    reportedAt: "2026-05-08T00:00:00.000Z",
    expiresAt: "2999-01-01T00:00:00.000Z",
    operator: {
      operatorId: OPERATOR_ID,
      gatewayId: "attacker-gateway",
      managerIds: []
    },
    gateway: {
      publicAddresses: ["198.51.100.10"],
      routeStateUrl: "https://attacker.example/route-state",
      activeRouteCount: 0,
      routeCapacity: 1,
      supportedClasses: []
    },
    processorScopes: [
      {
        kind: "explicit",
        processors: [PROCESSOR_ID]
      }
    ]
  };
}

async function signedStoredReport(): Promise<StoredGatewayCapabilityReport> {
  const signed = await signGatewayCapabilityReport(sampleReport(), ATTACKER_PRIVATE_KEY, {
    signedAt: "2026-05-08T00:00:00.000Z"
  });
  const verified = await verifySignedGatewayCapabilityReport(signed, {
    now: new Date("2026-05-08T00:00:01.000Z")
  });
  return {
    receivedAt: "2026-05-08T00:00:01.000Z",
    report: verified.report,
    signer: verified.signer,
    signature: verified.signature
  };
}

describe("operator capability signer authorization", () => {
  it("rejects active operator profiles without explicit report signers", () => {
    assert.throws(
      () => parseOperatorProfiles([{ operatorId: OPERATOR_ID }]),
      /Active operator profiles require at least one report signer/
    );
    assert.throws(
      () => parseOperatorProfiles([{ operatorId: OPERATOR_ID, reportSigners: [] }]),
      /Active operator profiles require at least one report signer/
    );
  });

  it("allows inactive profiles to omit report signers without authorizing reports", () => {
    const [profile] = parseOperatorProfiles([{ operatorId: OPERATOR_ID, status: "inactive" }]);
    assert.equal(profile.reportSigners.length, 0);
    assert.equal(reportSignerAllowedByProfile(profile, OTHER_SIGNER), false);
  });

  it("denies signer authorization when reportSigners is empty", () => {
    assert.equal(reportSignerAllowedByProfile(sampleProfile(), OTHER_SIGNER), false);
  });

  it("rejects candidate selection when a profile has no configured report signers", async () => {
    const stored = await signedStoredReport();
    const selected = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile()],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteStateUrl: true
    });

    assert.equal(selected, undefined);
  });

  it("allows candidate selection only when signer is explicitly allowlisted", async () => {
    const stored = await signedStoredReport();
    const selected = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile({ reportSigners: [stored.signer] })],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteStateUrl: true
    });

    assert.equal(selected?.reportSigner, stored.signer);

    const restricted = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile({ reportSigners: [OTHER_SIGNER] })],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteStateUrl: true
    });
    assert.equal(restricted, undefined);
  });
});
