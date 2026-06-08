import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  OPERATOR_CAPABILITY_REPORT_DOMAIN,
  gatewayCapabilityReportId,
  normalizeGatewayCapabilityReport,
  operatorCapabilityRouteIntentUrl,
  parseOperatorProfiles,
  reportSignerAllowedByProfile,
  selectOperatorCapabilityCandidate,
  signGatewayCapabilityReport,
  verifySignedGatewayCapabilityReport,
  type GatewayCapabilityReport,
  type OperatorProfile,
  type StoredGatewayCapabilityReport
} from "../src/operator-capability.js";
import { signReportPayload } from "../src/report-signing.js";

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

async function signedStoredReport(report: GatewayCapabilityReport = sampleReport()): Promise<StoredGatewayCapabilityReport> {
  const signed = await signGatewayCapabilityReport(report, ATTACKER_PRIVATE_KEY, {
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
  it("scopes generated gateway capability report ids by gateway", () => {
    const reportedAt = new Date("2026-06-08T14:13:39.000Z");

    assert.equal(
      gatewayCapabilityReportId({ gatewayId: "switchboard-az-02", reportedAt, configVersion: "24" }),
      "gateway-capability-switchboard-az-02-1780928019-24"
    );
    assert.equal(
      gatewayCapabilityReportId({ gatewayId: "switchboard-az-03", reportedAt, configVersion: "24" }),
      "gateway-capability-switchboard-az-03-1780928019-24"
    );

    const longReportId = gatewayCapabilityReportId({
      gatewayId: `gateway-${"very-long-".repeat(20)}az-03`,
      reportedAt,
      configVersion: "24"
    });
    assert.equal(longReportId.length <= 160, true);
    assert.match(longReportId, /^gateway-capability-gateway-very-long-/);
    assert.match(longReportId, /-1780928019-24$/);
  });

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

  it("skips explicitly unhealthy route-state reports when route-state is required", async () => {
    const report = sampleReport();
    report.gateway.routeStateHealthy = false;
    report.gateway.routeStateLastSuccessAt = "2026-05-08T00:00:00.000Z";
    const stored = await signedStoredReport(report);
    const selected = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile({ reportSigners: [stored.signer] })],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteStateUrl: true
    });

    assert.equal(selected, undefined);
  });

  it("keeps legacy route-state reports selectable when health is omitted", async () => {
    const stored = await signedStoredReport();
    const selected = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile({ reportSigners: [stored.signer] })],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteStateUrl: true
    });

    assert.equal(selected?.gatewayId, "attacker-gateway");
  });

  it("preserves minimal processor-discovery diagnostics in signed reports", async () => {
    const report = sampleReport();
    report.gateway.processorDiscoveryFresh = false;
    report.gateway.reportedProcessorCount = 0;

    const stored = await signedStoredReport(report);

    assert.equal(stored.report.gateway.processorDiscoveryFresh, false);
    assert.equal(stored.report.gateway.reportedProcessorCount, 0);
  });

  it("verifies signed reports with relay-pull route-state admission counters", async () => {
    const report = sampleReport();
    report.gateway.upstreamAdmissionModes = ["relay-pull", "direct-post", "relay-pull"];
    report.gateway.routeState = {
      enabled: true,
      url: "https://attacker.example/route-state",
      lastCheckedAt: "2026-05-08T00:00:00.000Z",
      lastSuccessAt: "2026-05-08T00:00:00.000Z",
      polledRouteCount: 0,
      desiredRouteCount: 0,
      pendingUpstreamAdmissionRequestCount: 1,
      acceptedUpstreamAdmissionCount: 2,
      processedUpstreamAdmissionRequestCount: 3,
      healthy: true,
      staleAfterMs: 15000
    };

    const stored = await signedStoredReport(report);

    assert.deepEqual(stored.report.gateway.upstreamAdmissionModes, ["relay-pull", "direct-post"]);
    assert.equal(stored.report.gateway.routeState?.pendingUpstreamAdmissionRequestCount, 1);
    assert.equal(stored.report.gateway.routeState?.acceptedUpstreamAdmissionCount, 2);
    assert.equal(stored.report.gateway.routeState?.processedUpstreamAdmissionRequestCount, 3);
  });

  it("strips legacy report route-intent URLs from new signed capability reports", async () => {
    const report = sampleReport();
    report.gateway.routeIntentUrl = "https://attacker.example/route-intents";

    const signed = await signGatewayCapabilityReport(report, ATTACKER_PRIVATE_KEY, {
      signedAt: "2026-05-08T00:00:00.000Z"
    });
    const verified = await verifySignedGatewayCapabilityReport(signed, {
      now: new Date("2026-05-08T00:00:01.000Z")
    });

    assert.equal("routeIntentUrl" in signed.report.gateway, false);
    assert.equal("routeIntentUrl" in verified.report.gateway, false);
  });

  it("accepts legacy signed reports with route-intent URLs but strips them before storage", async () => {
    const report = sampleReport();
    report.gateway.routeIntentUrl = "https://attacker.example/route-intents";
    const legacyReport = normalizeGatewayCapabilityReport(report, { preserveLegacyRouteIntentUrl: true });
    const signature = await signReportPayload(ATTACKER_PRIVATE_KEY, OPERATOR_CAPABILITY_REPORT_DOMAIN, legacyReport, {
      signedAt: "2026-05-08T00:00:00.000Z"
    });

    const verified = await verifySignedGatewayCapabilityReport({ report: legacyReport, signature }, {
      now: new Date("2026-05-08T00:00:01.000Z")
    });

    assert.equal("routeIntentUrl" in legacyReport.gateway, true);
    assert.equal("routeIntentUrl" in verified.report.gateway, false);
  });

  it("does not treat report route-intent URLs as selectable sinks", async () => {
    const stored = await signedStoredReport();
    stored.report.gateway.routeIntentUrl = "https://attacker.example/route-intents";

    const selected = selectOperatorCapabilityCandidate({
      profiles: [sampleProfile({ reportSigners: [stored.signer] })],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteIntentSink: true
    });

    assert.equal(operatorCapabilityRouteIntentUrl(sampleProfile(), stored.report), undefined);
    assert.equal(selected, undefined);
  });

  it("selects profile-pinned route-intent sinks", async () => {
    const stored = await signedStoredReport();
    stored.report.gateway.routeIntentUrl = "https://attacker.example/route-intents";
    const profileRouteIntentUrl = "https://profile.example/route-intents";

    const selected = selectOperatorCapabilityCandidate({
      profiles: [
        sampleProfile({
          reportSigners: [stored.signer],
          gatewayIds: ["attacker-gateway"],
          routeIntentUrl: profileRouteIntentUrl,
          routeIntentTokenEnv: "PROFILE_ROUTE_INTENT_TOKEN"
        })
      ],
      reports: [stored],
      now: new Date("2026-05-08T00:00:02.000Z"),
      requireRouteIntentSink: true
    });

    assert.equal(selected?.routeIntentUrl, profileRouteIntentUrl);
    assert.equal(selected?.routeIntentTokenEnv, "PROFILE_ROUTE_INTENT_TOKEN");
  });
});
