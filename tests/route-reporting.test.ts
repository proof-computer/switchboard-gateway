import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";

import { normalizeRouteIntent, routeServerNames } from "../src/route-intent.js";
import { buildRouteStatusReport } from "../src/route-status-report.js";
import { renderFileXds } from "../src/xds.js";
import { verifyReportSignature } from "../src/report-signing.js";

const REPORT_SEED = "//Alice//proof-ingress-operator-report";

describe("route reporting", () => {
  it("builds a signed route-status report from stored routes and rendered xDS", async () => {
    const outputDir = await mkdtemp(path.join(tmpdir(), "switchboard-xds-"));
    const now = new Date();
    const route = normalizeRouteIntent({
      routeId: "alpha-route",
      sessionId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      hostname: "Alpha.Ingress.Works",
      publicHostname: "Alpha.Ingress.Works",
      validationHostname: "Alpha-Validation.Ingress.Works",
      hostnameRole: "ha_public",
      upstreamHost: "192.168.3.69",
      upstreamPort: 3443,
      expiresAt: Math.floor(now.getTime() / 1000) + 600,
      source: {
        mode: "test"
      }
    });
    assert.deepEqual(routeServerNames(route), ["alpha.ingress.works", "alpha-validation.ingress.works"]);
    await renderFileXds([route], {
      outputDir,
      version: "7",
      listenerName: "switchboard_https",
      listenerAddress: "0.0.0.0",
      listenerPort: 10000
    });
    const lds = JSON.parse(await readFile(path.join(outputDir, "lds.json"), "utf8")) as {
      resources: Array<{ filter_chains?: Array<{ name?: string; filter_chain_match?: { server_names?: string[] } }> }>;
    };
    const renderedRoute = lds.resources[0].filter_chains?.find((filterChain) => filterChain.name === "route_alpha-route");
    assert.deepEqual(renderedRoute?.filter_chain_match?.server_names, [
      "alpha.ingress.works",
      "alpha-validation.ingress.works"
    ]);

    const report = await buildRouteStatusReport({
      routes: [route],
      xdsDir: outputDir,
      configVersion: "7",
      listenerName: "switchboard_https",
      listenerAddress: "0.0.0.0",
      listenerPort: 10000,
      operatorId: "operator-1",
      gatewayId: "gateway-1",
      signingKey: REPORT_SEED,
      signingScheme: "substrate-sr25519",
      signingSs58Format: 42,
      filters: {
        sessionId: route.sessionId,
        hostname: route.validationHostname
      },
      now
    });

    assert.equal(report.kind, "proof-ingress.operator.route-status");
    assert.equal(report.summary.reportedRouteCount, 1);
    assert.equal(report.summary.configuredRouteCount, 1);
    assert.equal(report.xds.ok, true);
    assert.equal(report.xds.listenerPresent, true);
    assert.equal(report.routes[0].observed.configured, true);
    assert.equal(report.routes[0].hostname, "alpha.ingress.works");
    assert.equal(report.routes[0].publicHostname, "alpha.ingress.works");
    assert.equal(report.routes[0].validationHostname, "alpha-validation.ingress.works");
    assert.deepEqual(report.routes[0].hostnames.serverNames, [
      "alpha.ingress.works",
      "alpha-validation.ingress.works"
    ]);
    assert.equal(report.signature?.scheme, "substrate-sr25519");
    assert.match(report.signature?.publicKey ?? "", /^0x[0-9a-f]{64}$/);
    const { signature, ...unsignedReport } = report;
    assert(signature);
    assert.equal(await verifyReportSignature(unsignedReport, signature), signature.signer);
  });

  it("renders unique Envoy resource names for long structured route IDs", async () => {
    const outputDir = await mkdtemp(path.join(tmpdir(), "switchboard-xds-"));
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const routeA = normalizeRouteIntent({
      routeId:
        'switchboard-{"origin":{"kind":"Acurast","source":"5cd81f74fbd78efad9568d2f0136ac2dc01f0f2d4ec0c9061277a3147cc7e031"},"id":"54489"}',
      sessionId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      hostname: "first.ingress.works",
      upstreamHost: "192.168.3.103",
      upstreamPort: 3443,
      expiresAt
    });
    const routeB = normalizeRouteIntent({
      routeId:
        'switchboard-{"origin":{"kind":"Acurast","source":"5cd81f74fbd78efad9568d2f0136ac2dc01f0f2d4ec0c9061277a3147cc7e031"},"id":"54494"}',
      sessionId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      hostname: "second.ingress.works",
      upstreamHost: "192.168.3.164",
      upstreamPort: 3443,
      expiresAt
    });

    await renderFileXds([routeA, routeB], {
      outputDir,
      version: "8",
      listenerName: "switchboard_https",
      listenerAddress: "0.0.0.0",
      listenerPort: 10000
    });

    const cds = JSON.parse(await readFile(path.join(outputDir, "cds.json"), "utf8")) as {
      resources: Array<{ name?: string; load_assignment?: { endpoints?: unknown[] } }>;
    };
    const routeClusterNames = cds.resources.map((resource) => resource.name).filter((name) => name?.startsWith("route_"));
    assert.equal(routeClusterNames.length, 2);
    assert.equal(new Set(routeClusterNames).size, 2);

    const lds = JSON.parse(await readFile(path.join(outputDir, "lds.json"), "utf8")) as {
      resources: Array<{
        filter_chains?: Array<{
          filter_chain_match?: { server_names?: string[] };
          filters?: Array<{ typed_config?: { cluster?: string } }>;
        }>;
      }>;
    };
    const routeChains = lds.resources[0].filter_chains?.filter((filterChain) =>
      filterChain.filter_chain_match?.server_names?.some((serverName) => serverName.endsWith(".ingress.works"))
    ) ?? [];
    assert.equal(routeChains.length, 2);
    assert.deepEqual(
      routeChains.map((filterChain) => filterChain.filters?.[0]?.typed_config?.cluster),
      routeClusterNames
    );
  });

  it("renders shared public hostnames as one HA Envoy filter chain", async () => {
    const outputDir = await mkdtemp(path.join(tmpdir(), "switchboard-xds-"));
    const expiresAt = Math.floor(Date.now() / 1000) + 600;
    const routeA = normalizeRouteIntent({
      routeId: "ha-a",
      sessionId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      hostname: "ha.ingress.works",
      publicHostname: "ha.ingress.works",
      validationHostname: "ha-a.validation.ingress.works",
      upstreamHost: "192.168.3.10",
      upstreamPort: 3443,
      expiresAt
    });
    const routeB = normalizeRouteIntent({
      routeId: "ha-b",
      sessionId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      hostname: "ha.ingress.works",
      publicHostname: "ha.ingress.works",
      validationHostname: "ha-b.validation.ingress.works",
      upstreamHost: "192.168.3.11",
      upstreamPort: 3443,
      expiresAt
    });

    await renderFileXds([routeA, routeB], {
      outputDir,
      version: "9",
      listenerName: "switchboard_https",
      listenerAddress: "0.0.0.0",
      listenerPort: 10000
    });

    const cds = JSON.parse(await readFile(path.join(outputDir, "cds.json"), "utf8")) as {
      resources: Array<{ name?: string; load_assignment?: { endpoints?: Array<{ lb_endpoints?: unknown[] }> } }>;
    };
    const haCluster = cds.resources.find((resource) => resource.name === "ha_ha.ingress.works");
    assert.equal(haCluster?.load_assignment?.endpoints?.[0]?.lb_endpoints?.length, 2);

    const lds = JSON.parse(await readFile(path.join(outputDir, "lds.json"), "utf8")) as {
      resources: Array<{
        filter_chains?: Array<{
          name?: string;
          filter_chain_match?: { server_names?: string[] };
          filters?: Array<{ typed_config?: { cluster?: string } }>;
        }>;
      }>;
    };
    const chains = lds.resources[0].filter_chains ?? [];
    const publicChains = chains.filter((chain) => chain.filter_chain_match?.server_names?.includes("ha.ingress.works"));
    assert.equal(publicChains.length, 1);
    assert.equal(publicChains[0]?.filters?.[0]?.typed_config?.cluster, "ha_ha.ingress.works");
    assert.deepEqual(
      chains
        .filter((chain) => chain.name?.startsWith("route_ha-"))
        .map((chain) => chain.filter_chain_match?.server_names)
        .sort(),
      [["ha-a.validation.ingress.works"], ["ha-b.validation.ingress.works"]]
    );
  });
});
