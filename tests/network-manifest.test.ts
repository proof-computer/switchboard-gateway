import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ethers } from "ethers";

import { discoverRegistryWatchTargets } from "../src/registry-discovery.js";
import {
  signNetworkManifest,
  verifySignedNetworkManifest,
  watchedManifestRegistries,
  type NetworkManifest
} from "../src/network-manifest.js";

const SIGNER_SEED = "//Alice//proof-ingress-network-manifest";
const OTHER_SIGNER_SEED = "//Bob//proof-ingress-network-manifest";

describe("network manifest", () => {
  it("signs, verifies, and selects active plus deprecated registries", async () => {
    const manifest = testManifest();
    const signed = await signNetworkManifest(manifest, SIGNER_SEED, {
      scheme: "substrate-sr25519",
      ss58Format: 42,
      signedAt: "2026-04-29T12:00:00.000Z"
    });
    const verified = await verifySignedNetworkManifest(signed, {
      expectedSigner: signed.signature.signer,
      now: new Date("2026-04-29T12:01:00.000Z")
    });

    assert.equal(verified.manifest.sequence, 7);
    assert.equal(verified.signer, signed.signature.signer);
    assert.deepEqual(
      watchedManifestRegistries(verified.manifest).map((registry) => registry.status),
      ["active", "deprecated"]
    );
    assert.deepEqual(
      watchedManifestRegistries(verified.manifest).map((registry) => registry.address),
      [
        "0x1000000000000000000000000000000000000001",
        "0x2000000000000000000000000000000000000002"
      ]
    );
    assert.deepEqual(verified.manifest.relays?.map((relay) => [relay.relayId, relay.active, relay.validationReportUrl]), [
      ["relay-a", true, "https://relay-a.example/v1/validation-reports"],
      ["relay-b", false, undefined]
    ]);
    assert.deepEqual(verified.manifest.catalogs?.relays, {
      url: "https://control.example/v1/service-catalogs/relay",
      signer: "5CatalogSigner111111111111111111111111111111111111",
      required: true,
      maxStaleSeconds: 300
    });
  });

  it("rejects stale manifests and untrusted signers", async () => {
    const manifest = {
      ...testManifest(),
      expiresAt: "2026-04-29T12:00:00.000Z"
    };
    const signed = await signNetworkManifest(manifest, SIGNER_SEED, {
      scheme: "substrate-sr25519",
      ss58Format: 42
    });
    await assert.rejects(
      () =>
        verifySignedNetworkManifest(signed, {
          expectedSigner: signed.signature.signer,
          now: new Date("2026-04-29T12:00:01.000Z")
        }),
      /expired/
    );

    const otherSigned = await signNetworkManifest(testManifest(), OTHER_SIGNER_SEED, {
      scheme: "substrate-sr25519",
      ss58Format: 42
    });
    await assert.rejects(
      () =>
        verifySignedNetworkManifest(otherSigned, {
          expectedSigner: signed.signature.signer,
          now: new Date("2026-04-29T11:59:00.000Z")
        }),
      /does not match expected signer/
    );
  });

  it("lets the operator discover manifest registries with fallback available", async () => {
    const signed = await signNetworkManifest(testManifest(), SIGNER_SEED, {
      scheme: "substrate-sr25519",
      ss58Format: 42
    });
    const discovered = await discoverRegistryWatchTargets({
      fallbackRegistryAddress: "0x9000000000000000000000000000000000000009",
      manifestUrl: "https://control.example.invalid/v1/network-manifest",
      expectedManifestSigner: signed.signature.signer,
      expectedChainId: 31337,
      fetchImpl: async () =>
        new Response(JSON.stringify(signed), {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        })
    });

    assert.equal(discovered.source, "manifest");
    assert.equal(discovered.signer, signed.signature.signer);
    assert.deepEqual(
      discovered.targets.map((target) => [target.status, target.address, target.fromBlock]),
      [
        ["active", "0x1000000000000000000000000000000000000001", 101],
        ["deprecated", "0x2000000000000000000000000000000000000002", 55]
      ]
    );

    const fallback = await discoverRegistryWatchTargets({
      fallbackRegistryAddress: "0x9000000000000000000000000000000000000009"
    });
    assert.equal(fallback.source, "fallback");
    assert.deepEqual(fallback.targets, [
      {
        address: "0x9000000000000000000000000000000000000009",
        status: "fallback"
      }
    ]);
  });
});

function testManifest(): NetworkManifest {
  return {
    version: 1,
    sequence: 7,
    issuedAt: "2099-04-29T11:58:00.000Z",
    effectiveAt: "2099-04-29T12:00:00.000Z",
    expiresAt: "2099-04-29T12:05:00.000Z",
    chain: {
      name: "local-test",
      chainId: "31337"
    },
    registries: {
      active: [
        {
          status: "active",
          address: "0x1000000000000000000000000000000000000001",
          abiVersion: "ingress-registry-v1",
          fromBlock: 101
        }
      ],
      deprecated: [
        {
          status: "deprecated",
          address: "0x2000000000000000000000000000000000000002",
          fromBlock: 55
        }
      ],
      retired: [
        {
          status: "retired",
          address: "0x3000000000000000000000000000000000000003"
        }
      ]
    },
    quoteSigner: new ethers.Wallet("0x0000000000000000000000000000000000000000000000000000000000000100").address,
    supportedAssets: [
      {
        address: "0x0000000000000000000000000000000000001337",
        symbol: "USDC",
        decimals: 6,
        kind: "erc20"
      }
    ],
    rpc: {
      eth: ["http://127.0.0.1:8545"]
    },
    finality: {
      confirmations: 1,
      mode: "eth-rpc-confirmations"
    },
    catalogs: {
      relays: {
        url: "https://control.example/v1/service-catalogs/relay",
        signer: "5CatalogSigner111111111111111111111111111111111111",
        required: true,
        maxStaleSeconds: 300
      }
    },
    relays: [
      {
        relayId: "relay-a",
        apiBaseUrl: "https://relay-a.example",
        validationReportUrl: "https://relay-a.example/v1/validation-reports",
        weight: 1
      },
      {
        relayId: "relay-b",
        apiBaseUrl: "https://relay-b.example",
        active: false
      }
    ]
  };
}
