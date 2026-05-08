import { ethers } from "ethers";

import {
  verifySignedNetworkManifest,
  watchedManifestRegistries,
  type NetworkManifest
} from "./network-manifest.js";

export interface RegistryWatchTarget {
  address: string;
  status: "active" | "deprecated" | "fallback";
  chainId?: string;
  chainName?: string;
  fromBlock?: number;
  manifestSequence?: number;
  manifestSigner?: string;
}

export interface RegistryDiscoveryResult {
  source: "fallback" | "manifest";
  targets: RegistryWatchTarget[];
  manifest?: NetworkManifest;
  signer?: string;
}

export interface RegistryDiscoveryConfig {
  fallbackRegistryAddress: string;
  manifestUrl?: string;
  expectedManifestSigner?: string;
  allowUnpinnedManifestSigner?: boolean;
  expectedChainId?: string | number | bigint;
  fetchImpl?: typeof fetch;
}

export async function discoverRegistryWatchTargets(config: RegistryDiscoveryConfig): Promise<RegistryDiscoveryResult> {
  if (!config.manifestUrl) {
    return fallbackResult(config.fallbackRegistryAddress);
  }
  if (!config.expectedManifestSigner && !config.allowUnpinnedManifestSigner) {
    throw new Error("PROOF_NETWORK_MANIFEST_SIGNER is required when PROOF_NETWORK_MANIFEST_URL is configured");
  }

  const fetchImpl = config.fetchImpl ?? fetch;
  const response = await fetchImpl(config.manifestUrl, {
    headers: {
      accept: "application/json"
    }
  });
  if (!response.ok) {
    throw new Error(`network manifest fetch failed: ${response.status} ${await response.text()}`);
  }

  const verified = await verifySignedNetworkManifest(await response.json(), {
    expectedSigner: config.expectedManifestSigner
  });
  const expectedChainId = config.expectedChainId?.toString();
  if (expectedChainId && verified.manifest.chain.chainId !== expectedChainId) {
    throw new Error(`network manifest chain ${verified.manifest.chain.chainId} does not match expected ${expectedChainId}`);
  }

  const targets = watchedManifestRegistries(verified.manifest).map((registry) => ({
    address: ethers.getAddress(registry.address),
    status: registry.status as "active" | "deprecated",
    chainId: verified.manifest.chain.chainId,
    chainName: verified.manifest.chain.name,
    fromBlock: registry.fromBlock,
    manifestSequence: verified.manifest.sequence,
    manifestSigner: verified.signer
  }));
  if (targets.length === 0) {
    throw new Error("network manifest did not include active or deprecated registries");
  }

  return {
    source: "manifest",
    targets,
    manifest: verified.manifest,
    signer: verified.signer
  };
}

export function fallbackResult(registryAddress: string): RegistryDiscoveryResult {
  return {
    source: "fallback",
    targets: [
      {
        address: ethers.getAddress(registryAddress),
        status: "fallback"
      }
    ]
  };
}
