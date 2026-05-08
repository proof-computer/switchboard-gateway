import { ethers } from "ethers";
import { z } from "zod";

import {
  signReportPayload,
  verifyReportSignature,
  type ReportSignature,
  type ReportSignatureScheme
} from "./report-signing.js";

export const NETWORK_MANIFEST_DOMAIN = "switchboard.network-manifest.v1";
export const LEGACY_NETWORK_MANIFEST_DOMAIN = "proof-ingress.network-manifest.v1";

const ACCEPTED_NETWORK_MANIFEST_DOMAINS = [NETWORK_MANIFEST_DOMAIN, LEGACY_NETWORK_MANIFEST_DOMAIN] as const;

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
const uintStringSchema = z.union([z.string().regex(/^[0-9]+$/), z.number().int().nonnegative()]).transform((value) => value.toString());
const registryStatusSchema = z.enum(["active", "deprecated", "retired"]);

const registrySchema = z.object({
  status: registryStatusSchema,
  address: addressSchema,
  label: z.string().min(1).optional(),
  abiVersion: z.string().min(1).optional(),
  buildHash: z.string().min(1).optional(),
  bytecodeHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
  fromBlock: z.number().int().nonnegative().optional(),
  effectiveAt: z.string().min(1).optional(),
  deprecatedAt: z.string().min(1).optional(),
  sunsetAt: z.string().min(1).optional()
});

const assetSchema = z.object({
  address: addressSchema,
  symbol: z.string().min(1).optional(),
  decimals: z.number().int().nonnegative().optional(),
  kind: z.enum(["native", "erc20"]).optional()
});

const relaySchema = z.object({
  relayId: z.string().min(1),
  apiBaseUrl: z.string().min(1).optional(),
  validationReportUrl: z.string().min(1).optional(),
  controlPlaneUrl: z.string().min(1).optional(),
  operatorId: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
  weight: z.number().int().positive().optional(),
  active: z.boolean().optional(),
  metadata: z.record(z.string(), z.unknown()).optional()
});

const catalogRefSchema = z.object({
  url: z.string().min(1),
  signer: z.string().min(1).optional(),
  required: z.boolean().optional(),
  maxStaleSeconds: z.number().int().nonnegative().optional(),
  digest: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
  metadata: z.record(z.string(), z.unknown()).optional()
});

export const networkManifestSchema = z.object({
  version: z.literal(1),
  sequence: z.number().int().nonnegative(),
  issuedAt: z.string().min(1),
  effectiveAt: z.string().min(1).optional(),
  expiresAt: z.string().min(1).optional(),
  chain: z.object({
    name: z.string().min(1).optional(),
    chainId: uintStringSchema
  }),
  registries: z.object({
    active: z.array(registrySchema).default([]),
    deprecated: z.array(registrySchema).default([]),
    retired: z.array(registrySchema).default([])
  }),
  quoteSigner: addressSchema.optional(),
  supportedAssets: z.array(assetSchema).optional(),
  rpc: z
    .object({
      eth: z.array(z.string().min(1)).optional(),
      substrate: z.array(z.string().min(1)).optional()
    })
    .optional(),
  explorer: z
    .object({
      blockscoutUrl: z.string().min(1).optional(),
      proofExplorerUrl: z.string().min(1).optional()
    })
    .optional(),
  controlPlane: z
    .object({
      apiBaseUrl: z.string().min(1).optional(),
      apiVersion: z.string().min(1).optional()
    })
    .optional(),
  catalogs: z.record(z.string(), catalogRefSchema).optional(),
  validators: z
    .object({
      launch: z
        .object({
          enabled: z.boolean().optional(),
          scriptIpfs: z.string().min(1).optional(),
          scriptHash: z.string().min(1).optional(),
          targetNetwork: z.enum(["mainnet", "canary"]).optional(),
          maxActivePerDeployer: z.number().int().positive().optional(),
          relaunchGraceSeconds: z.number().int().nonnegative().optional()
        })
        .optional()
    })
    .optional(),
  relays: z.array(relaySchema).optional(),
  finality: z
    .object({
      confirmations: z.number().int().nonnegative().optional(),
      mode: z.string().min(1).optional()
    })
    .optional()
});

export const signedNetworkManifestSchema = z.object({
  manifest: networkManifestSchema,
  signature: z.object({
    scheme: z.enum(["substrate-sr25519", "eip191-secp256k1"]),
    domain: z.string().min(1),
    signer: z.string().min(1),
    signature: z.string().min(1),
    signedAt: z.string().min(1),
    publicKey: z.string().regex(/^0x[0-9a-fA-F]+$/).optional(),
    ss58Format: z.number().int().nonnegative().optional()
  })
});

export type NetworkManifest = z.output<typeof networkManifestSchema>;
export type SignedNetworkManifest = z.output<typeof signedNetworkManifestSchema>;
export type NetworkManifestRegistry = NetworkManifest["registries"]["active"][number];
export type NetworkManifestCatalogRef = NonNullable<NetworkManifest["catalogs"]>[string];

export interface SignNetworkManifestOptions {
  scheme?: ReportSignatureScheme;
  ss58Format?: number;
  signedAt?: string;
}

export interface VerifyNetworkManifestOptions {
  expectedSigner?: string;
  now?: Date;
  allowExpired?: boolean;
}

export async function signNetworkManifest(
  manifest: NetworkManifest,
  signingKey: string,
  options: SignNetworkManifestOptions = {}
): Promise<SignedNetworkManifest> {
  const normalized = normalizeNetworkManifest(manifest);
  return {
    manifest: normalized,
    signature: await signReportPayload(signingKey, NETWORK_MANIFEST_DOMAIN, normalized, {
      scheme: options.scheme,
      ss58Format: options.ss58Format,
      signedAt: options.signedAt
    })
  };
}

export async function verifySignedNetworkManifest(
  input: unknown,
  options: VerifyNetworkManifestOptions = {}
): Promise<{ manifest: NetworkManifest; signer: string; signature: ReportSignature }> {
  const signed = parseSignedNetworkManifest(input);
  if (!ACCEPTED_NETWORK_MANIFEST_DOMAINS.includes(signed.signature.domain as typeof ACCEPTED_NETWORK_MANIFEST_DOMAINS[number])) {
    throw new Error(`Unexpected network manifest signature domain ${signed.signature.domain}`);
  }
  if (!options.allowExpired && manifestExpired(signed.manifest, options.now)) {
    throw new Error("Network manifest is expired");
  }
  const signer = await verifyReportSignature(signed.manifest, signed.signature);
  if (options.expectedSigner && !sameSigner(signer, options.expectedSigner)) {
    throw new Error(`Network manifest signer ${signer} does not match expected signer ${options.expectedSigner}`);
  }

  return {
    manifest: signed.manifest,
    signer,
    signature: signed.signature
  };
}

export function parseNetworkManifest(input: unknown): NetworkManifest {
  return normalizeNetworkManifest(networkManifestSchema.parse(input));
}

export function parseSignedNetworkManifest(input: unknown): SignedNetworkManifest {
  const signed = signedNetworkManifestSchema.parse(input);
  return {
    manifest: normalizeNetworkManifest(signed.manifest),
    signature: signed.signature
  };
}

export function watchedManifestRegistries(manifest: NetworkManifest): NetworkManifestRegistry[] {
  const normalized = normalizeNetworkManifest(manifest);
  return [...normalized.registries.active, ...normalized.registries.deprecated];
}

export function manifestExpired(manifest: NetworkManifest, now = new Date()): boolean {
  return Boolean(manifest.expiresAt && Date.parse(manifest.expiresAt) <= now.getTime());
}

export function normalizeNetworkManifest(manifest: NetworkManifest): NetworkManifest {
  return {
    ...manifest,
    quoteSigner: manifest.quoteSigner ? ethers.getAddress(manifest.quoteSigner) : undefined,
    registries: {
      active: normalizeRegistries(manifest.registries.active, "active"),
      deprecated: normalizeRegistries(manifest.registries.deprecated, "deprecated"),
      retired: normalizeRegistries(manifest.registries.retired, "retired")
    },
    supportedAssets: manifest.supportedAssets?.map((asset) => ({
      ...asset,
      address: ethers.getAddress(asset.address)
    })),
    catalogs: manifest.catalogs ? normalizeCatalogRefs(manifest.catalogs) : undefined,
    relays: manifest.relays?.map((relay) => ({
      ...relay,
      active: relay.active ?? true
    }))
  };
}

function normalizeRegistries(
  registries: NetworkManifestRegistry[],
  status: NetworkManifestRegistry["status"]
): NetworkManifestRegistry[] {
  return registries.map((registry) => ({
    ...registry,
    status,
    address: ethers.getAddress(registry.address)
  }));
}

function normalizeCatalogRefs(catalogs: NonNullable<NetworkManifest["catalogs"]>): NonNullable<NetworkManifest["catalogs"]> {
  return Object.fromEntries(
    Object.entries(catalogs).map(([key, ref]) => [
      key,
      {
        ...ref,
        url: normalizeUrl(ref.url)
      }
    ])
  );
}

function normalizeUrl(value: string): string {
  const url = new URL(value);
  url.hash = "";
  return url.toString();
}

function sameSigner(left: string, right: string): boolean {
  if (/^0x[0-9a-fA-F]+$/.test(left) && /^0x[0-9a-fA-F]+$/.test(right)) {
    return left.toLowerCase() === right.toLowerCase();
  }
  return left === right;
}
