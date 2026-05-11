import { decodeAddress } from "@polkadot/util-crypto";
import { ethers } from "ethers";
import { isIP } from "node:net";
import { z } from "zod";

import {
  signReportPayload,
  verifyReportSignature,
  type ReportSignature,
  type ReportSignatureScheme
} from "./report-signing.js";

export const OPERATOR_CAPABILITY_REPORT_DOMAIN = "switchboard.operator.capability.v1";
export const LEGACY_OPERATOR_CAPABILITY_REPORT_DOMAIN = "proof-ingress.operator.capability.v1";

const ACCEPTED_OPERATOR_CAPABILITY_REPORT_DOMAINS = [
  OPERATOR_CAPABILITY_REPORT_DOMAIN,
  LEGACY_OPERATOR_CAPABILITY_REPORT_DOMAIN
] as const;

const hex32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);

const reportSignatureSchema = z.object({
  scheme: z.enum(["substrate-sr25519", "eip191-secp256k1"]),
  domain: z.string().min(1),
  signer: z.string().min(1),
  signature: z.string().min(1),
  signedAt: z.string().min(1),
  publicKey: z.string().regex(/^0x[0-9a-fA-F]+$/).optional(),
  ss58Format: z.number().int().nonnegative().optional()
});

const processorScopeSchema = z.object({
  kind: z.enum(["explicit", "manager"]),
  managerId: z.string().min(1).optional(),
  processors: z.array(z.string().min(1)).optional(),
  includeProcessors: z.array(z.string().min(1)).optional(),
  excludeProcessors: z.array(z.string().min(1)).optional()
});

const operatorEconomicsSchema = z.object({
  floorPricePerMinute: z.string().regex(/^[0-9]+$/).optional(),
  payoutAddress: address.optional(),
  supportedAssets: z.array(address).optional()
}).optional();

const uintString = z.string().regex(/^[0-9]+$/);

const gatewayRouteMetricsSchema = z.object({
  routeId: z.string().min(1).max(160).optional(),
  hostname: z.string().min(1).max(253),
  statPrefix: z.string().min(1).max(253).optional(),
  sampledAt: z.string().min(1),
  counters: z.object({
    downstreamConnectionsTotal: uintString.optional(),
    downstreamBytesReceivedTotal: uintString.optional(),
    downstreamBytesSentTotal: uintString.optional(),
    upstreamConnectionsTotal: uintString.optional(),
    upstreamBytesReceivedTotal: uintString.optional(),
    upstreamBytesSentTotal: uintString.optional()
  }).default({})
});

export const gatewayCapabilityReportSchema = z.object({
  version: z.literal(1),
  kind: z.enum(["switchboard.operator.capability", "proof-ingress.operator.capability"]),
  reportId: z.string().min(1).max(160),
  reportedAt: z.string().min(1),
  expiresAt: z.string().min(1),
  operator: z.object({
    operatorId: hex32,
    gatewayId: z.string().min(1).max(160),
    managerIds: z.array(z.string().min(1)).optional()
  }),
  gateway: z.object({
    publicAddresses: z.array(z.string().min(1)).default([]),
    publicAddressMode: z.enum(["static", "auto"]).optional(),
    publicAddressSource: z.string().min(1).optional(),
    publicAddressObservedAt: z.string().min(1).optional(),
    publicAddressLastChangedAt: z.string().min(1).optional(),
    publicAddressProbeError: z.string().min(1).optional(),
    validationHostname: z.string().min(1).max(253).optional(),
    routeStateUrl: z.string().url().optional(),
    routeIntentUrl: z.string().url().optional(),
    activeRouteCount: z.number().int().nonnegative(),
    routeCapacity: z.number().int().nonnegative(),
    softwareVersion: z.string().min(1).optional(),
    supportedClasses: z.array(z.string().min(1)).default([]),
    routeMetrics: z.array(gatewayRouteMetricsSchema).max(500).optional()
  }),
  processorScopes: z.array(processorScopeSchema).default([]),
  economics: operatorEconomicsSchema
});

export const signedGatewayCapabilityReportSchema = z.object({
  report: gatewayCapabilityReportSchema,
  signature: reportSignatureSchema
});

export const operatorProfileSchema = z.object({
  operatorId: hex32,
  status: z.enum(["active", "draining", "inactive"]).default("active"),
  displayName: z.string().min(1).optional(),
  payoutAddress: address.optional(),
  reportSigners: z.array(z.string().min(1)).default([]),
  gatewayIds: z.array(z.string().min(1)).default([]),
  managerIds: z.array(z.string().min(1)).default([]),
  processorIds: z.array(hex32).default([]),
  routeStateUrl: z.string().url().optional(),
  routeIntentUrl: z.string().url().optional(),
  routeIntentTokenEnv: z.string().regex(/^[A-Z_][A-Z0-9_]*$/).optional(),
  maxActiveSessions: z.number().int().nonnegative().optional(),
  floorPricePerMinute: z.string().regex(/^[0-9]+$/).optional()
}).superRefine((profile, ctx) => {
  if (profile.status === "active" && profile.reportSigners.length === 0) {
    ctx.addIssue({
      code: "custom",
      path: ["reportSigners"],
      message: "Active operator profiles require at least one report signer"
    });
  }
});

export type ProcessorScope = z.output<typeof processorScopeSchema>;
export type GatewayCapabilityReport = z.output<typeof gatewayCapabilityReportSchema>;
export type SignedGatewayCapabilityReport = z.output<typeof signedGatewayCapabilityReportSchema>;
export type OperatorProfile = z.output<typeof operatorProfileSchema>;

export interface StoredGatewayCapabilityReport {
  receivedAt: string;
  signer: string;
  report: GatewayCapabilityReport;
  signature: ReportSignature;
}

export interface SignGatewayCapabilityReportOptions {
  scheme?: ReportSignatureScheme;
  ss58Format?: number;
  signedAt?: string;
}

export interface VerifyGatewayCapabilityReportOptions {
  now?: Date;
  allowExpired?: boolean;
}

export interface OperatorCapabilityCandidate {
  operatorId: string;
  gatewayId: string;
  processorId: string;
  processorAddress?: string;
  managerId?: string;
  reportId: string;
  reportExpiresAt: string;
  reportSigner: string;
  publicAddresses: string[];
  activeRouteCount: number;
  routeCapacity: number;
  routeStateUrl?: string;
  routeIntentUrl?: string;
  routeIntentTokenEnv?: string;
  selectionReasons: string[];
}

export interface SelectOperatorCapabilityCandidateInput {
  profiles: OperatorProfile[];
  reports: StoredGatewayCapabilityReport[];
  now?: Date;
  operatorId?: string;
  processorId?: string;
  requireRouteStateUrl?: boolean;
  requireRouteIntentSink?: boolean;
}

export async function signGatewayCapabilityReport(
  report: GatewayCapabilityReport,
  signingKey: string,
  options: SignGatewayCapabilityReportOptions = {}
): Promise<SignedGatewayCapabilityReport> {
  const normalized = normalizeGatewayCapabilityReport(report);
  return {
    report: normalized,
    signature: await signReportPayload(signingKey, OPERATOR_CAPABILITY_REPORT_DOMAIN, normalized, {
      scheme: options.scheme,
      ss58Format: options.ss58Format,
      signedAt: options.signedAt
    })
  };
}

export async function verifySignedGatewayCapabilityReport(
  input: unknown,
  options: VerifyGatewayCapabilityReportOptions = {}
): Promise<{ report: GatewayCapabilityReport; signer: string; signature: ReportSignature }> {
  const signed = signedGatewayCapabilityReportSchema.parse(input);
  const report = normalizeGatewayCapabilityReport(signed.report);
  if (!ACCEPTED_OPERATOR_CAPABILITY_REPORT_DOMAINS.includes(signed.signature.domain as typeof ACCEPTED_OPERATOR_CAPABILITY_REPORT_DOMAINS[number])) {
    throw new Error(`Unexpected operator capability signature domain ${signed.signature.domain}`);
  }
  if (!options.allowExpired && capabilityReportExpired(report, options.now)) {
    throw new Error("Operator capability report is expired");
  }
  const signer = await verifyReportSignature(report, signed.signature);
  if (!sameSigner(signer, signed.signature.signer)) {
    throw new Error(`Operator capability signer ${signer} does not match claimed signer ${signed.signature.signer}`);
  }
  return {
    report,
    signer,
    signature: signed.signature
  };
}

export function parseOperatorProfiles(input: unknown): OperatorProfile[] {
  return z.array(operatorProfileSchema).parse(input).map(normalizeOperatorProfile);
}

export function normalizeOperatorProfile(profile: OperatorProfile): OperatorProfile {
  return {
    ...profile,
    operatorId: profile.operatorId.toLowerCase(),
    payoutAddress: profile.payoutAddress ? ethers.getAddress(profile.payoutAddress) : undefined,
    processorIds: profile.processorIds.map((processorId) => processorId.toLowerCase())
  };
}

export function normalizeGatewayCapabilityReport(report: GatewayCapabilityReport): GatewayCapabilityReport {
  return {
    ...report,
    operator: {
      ...report.operator,
      operatorId: report.operator.operatorId.toLowerCase(),
      managerIds: uniqueStrings(report.operator.managerIds ?? [])
    },
    gateway: {
      ...report.gateway,
      publicAddresses: uniqueStrings(report.gateway.publicAddresses ?? []),
      supportedClasses: uniqueStrings(report.gateway.supportedClasses ?? [])
    },
    processorScopes: report.processorScopes.map((scope) => ({
      ...scope,
      processors: uniqueStrings(scope.processors ?? []),
      includeProcessors: uniqueStrings(scope.includeProcessors ?? []),
      excludeProcessors: uniqueStrings(scope.excludeProcessors ?? [])
    })),
    economics: report.economics
      ? {
          ...report.economics,
          payoutAddress: report.economics.payoutAddress ? ethers.getAddress(report.economics.payoutAddress) : undefined,
          supportedAssets: report.economics.supportedAssets?.map((asset) => ethers.getAddress(asset))
        }
      : undefined
  };
}

export function capabilityReportExpired(report: GatewayCapabilityReport, now = new Date()): boolean {
  return Date.parse(report.expiresAt) <= now.getTime();
}

export function selectDnsEligiblePublicIpv4(publicAddresses: string[]): string {
  const ipv4 = uniqueStrings(publicAddresses.map((item) => item.trim()).filter((item) => isIP(item) === 4));
  if (ipv4.length === 0) {
    throw new Error("dns_target_unavailable");
  }
  if (ipv4.length > 1) {
    throw new Error(`dns_target_ambiguous:${ipv4.join(",")}`);
  }
  const selected = ipv4[0];
  if (!publicIpv4Address(selected)) {
    throw new Error(`dns_target_not_public:${selected}`);
  }
  return selected;
}

export function publicIpv4Address(value: string): boolean {
  if (isIP(value) !== 4) {
    return false;
  }
  const octets = value.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b, c, d] = octets as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  if (a >= 224) return false;
  if (a === 255 && b === 255 && c === 255 && d === 255) return false;
  return true;
}

export function reportSignerAllowedByProfile(profile: OperatorProfile, signer: string): boolean {
  return profile.reportSigners.length > 0 && profile.reportSigners.some((allowed) => sameSigner(allowed, signer));
}

export function operatorProfileRouteIntentUrlForGateway(profile: OperatorProfile | undefined, gatewayId: string): string | undefined {
  if (!profile?.routeIntentUrl) {
    return undefined;
  }
  if (profile.gatewayIds.length === 1 && profile.gatewayIds[0] === gatewayId) {
    return profile.routeIntentUrl;
  }
  return undefined;
}

export function operatorProfileRouteStateUrlForGateway(profile: OperatorProfile | undefined, gatewayId: string): string | undefined {
  if (!profile?.routeStateUrl) {
    return undefined;
  }
  if (profile.gatewayIds.length === 1 && profile.gatewayIds[0] === gatewayId) {
    return profile.routeStateUrl;
  }
  return undefined;
}

export function operatorCapabilityRouteIntentUrl(
  profile: OperatorProfile | undefined,
  report: GatewayCapabilityReport
): string | undefined {
  return report.gateway.routeIntentUrl ?? operatorProfileRouteIntentUrlForGateway(profile, report.operator.gatewayId);
}

export function operatorCapabilityRouteStateUrl(
  profile: OperatorProfile | undefined,
  report: GatewayCapabilityReport
): string | undefined {
  return report.gateway.routeStateUrl ?? operatorProfileRouteStateUrlForGateway(profile, report.operator.gatewayId);
}

export function selectOperatorCapabilityCandidate(
  input: SelectOperatorCapabilityCandidateInput
): OperatorCapabilityCandidate | undefined {
  const now = input.now ?? new Date();
  const requestedOperatorId = input.operatorId?.toLowerCase();
  const requestedProcessorId = input.processorId?.toLowerCase();
  const profiles = new Map(input.profiles.map((profile) => [profile.operatorId.toLowerCase(), profile]));
  const reports = [...input.reports].sort((left, right) => {
    const reportedDelta = Date.parse(right.report.reportedAt) - Date.parse(left.report.reportedAt);
    if (reportedDelta !== 0) return reportedDelta;
    return Date.parse(right.receivedAt) - Date.parse(left.receivedAt);
  });
  const candidates: Array<{
    stored: StoredGatewayCapabilityReport;
    profile: OperatorProfile;
    operatorId: string;
    gatewayKey: string;
    routeStateUrl?: string;
    routeIntentUrl?: string;
    processors: ReturnType<typeof expandedReportProcessors>;
  }> = [];

  for (const stored of reports) {
    const report = stored.report;
    const operatorId = report.operator.operatorId.toLowerCase();
    const profile = profiles.get(operatorId);
    if (!profile || profile.status !== "active") {
      continue;
    }
    if (requestedOperatorId && operatorId !== requestedOperatorId) {
      continue;
    }
    if (capabilityReportExpired(report, now)) {
      continue;
    }
    if (!reportSignerAllowedByProfile(profile, stored.signer)) {
      continue;
    }
    if (profile.gatewayIds.length > 0 && !profile.gatewayIds.includes(report.operator.gatewayId)) {
      continue;
    }
    if (report.gateway.routeCapacity <= 0 || report.gateway.activeRouteCount >= report.gateway.routeCapacity) {
      continue;
    }
    const routeStateUrl = operatorCapabilityRouteStateUrl(profile, report);
    if (input.requireRouteStateUrl && !routeStateUrl) {
      continue;
    }
    const routeIntentUrl = operatorCapabilityRouteIntentUrl(profile, report);
    if (input.requireRouteIntentSink && !routeIntentUrl) {
      continue;
    }

    const processors = expandedReportProcessors(report).filter((processor) => {
      if (requestedProcessorId && processor.processorId !== requestedProcessorId) return false;
      if (profile.processorIds.length > 0 && !profile.processorIds.includes(processor.processorId)) return false;
      if (profile.managerIds.length > 0 && processor.managerId && !profile.managerIds.includes(processor.managerId)) return false;
      return true;
    });
    if (processors.length === 0) {
      continue;
    }
    candidates.push({
      stored,
      profile,
      operatorId,
      gatewayKey: `${operatorId}:${report.operator.gatewayId}`,
      routeStateUrl,
      routeIntentUrl,
      processors
    });
  }

  const publicAddressFingerprints = new Map<string, Set<string>>();
  for (const candidate of candidates) {
    const fingerprints = publicAddressFingerprints.get(candidate.gatewayKey) ?? new Set<string>();
    fingerprints.add(publicAddressFingerprint(candidate.stored.report.gateway.publicAddresses));
    publicAddressFingerprints.set(candidate.gatewayKey, fingerprints);
  }
  const ambiguousGatewayKeys = new Set(
    [...publicAddressFingerprints.entries()]
      .filter(([, fingerprints]) => fingerprints.size > 1)
      .map(([gatewayKey]) => gatewayKey)
  );

  for (const candidate of candidates) {
    if (ambiguousGatewayKeys.has(candidate.gatewayKey)) {
      continue;
    }
    const report = candidate.stored.report;
    const processor = candidate.processors[0];
    return {
      operatorId: candidate.operatorId,
      gatewayId: report.operator.gatewayId,
      processorId: processor.processorId,
      processorAddress: processor.address,
      managerId: processor.managerId,
      reportId: report.reportId,
      reportExpiresAt: report.expiresAt,
      reportSigner: candidate.stored.signer,
      publicAddresses: report.gateway.publicAddresses,
      activeRouteCount: report.gateway.activeRouteCount,
      routeCapacity: report.gateway.routeCapacity,
      routeStateUrl: candidate.routeStateUrl,
      routeIntentUrl: candidate.routeIntentUrl,
      routeIntentTokenEnv: candidate.profile.routeIntentTokenEnv,
      selectionReasons: [
        "operator-profile-active",
        "capability-report-fresh",
        "gateway-capacity-available",
        ...(input.requireRouteStateUrl ? ["route-state-polling"] : []),
        ...(input.requireRouteIntentSink ? ["route-intent-sink"] : []),
        processor.managerId ? "manager-scoped-processor" : "explicit-processor"
      ]
    };
  }

  return undefined;
}

function publicAddressFingerprint(publicAddresses: string[]): string {
  return uniqueStrings(publicAddresses.map((item) => item.trim()).filter(Boolean)).sort().join(",");
}

export function expandedReportProcessors(report: GatewayCapabilityReport): Array<{
  processorId: string;
  address?: string;
  managerId?: string;
}> {
  const result: Array<{ processorId: string; address?: string; managerId?: string }> = [];
  const seen = new Set<string>();
  for (const scope of report.processorScopes) {
    const excluded = new Set((scope.excludeProcessors ?? []).map(processorRefToId).filter((item): item is string => Boolean(item)));
    const rawProcessors = scope.kind === "explicit" ? scope.processors ?? [] : scope.processors ?? scope.includeProcessors ?? [];
    for (const raw of rawProcessors) {
      const processorId = processorRefToId(raw);
      if (!processorId || excluded.has(processorId) || seen.has(processorId)) {
        continue;
      }
      seen.add(processorId);
      result.push({
        processorId,
        address: /^0x[0-9a-fA-F]{64}$/.test(raw) ? undefined : raw,
        managerId: scope.managerId
      });
    }
  }
  return result;
}

export function processorRefToId(value: string): string | undefined {
  if (/^0x[0-9a-fA-F]{64}$/.test(value)) {
    return value.toLowerCase();
  }
  try {
    return `0x${Buffer.from(decodeAddress(value)).toString("hex")}`.toLowerCase();
  } catch {
    return undefined;
  }
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))];
}

function sameSigner(left: string, right: string): boolean {
  if (/^0x[0-9a-fA-F]+$/.test(left) && /^0x[0-9a-fA-F]+$/.test(right)) {
    return left.toLowerCase() === right.toLowerCase();
  }
  return left === right;
}
