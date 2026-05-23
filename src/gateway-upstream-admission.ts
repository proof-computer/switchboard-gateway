import { ethers } from "ethers";

export const GATEWAY_UPSTREAM_ADMISSION_REQUEST_DOMAIN = "switchboard.gateway-upstream-admission.v1";
export const GATEWAY_UPSTREAM_OBSERVATION_DOMAIN = "switchboard.gateway-upstream-observation.v1";

const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_HALF_N = SECP256K1_N / 2n;

export interface GatewayUpstreamAdmissionPayload {
  intentId: string;
  sessionId: string;
  runtimeSigner: string;
  operatorId: string;
  gatewayId: string;
  processorId: string;
  hostname: string;
  validationHostname?: string;
  upstreamPort: number;
  nonce: string;
  deadline: string | number | bigint;
}

export interface GatewayUpstreamObservationPayload {
  version: 1;
  kind: "switchboard.gateway-upstream-observation";
  admissionId: string;
  request: GatewayUpstreamAdmissionPayload;
  requestDigest: string;
  observedIp: string;
  observedPort?: number;
  observedAt: string;
  expiresAt: string;
  tls: {
    verified: boolean;
    servername: string;
    skipped?: boolean;
    authorizationError?: string;
  };
}

export interface SignedGatewayUpstreamObservation {
  observation: GatewayUpstreamObservationPayload;
  signature: {
    scheme: "substrate-sr25519" | "eip191-secp256k1";
    domain: string;
    signer: string;
    signature: string;
    signedAt: string;
    publicKey?: string;
    ss58Format?: number;
  };
}

export function normalizeGatewayUpstreamAdmissionPayload(
  payload: GatewayUpstreamAdmissionPayload
): GatewayUpstreamAdmissionPayload {
  return {
    intentId: payload.intentId.trim(),
    sessionId: ethers.hexlify(payload.sessionId),
    runtimeSigner: ethers.getAddress(payload.runtimeSigner),
    operatorId: ethers.hexlify(payload.operatorId).toLowerCase(),
    gatewayId: payload.gatewayId.trim(),
    processorId: ethers.hexlify(payload.processorId).toLowerCase(),
    hostname: normalizeAdmissionHostname(payload.hostname),
    validationHostname: payload.validationHostname ? normalizeAdmissionHostname(payload.validationHostname) : undefined,
    upstreamPort: Number(payload.upstreamPort),
    nonce: String(payload.nonce),
    deadline: payload.deadline.toString()
  };
}

export function normalizeGatewayUpstreamObservationPayload(
  payload: GatewayUpstreamObservationPayload
): GatewayUpstreamObservationPayload {
  const request = normalizeGatewayUpstreamAdmissionPayload(payload.request);
  return {
    version: 1,
    kind: "switchboard.gateway-upstream-observation",
    admissionId: payload.admissionId.trim(),
    request,
    requestDigest: ethers.hexlify(payload.requestDigest),
    observedIp: payload.observedIp.trim(),
    observedPort: payload.observedPort,
    observedAt: payload.observedAt,
    expiresAt: payload.expiresAt,
    tls: {
      verified: payload.tls.verified === true,
      servername: normalizeAdmissionHostname(payload.tls.servername),
      skipped: payload.tls.skipped === true ? true : undefined,
      authorizationError: payload.tls.authorizationError
    }
  };
}

export function gatewayUpstreamAdmissionDigest(payload: GatewayUpstreamAdmissionPayload): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalJson({
    domain: GATEWAY_UPSTREAM_ADMISSION_REQUEST_DOMAIN,
    payload: normalizeGatewayUpstreamAdmissionPayload(payload)
  })));
}

export function gatewayUpstreamObservationDigest(payload: GatewayUpstreamObservationPayload): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalJson({
    domain: GATEWAY_UPSTREAM_OBSERVATION_DOMAIN,
    payload: normalizeGatewayUpstreamObservationPayload(payload)
  })));
}

export function gatewayUpstreamAdmissionId(payload: Omit<GatewayUpstreamObservationPayload, "admissionId">): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalJson({
    domain: `${GATEWAY_UPSTREAM_OBSERVATION_DOMAIN}.id`,
    payload: {
      requestDigest: ethers.hexlify(payload.requestDigest),
      observedIp: payload.observedIp.trim(),
      observedPort: payload.observedPort,
      observedAt: payload.observedAt,
      expiresAt: payload.expiresAt
    }
  })));
}

export function recoverGatewayUpstreamAdmissionSigner(
  payload: GatewayUpstreamAdmissionPayload,
  signature: string
): string {
  return ethers.recoverAddress(gatewayUpstreamAdmissionDigest(payload), signature);
}

export function normalizeSecp256k1SignatureForDigest(
  rawSignature: string,
  digest: string,
  expectedAddress: string
): string {
  const bytes = ethers.getBytes(prefixedHex(rawSignature));
  if (bytes.length !== 64 && bytes.length !== 65) {
    throw new Error(`unsupported secp256k1 signature length: ${bytes.length}`);
  }
  const r = ethers.hexlify(bytes.slice(0, 32));
  let s = BigInt(ethers.hexlify(bytes.slice(32, 64)));
  const rawV = bytes.length === 65 ? bytes[64] : undefined;
  const recoveryCandidates = rawV === undefined ? [0, 1] : [rawV >= 27 ? rawV - 27 : rawV];
  const expected = ethers.getAddress(expectedAddress);
  for (const recoveryCandidate of recoveryCandidates) {
    if (recoveryCandidate !== 0 && recoveryCandidate !== 1) continue;
    let v = recoveryCandidate;
    let candidateS = s;
    if (candidateS > SECP256K1_HALF_N) {
      candidateS = SECP256K1_N - candidateS;
      v = 1 - v;
    }
    const signature = ethers.Signature.from({
      r,
      s: ethers.toBeHex(candidateS, 32),
      v: v + 27
    }).serialized;
    if (ethers.getAddress(ethers.recoverAddress(digest, signature)) === expected) {
      return signature;
    }
  }
  throw new Error("secp256k1 signature did not recover to the expected signer");
}

export function prefixedHex(value: string): string {
  return value.startsWith("0x") || value.startsWith("0X") ? value : `0x${value}`;
}

function normalizeAdmissionHostname(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, sortJson(item)])
  );
}
