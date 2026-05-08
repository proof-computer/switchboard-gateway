import { Keyring } from "@polkadot/keyring";
import { stringToU8a, u8aToHex } from "@polkadot/util";
import { cryptoWaitReady, encodeAddress, signatureVerify } from "@polkadot/util-crypto";
import { ethers } from "ethers";

export type ReportSignatureScheme = "substrate-sr25519" | "eip191-secp256k1";

export interface ReportSignature {
  scheme: ReportSignatureScheme;
  domain: string;
  signer: string;
  signature: string;
  signedAt: string;
  publicKey?: string;
  ss58Format?: number;
}

export interface ReportSigningOptions {
  scheme?: ReportSignatureScheme;
  signedAt?: string;
  ss58Format?: number;
}

export async function signReportPayload(
  signingKey: string,
  domain: string,
  payload: unknown,
  options: ReportSigningOptions | string = {}
): Promise<ReportSignature> {
  const normalizedOptions = typeof options === "string" ? { signedAt: options } : options;
  const scheme = normalizedOptions.scheme ?? inferReportSigningScheme(signingKey);
  const signedAt = normalizedOptions.signedAt ?? new Date().toISOString();
  const message = reportSigningMessage(domain, payload);
  if (scheme === "eip191-secp256k1") {
    const wallet = new ethers.Wallet(signingKey);
    return {
      scheme,
      domain,
      signer: await wallet.getAddress(),
      signature: await wallet.signMessage(message),
      signedAt
    };
  }

  await cryptoWaitReady();
  const keyring = new Keyring({
    type: "sr25519",
    ss58Format: normalizedOptions.ss58Format
  });
  const pair = keyring.addFromUri(signingKey);
  const messageBytes = stringToU8a(message);
  return {
    scheme,
    domain,
    signer: pair.address,
    signature: u8aToHex(pair.sign(messageBytes)),
    signedAt,
    publicKey: u8aToHex(pair.publicKey),
    ss58Format: normalizedOptions.ss58Format
  };
}

export async function verifyReportSignature(payload: unknown, signature: ReportSignature): Promise<string> {
  const message = reportSigningMessage(signature.domain, payload);
  if (signature.scheme === "eip191-secp256k1") {
    return ethers.verifyMessage(message, signature.signature);
  }

  await cryptoWaitReady();
  const result = signatureVerify(stringToU8a(message), signature.signature, signature.publicKey ?? signature.signer);
  if (!result.isValid) {
    throw new Error(`Invalid ${signature.scheme} report signature for ${signature.signer}`);
  }
  if (signature.publicKey) {
    const signer = encodeAddress(result.publicKey, signature.ss58Format);
    if (signer !== signature.signer) {
      throw new Error(`Report signature public key does not match signer ${signature.signer}`);
    }
  }
  return signature.signer;
}

export function reportSigningMessage(domain: string, payload: unknown): string {
  return canonicalJson({
    domain,
    payload
  });
}

export function canonicalJson(value: unknown): string {
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

function inferReportSigningScheme(signingKey: string): ReportSignatureScheme {
  return /^0x[0-9a-fA-F]{64}$/.test(signingKey) ? "eip191-secp256k1" : "substrate-sr25519";
}
