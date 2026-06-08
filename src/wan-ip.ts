import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { URL } from "node:url";

import { publicIpv4Address } from "./operator-capability.js";

export type OperatorPublicAddressMode = "static" | "auto";

export interface WanIpProbeOptions {
  url: string;
  timeoutMs?: number;
  requestText?: (url: string, timeoutMs: number) => Promise<string>;
}

export function normalizeOperatorPublicAddressMode(
  value: string | undefined,
  staticAddresses: string[]
): OperatorPublicAddressMode {
  const normalized = value?.trim().toLowerCase();
  if (normalized === "auto" || normalized === "static") {
    return normalized;
  }
  return staticAddresses.length > 0 ? "static" : "auto";
}

export async function fetchWanIpv4(options: WanIpProbeOptions): Promise<string> {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const raw = await (options.requestText ?? requestTextIpv4Only)(options.url, timeoutMs);
  return normalizeWanIpv4Response(raw);
}

export function normalizeWanIpv4Response(raw: string): string {
  const ip = raw.trim().split(/\s+/)[0] ?? "";
  if (!publicIpv4Address(ip)) {
    throw new Error(ip ? `WAN IP probe returned non-public IPv4 address ${ip}` : "WAN IP probe returned an empty response");
  }
  return ip;
}

async function requestTextIpv4Only(urlValue: string, timeoutMs: number): Promise<string> {
  const url = new URL(urlValue);
  const request = url.protocol === "http:" ? httpRequest : httpsRequest;
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Unsupported WAN IP URL protocol ${url.protocol}`);
  }

  return await new Promise<string>((resolve, reject) => {
    const req = request(
      url,
      {
        family: 4,
        headers: {
          "user-agent": "switchboard-gateway-agent/1"
        }
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 256) {
            req.destroy(new Error("WAN IP probe response exceeded 256 bytes"));
          }
        });
        response.on("end", () => {
          if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`WAN IP probe failed with HTTP ${response.statusCode ?? "unknown"}`));
            return;
          }
          resolve(body);
        });
      }
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`WAN IP probe timed out after ${timeoutMs}ms`));
    });
    req.on("error", reject);
    req.end();
  });
}
