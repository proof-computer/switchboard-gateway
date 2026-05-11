import { routeHostnames, safeResourceName, type RouteIntent } from "./route-intent.js";
import type { GatewayCapabilityReport } from "./operator-capability.js";

export type GatewayRouteMetrics = NonNullable<GatewayCapabilityReport["gateway"]["routeMetrics"]>;

interface CollectEnvoyRouteMetricsInput {
  routes: RouteIntent[];
  statsUrl: string;
  timeoutMs: number;
  maxRoutes: number;
  now?: Date;
}

type MetricCounters = GatewayRouteMetrics[number]["counters"];

const COUNTER_FIELDS: Array<[keyof MetricCounters, string[]]> = [
  ["downstreamConnectionsTotal", ["downstream_cx_total"]],
  ["downstreamBytesReceivedTotal", ["downstream_cx_rx_bytes_total", "downstream_cx_rx_bytes_buffered_total"]],
  ["downstreamBytesSentTotal", ["downstream_cx_tx_bytes_total", "downstream_cx_tx_bytes_buffered_total"]],
  ["upstreamConnectionsTotal", ["upstream_cx_total"]],
  ["upstreamBytesReceivedTotal", ["upstream_cx_rx_bytes_total"]],
  ["upstreamBytesSentTotal", ["upstream_cx_tx_bytes_total"]]
];

export async function collectEnvoyRouteMetrics(input: CollectEnvoyRouteMetricsInput): Promise<GatewayRouteMetrics> {
  const routes = input.routes.slice(0, Math.max(0, input.maxRoutes));
  if (routes.length === 0) {
    return [];
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), input.timeoutMs).unref();
  try {
    const response = await fetch(input.statsUrl, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`envoy stats request failed: ${response.status} ${response.statusText}`);
    }
    return parseEnvoyRouteMetrics(await response.text(), routes, input.now ?? new Date());
  } finally {
    clearTimeout(timeout);
  }
}

export function parseEnvoyRouteMetrics(stats: string, routes: RouteIntent[], now = new Date()): GatewayRouteMetrics {
  const routeRows = routes.flatMap((route) =>
    routeHostnames(route).serverNames.map((hostname) => ({
      routeId: route.routeId,
      hostname,
      statPrefix: `sni_${safeResourceName(hostname)}`
    }))
  );
  const countersByPrefix = new Map<string, MetricCounters>();
  for (const line of stats.split("\n")) {
    const parsed = parseMetricLine(line);
    if (!parsed) continue;
    for (const row of routeRows) {
      if (!metricMatchesPrefix(parsed, row.statPrefix)) continue;
      const counters = countersByPrefix.get(row.statPrefix) ?? {};
      for (const [field, suffixes] of COUNTER_FIELDS) {
        if (suffixes.some((suffix) => parsed.name.endsWith(suffix))) {
          counters[field] = parsed.value;
        }
      }
      countersByPrefix.set(row.statPrefix, counters);
    }
  }
  const sampledAt = now.toISOString();
  return routeRows
    .map((row) => ({
      ...row,
      sampledAt,
      counters: countersByPrefix.get(row.statPrefix) ?? {}
    }))
    .filter((row) => Object.keys(row.counters).length > 0);
}

function parseMetricLine(line: string): { name: string; labels: Record<string, string>; value: string } | undefined {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return undefined;
  }

  const prometheus = trimmed.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9]+)(?:\.[0-9]+)?(?:\s+\d+)?$/);
  if (prometheus) {
    return {
      name: prometheus[1],
      labels: parsePrometheusLabels(prometheus[2]),
      value: prometheus[3]
    };
  }

  const text = trimmed.match(/^([A-Za-z0-9_.:-]+):\s*([0-9]+)$/);
  if (text) {
    return {
      name: text[1],
      labels: {},
      value: text[2]
    };
  }

  return undefined;
}

function parsePrometheusLabels(raw: string | undefined): Record<string, string> {
  if (!raw) {
    return {};
  }
  const labels: Record<string, string> = {};
  for (const part of raw.split(",")) {
    const [key, value] = part.split("=", 2);
    if (!key || !value) continue;
    labels[key.trim()] = value.trim().replace(/^"|"$/g, "");
  }
  return labels;
}

function metricMatchesPrefix(metric: { name: string; labels: Record<string, string> }, statPrefix: string): boolean {
  if (metric.name.includes(statPrefix)) {
    return true;
  }
  return Object.values(metric.labels).some((value) => value === statPrefix || value.includes(statPrefix));
}
