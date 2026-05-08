import { promises as fs } from "node:fs";
import { hostname as osHostname } from "node:os";
import path from "node:path";

import { signReportPayload, type ReportSignature, type ReportSignatureScheme } from "./report-signing.js";
import { normalizeHostname, routeHostnames, routeIsActive, routeMatchesHostname, type HostnameRole, type RouteIntent } from "./route-intent.js";

export interface RouteStatusReportInput {
  routes: RouteIntent[];
  xdsDir: string;
  configVersion: string;
  listenerName: string;
  listenerAddress: string;
  listenerPort: number;
  operatorId?: string;
  gatewayId?: string;
  signingKey?: string;
  signingScheme?: ReportSignatureScheme;
  signingSs58Format?: number;
  /** @deprecated Use signingKey with signingScheme instead. */
  signingPrivateKey?: string;
  filters?: RouteStatusReportFilters;
  now?: Date;
}

export interface RouteStatusReportFilters {
  routeId?: string;
  sessionId?: string;
  hostname?: string;
}

export interface RouteStatusReport {
  version: 1;
  kind: "proof-ingress.operator.route-status";
  reportId: string;
  reportedAt: string;
  nowUnixSeconds: number;
  operator: {
    operatorId?: string;
    gatewayId: string;
    host: string;
  };
  listener: {
    name: string;
    address: string;
    port: number;
  };
  configVersion: string;
  filters?: RouteStatusReportFilters;
  summary: {
    routeCount: number;
    activeRouteCount: number;
    reportedRouteCount: number;
    configuredRouteCount: number;
    expiredRouteCount: number;
  };
  xds: {
    ok: boolean;
    dir: string;
    version?: string;
    generatedAt?: string;
    listenerPresent: boolean;
    files: Record<string, FileStatus>;
    error?: string;
  };
  routes: RouteStatus[];
  signature?: ReportSignature;
}

export interface RouteStatus {
  routeId: string;
  sessionId: string;
  hostname: string;
  publicHostname: string;
  validationHostname?: string;
  customerHostnames: string[];
  hostnameRole: HostnameRole;
  hostnames: {
    primary: string;
    public: string;
    validation?: string;
    customer: string[];
    serverNames: string[];
  };
  upstream: {
    host: string;
    port: number;
  };
  expiresAt: number;
  expiresAtIso: string;
  secondsUntilExpiry: number;
  source?: Record<string, unknown>;
  observed: {
    stored: boolean;
    active: boolean;
    expired: boolean;
    xdsRendered: boolean;
    listenerPresent: boolean;
    configured: boolean;
  };
}

interface FileStatus {
  exists: boolean;
  path: string;
  size?: number;
  modifiedAt?: string;
}

interface XdsState {
  ok: boolean;
  dir: string;
  version?: string;
  generatedAt?: string;
  routeIds: Set<string>;
  listenerPresent: boolean;
  files: Record<string, FileStatus>;
  error?: string;
}

const ROUTE_STATUS_REPORT_DOMAIN = "proof-ingress.operator.route-status.v1";

export async function buildRouteStatusReport(input: RouteStatusReportInput): Promise<RouteStatusReport> {
  const now = input.now ?? new Date();
  const nowUnixSeconds = Math.floor(now.getTime() / 1000);
  const xds = await readXdsState(input.xdsDir, input.listenerName);
  const routes = filterRoutes(input.routes, input.filters);
  const routeStatuses = routes.map((route) => routeStatus(route, xds, nowUnixSeconds));
  const unsignedReport: Omit<RouteStatusReport, "signature"> = {
    version: 1,
    kind: "proof-ingress.operator.route-status",
    reportId: `route-status-${nowUnixSeconds}-${input.configVersion}`,
    reportedAt: now.toISOString(),
    nowUnixSeconds,
    operator: {
      operatorId: input.operatorId,
      gatewayId: input.gatewayId && input.gatewayId.length > 0 ? input.gatewayId : osHostname(),
      host: osHostname()
    },
    listener: {
      name: input.listenerName,
      address: input.listenerAddress,
      port: input.listenerPort
    },
    configVersion: input.configVersion,
    filters: compactFilters(input.filters),
    summary: {
      routeCount: input.routes.length,
      activeRouteCount: input.routes.filter((route) => routeIsActive(route, nowUnixSeconds)).length,
      reportedRouteCount: routeStatuses.length,
      configuredRouteCount: routeStatuses.filter((route) => route.observed.configured).length,
      expiredRouteCount: routeStatuses.filter((route) => route.observed.expired).length
    },
    xds: {
      ok: xds.ok,
      dir: xds.dir,
      version: xds.version,
      generatedAt: xds.generatedAt,
      listenerPresent: xds.listenerPresent,
      files: xds.files,
      error: xds.error
    },
    routes: routeStatuses
  };
  const signingKey = input.signingKey ?? input.signingPrivateKey;
  return signingKey
    ? {
        ...unsignedReport,
        signature: await signReportPayload(signingKey, ROUTE_STATUS_REPORT_DOMAIN, unsignedReport, {
          scheme: input.signingScheme,
          ss58Format: input.signingSs58Format
        })
      }
    : unsignedReport;
}

function routeStatus(route: RouteIntent, xds: XdsState, nowUnixSeconds: number): RouteStatus {
  const active = routeIsActive(route, nowUnixSeconds);
  const xdsRendered = xds.routeIds.has(route.routeId);
  const hostnames = routeHostnames(route);
  return {
    routeId: route.routeId,
    sessionId: route.sessionId,
    hostname: route.hostname,
    publicHostname: hostnames.public,
    validationHostname: hostnames.validation,
    customerHostnames: hostnames.customer,
    hostnameRole: route.hostnameRole,
    hostnames,
    upstream: {
      host: route.upstreamHost,
      port: route.upstreamPort
    },
    expiresAt: route.expiresAt,
    expiresAtIso: new Date(route.expiresAt * 1000).toISOString(),
    secondsUntilExpiry: route.expiresAt - nowUnixSeconds,
    source: route.source,
    observed: {
      stored: true,
      active,
      expired: !active,
      xdsRendered,
      listenerPresent: xds.listenerPresent,
      configured: active && xds.ok && xds.listenerPresent && xdsRendered
    }
  };
}

function filterRoutes(routes: RouteIntent[], filters: RouteStatusReportFilters | undefined): RouteIntent[] {
  const normalizedHostname = filters?.hostname ? normalizeHostname(filters.hostname) : undefined;
  return routes.filter((route) => {
    if (filters?.routeId && route.routeId !== filters.routeId) {
      return false;
    }
    if (filters?.sessionId && route.sessionId.toLowerCase() !== filters.sessionId.toLowerCase()) {
      return false;
    }
    if (normalizedHostname && !routeMatchesHostname(route, normalizedHostname)) {
      return false;
    }
    return true;
  });
}

function compactFilters(filters: RouteStatusReportFilters | undefined): RouteStatusReportFilters | undefined {
  if (!filters) {
    return undefined;
  }
  const compact = Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== undefined && value !== ""));
  return Object.keys(compact).length > 0 ? compact : undefined;
}

async function readXdsState(xdsDir: string, listenerName: string): Promise<XdsState> {
  const files = {
    routes: await fileStatus(path.join(xdsDir, "routes.json")),
    lds: await fileStatus(path.join(xdsDir, "lds.json")),
    cds: await fileStatus(path.join(xdsDir, "cds.json"))
  };
  try {
    const routesJson = JSON.parse(await fs.readFile(files.routes.path, "utf8")) as {
      version?: string;
      generatedAt?: string;
      routes?: Array<{ routeId?: string }>;
    };
    const ldsJson = JSON.parse(await fs.readFile(files.lds.path, "utf8")) as {
      resources?: Array<{ name?: string }>;
    };
    const routeIds = new Set((routesJson.routes ?? []).map((route) => route.routeId).filter((routeId): routeId is string => Boolean(routeId)));
    return {
      ok: files.routes.exists && files.lds.exists && files.cds.exists,
      dir: xdsDir,
      version: routesJson.version,
      generatedAt: routesJson.generatedAt,
      routeIds,
      listenerPresent: (ldsJson.resources ?? []).some((resource) => resource.name === listenerName),
      files
    };
  } catch (error) {
    return {
      ok: false,
      dir: xdsDir,
      routeIds: new Set(),
      listenerPresent: false,
      files,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function fileStatus(filePath: string): Promise<FileStatus> {
  try {
    const stat = await fs.stat(filePath);
    return {
      exists: true,
      path: filePath,
      size: stat.size,
      modifiedAt: stat.mtime.toISOString()
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        exists: false,
        path: filePath
      };
    }
    throw error;
  }
}
