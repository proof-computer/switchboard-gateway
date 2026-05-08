import { z } from "zod";

export const hex32Schema = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
export const hostnameRoleSchema = z.enum(["legacy", "ha_public", "validation"]);

export type HostnameRole = z.infer<typeof hostnameRoleSchema>;

const hostnameSchema = z.string().min(1).max(253).transform(normalizeHostname);

export const routeIntentSchema = z.object({
  routeId: z.string().min(1).optional(),
  sessionId: hex32Schema,
  hostname: hostnameSchema,
  publicHostname: hostnameSchema.optional(),
  validationHostname: hostnameSchema.optional(),
  customerHostnames: z.array(hostnameSchema).optional().default([]),
  hostnameRole: hostnameRoleSchema.optional(),
  upstreamHost: z.string().min(1),
  upstreamPort: z.number().int().min(1).max(65535),
  expiresAt: z.union([z.string().regex(/^[0-9]+$/), z.number().int().nonnegative()]).transform((value) => Number(value)),
  source: z.record(z.string(), z.unknown()).optional()
});

export type RouteIntentInput = z.input<typeof routeIntentSchema>;
type ParsedRouteIntent = z.output<typeof routeIntentSchema>;

export interface RouteHostnames {
  primary: string;
  public: string;
  validation?: string;
  customer: string[];
  serverNames: string[];
}

export type RouteIntent = Omit<ParsedRouteIntent, "publicHostname" | "customerHostnames" | "hostnameRole"> & {
  routeId: string;
  publicHostname: string;
  customerHostnames: string[];
  hostnameRole: HostnameRole;
};

export function normalizeRouteIntent(input: RouteIntentInput): RouteIntent {
  const parsed = routeIntentSchema.parse(input);
  const publicHostname = parsed.publicHostname ?? parsed.hostname;
  return {
    ...parsed,
    publicHostname,
    customerHostnames: uniqueHostnames(parsed.customerHostnames),
    hostnameRole: parsed.hostnameRole ?? (parsed.publicHostname || parsed.validationHostname ? "ha_public" : "legacy"),
    routeId: parsed.routeId ?? parsed.sessionId
  };
}

export function routeIsActive(route: RouteIntent, nowSeconds = Math.floor(Date.now() / 1000)): boolean {
  return route.expiresAt > nowSeconds;
}

export function normalizeHostname(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

export function routeHostnames(route: RouteIntent): RouteHostnames {
  const publicHostname = route.publicHostname ?? route.hostname;
  const customer = uniqueHostnames(route.customerHostnames ?? []);
  return {
    primary: route.hostname,
    public: publicHostname,
    validation: route.validationHostname,
    customer,
    serverNames: uniqueHostnames([route.hostname, publicHostname, route.validationHostname, ...customer])
  };
}

export function routeServerNames(route: RouteIntent): string[] {
  return routeHostnames(route).serverNames;
}

export function routeMatchesHostname(route: RouteIntent, hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return routeServerNames(route).includes(normalized);
}

export function safeResourceName(value: string): string {
  return value
    .toLowerCase()
    .replace(/^0x/, "")
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function uniqueHostnames(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)).map(normalizeHostname))];
}
