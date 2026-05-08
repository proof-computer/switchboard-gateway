import { promises as fs } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

import { type RouteIntent, routeHostnames, routeIsActive, routeServerNames, safeResourceName } from "./route-intent.js";

export interface XdsRenderOptions {
  outputDir: string;
  version: string;
  listenerName: string;
  listenerAddress: string;
  listenerPort: number;
}

export async function renderFileXds(routes: RouteIntent[], options: XdsRenderOptions): Promise<void> {
  await fs.mkdir(options.outputDir, { recursive: true });

  const activeRoutes = routes.filter((route) => routeIsActive(route));
  const haGroups = haHostnameGroups(activeRoutes);
  const clusters = [
    blackholeCluster(),
    ...activeRoutes.map(routeCluster),
    ...haGroups.map((group) => haRouteCluster(group))
  ];
  const listener = listenerResource(activeRoutes, haGroups, options);

  await writeJsonAtomic(path.join(options.outputDir, "cds.json"), {
    version_info: options.version,
    type_url: "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    resources: clusters
  });

  await writeJsonAtomic(path.join(options.outputDir, "lds.json"), {
    version_info: options.version,
    type_url: "type.googleapis.com/envoy.config.listener.v3.Listener",
    resources: [listener]
  });

  await writeJsonAtomic(path.join(options.outputDir, "routes.json"), {
    version: options.version,
    generatedAt: new Date().toISOString(),
    routes: activeRoutes
  });
}

function routeCluster(route: RouteIntent) {
  return {
    "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    name: clusterName(route),
    type: "STRICT_DNS",
    connect_timeout: "2s",
    dns_lookup_family: "V4_ONLY",
    load_assignment: {
      cluster_name: clusterName(route),
      endpoints: [
        {
          lb_endpoints: [
            {
              endpoint: {
                address: {
                  socket_address: {
                    address: route.upstreamHost,
                    port_value: route.upstreamPort
                  }
                }
              }
            }
          ]
        }
      ]
    }
  };
}

interface HaHostnameGroup {
  hostname: string;
  routes: RouteIntent[];
}

function haRouteCluster(group: HaHostnameGroup) {
  const name = haClusterName(group.hostname);
  return {
    "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    name,
    type: "STRICT_DNS",
    connect_timeout: "2s",
    dns_lookup_family: "V4_ONLY",
    load_assignment: {
      cluster_name: name,
      endpoints: [
        {
          lb_endpoints: group.routes.map((route) => ({
            endpoint: {
              address: {
                socket_address: {
                  address: route.upstreamHost,
                  port_value: route.upstreamPort
                }
              }
            }
          }))
        }
      ]
    }
  };
}

function blackholeCluster() {
  return {
    "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    name: "blackhole",
    type: "STATIC",
    connect_timeout: "0.250s",
    load_assignment: {
      cluster_name: "blackhole",
      endpoints: [
        {
          lb_endpoints: [
            {
              endpoint: {
                address: {
                  socket_address: {
                    address: "127.0.0.1",
                    port_value: 1
                  }
                }
              }
            }
          ]
        }
      ]
    }
  };
}

function listenerResource(routes: RouteIntent[], haGroups: HaHostnameGroup[], options: XdsRenderOptions) {
  const groupedHostnames = new Set(haGroups.map((group) => group.hostname));
  const routeChains = routes
    .map((route) => filterChainForRoute(route, groupedHostnames))
    .filter((chain): chain is NonNullable<ReturnType<typeof filterChainForRoute>> => Boolean(chain));
  return {
    "@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
    name: options.listenerName,
    address: {
      socket_address: {
        address: options.listenerAddress,
        port_value: options.listenerPort
      }
    },
    listener_filters: [
      {
        name: "envoy.filters.listener.tls_inspector",
        typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector"
        }
      }
    ],
    filter_chains: [
      ...haGroups.map(filterChainForHaGroup),
      ...routeChains,
      defaultFilterChain()
    ]
  };
}

function filterChainForRoute(route: RouteIntent, groupedHostnames: Set<string>) {
  const serverNames = routeServerNames(route).filter((serverName) => !groupedHostnames.has(serverName));
  if (serverNames.length === 0) {
    return undefined;
  }
  return {
    name: routeResourceName(route),
    filter_chain_match: {
      server_names: serverNames
    },
    filters: [
      {
        name: "envoy.filters.network.tcp_proxy",
        typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
          stat_prefix: `sni_${safeResourceName(serverNames[0] ?? route.hostname)}`,
          cluster: clusterName(route)
        }
      }
    ]
  };
}

function filterChainForHaGroup(group: HaHostnameGroup) {
  return {
    name: haClusterName(group.hostname),
    filter_chain_match: {
      server_names: [group.hostname]
    },
    filters: [
      {
        name: "envoy.filters.network.tcp_proxy",
        typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
          stat_prefix: `sni_${safeResourceName(group.hostname)}`,
          cluster: haClusterName(group.hostname)
        }
      }
    ]
  };
}

function defaultFilterChain() {
  return {
    name: "default_blackhole",
    filters: [
      {
        name: "envoy.filters.network.tcp_proxy",
        typed_config: {
          "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
          stat_prefix: "sni_unmatched",
          cluster: "blackhole"
        }
      }
    ]
  };
}

function clusterName(route: RouteIntent): string {
  return routeResourceName(route);
}

function haClusterName(hostname: string): string {
  return uniqueResourceName("ha", hostname);
}

function routeResourceName(route: RouteIntent): string {
  return uniqueResourceName("route", route.routeId);
}

function haHostnameGroups(routes: RouteIntent[]): HaHostnameGroup[] {
  const grouped = new Map<string, RouteIntent[]>();
  for (const route of routes) {
    const hostnames = routeHostnames(route);
    for (const hostname of [hostnames.public, ...hostnames.customer]) {
      const members = grouped.get(hostname) ?? [];
      members.push(route);
      grouped.set(hostname, members);
    }
  }
  return [...grouped.entries()]
    .filter(([, members]) => members.length > 1)
    .map(([hostname, members]) => ({
      hostname,
      routes: dedupeRoutes(members)
    }))
    .filter((group) => group.routes.length > 1)
    .sort((left, right) => left.hostname.localeCompare(right.hostname));
}

function dedupeRoutes(routes: RouteIntent[]): RouteIntent[] {
  const seen = new Set<string>();
  const unique: RouteIntent[] = [];
  for (const route of routes) {
    const key = route.routeId;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(route);
  }
  return unique;
}

function uniqueResourceName(prefix: string, value: string): string {
  const safe = safeResourceName(value) || "resource";
  if (/^(0x)?[A-Za-z0-9_.-]+$/.test(value) && safe.length <= 64) {
    return `${prefix}_${safe}`;
  }
  const hash = createHash("sha256").update(value).digest("hex").slice(0, 12);
  return `${prefix}_${safe.slice(0, 64)}_${hash}`;
}

async function writeJsonAtomic(filePath: string, value: unknown): Promise<void> {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`);
  await fs.rename(tempPath, filePath);
}
