# Switchboard Gateway

Public runtime source for Switchboard operator gateway services.

This repository builds the `ghcr.io/proof-computer/switchboard-gateway/gateway`
image. The image contains both long-running Node processes:

- `gateway-agent`: manages route state, renders Envoy filesystem xDS, and
  submits signed gateway capability reports.
- `hub-watcher`: watches Hub registry events and posts internal route intents
  for local/dev recovery flows.

The public CLI still exposes user-facing commands as `switchboard operator ...`
for compatibility. Runtime ownership is gateway-branded here; service names
inside Compose remain `gateway-agent` and `hub-watcher`.

## Development

```sh
npm ci
npm run build
npm run typecheck
npm test
npm run verify:public-surface
```

Development entrypoints run TypeScript directly:

```sh
npm run dev:gateway-agent
npm run dev:hub-watcher
```

Production scripts run the compiled `dist/` output:

```sh
npm run gateway:agent
npm run gateway:hub-watcher
```

Compatibility aliases are also kept:

```sh
npm run operator:gateway-agent
npm run operator:hub-watcher
```

## Images

The Docker workflow builds:

- `ghcr.io/proof-computer/switchboard-gateway/gateway`
- `ghcr.io/proof-computer/switchboard-gateway/tls-test-upstream`

Pull requests build but do not push. Pushes to the default branch and version
tags push GHCR tags for `latest`, branch, semver, and short SHA.

Operator hosts should use upstream Envoy, VictoriaMetrics, and Grafana images
with mounted config instead of Switchboard-republished support images.
