import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it } from "node:test";

import {
  fetchWanIpv4,
  normalizeOperatorPublicAddressMode,
  normalizeWanIpv4Response
} from "../src/wan-ip.js";

describe("operator WAN IP detection", () => {
  it("defaults to auto only when no static public address is configured", () => {
    assert.equal(normalizeOperatorPublicAddressMode(undefined, []), "auto");
    assert.equal(normalizeOperatorPublicAddressMode(undefined, ["195.22.134.245"]), "static");
    assert.equal(normalizeOperatorPublicAddressMode("auto", ["195.22.134.245"]), "auto");
  });

  it("normalizes public IPv4 probe responses and rejects non-public addresses", () => {
    assert.equal(normalizeWanIpv4Response("195.22.134.245\n"), "195.22.134.245");
    assert.throws(() => normalizeWanIpv4Response("192.168.3.4\n"), /non-public IPv4/);
    assert.throws(() => normalizeWanIpv4Response(""), /empty response/);
  });

  it("uses the injected request function for probe tests", async () => {
    const observed = await fetchWanIpv4({
      url: "https://ifconfig.me/ip",
      requestText: async (url, timeoutMs) => {
        assert.equal(url, "https://ifconfig.me/ip");
        assert.equal(timeoutMs, 5000);
        return "2.122.7.112\n";
      }
    });
    assert.equal(observed, "2.122.7.112");
  });

  it("fetches WAN IPv4 probe responses over the real HTTP request path", async () => {
    const server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("195.22.134.245\n");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address() as AddressInfo | null;
      assert(address);
      const observed = await fetchWanIpv4({
        url: `http://127.0.0.1:${address.port}/ip`,
        timeoutMs: 5000
      });
      assert.equal(observed, "195.22.134.245");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
