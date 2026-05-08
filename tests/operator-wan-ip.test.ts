import assert from "node:assert/strict";
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
});
