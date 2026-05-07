/**
 * DNS fix preload script for HF Spaces.
 *
 * Patches Node.js dns.lookup to:
 * 1. Try system DNS first
 * 2. Fall back to DNS-over-HTTPS (Cloudflare) if system DNS fails
 *    (This is needed because HF Spaces intercepts/blocks some domains like
 *    WhatsApp web or Telegram API via standard UDP DNS).
 *
 * Loaded via: NODE_OPTIONS="--require /opt/dns-fix.js"
 */
"use strict";

const dns = require("dns");
const https = require("https");

// In-memory cache for runtime DoH resolutions
const runtimeCache = new Map(); // hostname -> { ips, expiry, cursor }

// HF Spaces can prefer IPv6 addresses that are not reachable from the runtime.
// Prefer IPv4 first unless callers explicitly request another family.
try {
  dns.setDefaultResultOrder("ipv4first");
  console.log("[dns-fix] Enabled ipv4first DNS result ordering");
} catch (_) {
  // No-op on older Node versions where this API is unavailable.
}

const FORCE_IPV4_HOSTS = new Set(["api.telegram.org"]);

function nextCachedIp(hostname) {
  const cached = runtimeCache.get(hostname);
  if (!cached || cached.expiry <= Date.now() || !Array.isArray(cached.ips) || cached.ips.length === 0) {
    return null;
  }
  const index = cached.cursor % cached.ips.length;
  const ip = cached.ips[index];
  cached.cursor = (index + 1) % cached.ips.length;
  return ip;
}

// DNS-over-HTTPS resolver
function dohResolve(hostname, callback) {
  // Check runtime cache
  const cachedIp = nextCachedIp(hostname);
  if (cachedIp) {
    return callback(null, cachedIp);
  }

  const url = `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
  const req = https.get(
    url,
    { headers: { Accept: "application/dns-json" }, timeout: 15000 },
    (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => {
        try {
          const data = JSON.parse(body);
          const aRecords = (data.Answer || []).filter((a) => a.type === 1);
          if (aRecords.length === 0) {
            return callback(new Error(`DoH: no A record for ${hostname}`));
          }
          const ips = [...new Set(aRecords.map((record) => record.data).filter(Boolean))];
          if (ips.length === 0) {
            return callback(new Error(`DoH: no valid A record for ${hostname}`));
          }
          const ttl = Math.max((aRecords[0].TTL || 300) * 1000, 60000);
          runtimeCache.set(hostname, { ips, expiry: Date.now() + ttl, cursor: 1 % ips.length });
          callback(null, ips[0]);
        } catch (e) {
          callback(new Error(`DoH parse error: ${e.message}`));
        }
      });
    }
  );
  req.on("error", (e) => callback(new Error(`DoH request failed: ${e.message}`)));
  req.on("timeout", () => {
    req.destroy();
    callback(new Error("DoH request timed out"));
  });
}

// Monkey-patch dns.lookup
const origLookup = dns.lookup;

dns.lookup = function patchedLookup(hostname, options, callback) {
  // Normalize arguments (options is optional, can be number or object)
  if (typeof options === "function") {
    callback = options;
    options = {};
  }
  if (typeof options === "number") {
    options = { family: options };
  }
  options = options || {};
  const lookupOptions = { ...options };

  // Skip patching for localhost, IPs, and internal domains
  if (
    !hostname ||
    hostname === "localhost" ||
    hostname === "0.0.0.0" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ||
    /^::/.test(hostname)
  ) {
    return origLookup.call(dns, hostname, lookupOptions, callback);
  }

  if (!lookupOptions.family && FORCE_IPV4_HOSTS.has(hostname)) {
    lookupOptions.family = 4;
  }

  // 1) Try system DNS first
  origLookup.call(dns, hostname, lookupOptions, (err, address, family) => {
    if (!err && address) {
      return callback(null, address, family);
    }

    // 2) System DNS failed with ENOTFOUND or EAI_AGAIN — fall back to DoH
    if (err && (err.code === "ENOTFOUND" || err.code === "EAI_AGAIN")) {
      dohResolve(hostname, (dohErr, ip) => {
        if (dohErr || !ip) {
          return callback(err); // Return original error
        }
        if (options.all) {
          return callback(null, [{ address: ip, family: 4 }]);
        }
        callback(null, ip, 4);
      });
    } else {
      // Other DNS errors — pass through
      callback(err, address, family);
    }
  });
};
