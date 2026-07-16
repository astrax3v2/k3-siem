'use strict';
function isConfigured() { return !!process.env.SHODAN_API_KEY; }

async function lookupIp(ip) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${process.env.SHODAN_API_KEY}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

module.exports = { isConfigured, lookupIp };
