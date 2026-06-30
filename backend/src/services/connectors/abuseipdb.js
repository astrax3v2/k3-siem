'use strict';
function isConfigured() { return !!process.env.ABUSEIPDB_API_KEY; }

async function checkIp(ip) {
  if (!isConfigured()) return null;
  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' }, signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.data || null;
  } catch { return null; }
}

module.exports = { isConfigured, checkIp };
