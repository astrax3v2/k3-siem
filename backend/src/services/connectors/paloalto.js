'use strict';
function isConfigured() { return !!(process.env.PANOS_HOST && process.env.PANOS_API_KEY); }

async function blockIp(ip) {
  if (!isConfigured()) return { ok: false, detail: 'Palo Alto not configured (PANOS_HOST/PANOS_API_KEY unset)' };
  const base = `https://${process.env.PANOS_HOST}/api/`;
  const group = process.env.PANOS_BLOCK_GROUP || 'K3-Blocked-IPs';
  const addrName = `k3-block-${ip.replace(/\./g, '-')}`;
  try {
    const setAddr = new URL(base);
    setAddr.searchParams.set('type', 'config');
    setAddr.searchParams.set('action', 'set');
    setAddr.searchParams.set('key', process.env.PANOS_API_KEY);
    setAddr.searchParams.set('xpath', `/config/devices/entry/vsys/entry/address/entry[@name='${addrName}']`);
    setAddr.searchParams.set('element', `<ip-netmask>${ip}/32</ip-netmask>`);
    const r1 = await fetch(setAddr, { method: 'GET', signal: AbortSignal.timeout(8000) });
    if (!r1.ok) return { ok: false, detail: `PAN-OS address object creation failed (HTTP ${r1.status})` };

    const setMember = new URL(base);
    setMember.searchParams.set('type', 'config');
    setMember.searchParams.set('action', 'set');
    setMember.searchParams.set('key', process.env.PANOS_API_KEY);
    setMember.searchParams.set('xpath', `/config/devices/entry/vsys/entry/address-group/entry[@name='${group}']/static`);
    setMember.searchParams.set('element', `<member>${addrName}</member>`);
    const r2 = await fetch(setMember, { method: 'GET', signal: AbortSignal.timeout(8000) });
    if (!r2.ok) return { ok: false, detail: `PAN-OS address-group update failed (HTTP ${r2.status})` };

    const commit = new URL(base);
    commit.searchParams.set('type', 'commit');
    commit.searchParams.set('cmd', '<commit></commit>');
    commit.searchParams.set('key', process.env.PANOS_API_KEY);
    await fetch(commit, { method: 'GET', signal: AbortSignal.timeout(8000) }).catch(() => {});

    return { ok: true, detail: `Added ${ip} to PAN-OS group "${group}" (commit queued)` };
  } catch (e) { return { ok: false, detail: `Palo Alto error: ${e.message}` }; }
}

module.exports = { isConfigured, blockIp };
