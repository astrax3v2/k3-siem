'use strict';
const { extractCandidates } = require('../../src/services/iocMatcher');

describe('iocMatcher.extractCandidates', () => {
  test('extracts IP from ip_address field', () => {
    const c = extractCandidates({ ip_address: '185.220.101.47', raw_log: '{}' });
    expect(c.IP.has('185.220.101.47')).toBe(true);
  });

  test('extracts hash from raw_log text', () => {
    const c = extractCandidates({ raw_log: 'hash=d41d8cd98f00b204e9800998ecf8427e found' });
    expect(c.Hash.has('d41d8cd98f00b204e9800998ecf8427e')).toBe(true);
  });

  test('extracts URL and excludes its host from domain set when separately matched as email/domain', () => {
    const c = extractCandidates({ raw_log: 'downloaded from http://45.33.32.156/payload.exe' });
    expect(Array.from(c.URL)).toContain('http://45.33.32.156/payload.exe');
  });

  test('extracts email and does not duplicate into domain set', () => {
    const c = extractCandidates({ raw_log: 'sender attacker@phish-campaign.com flagged' });
    expect(c.Email.has('attacker@phish-campaign.com')).toBe(true);
    expect(c.Domain.has('attacker@phish-campaign.com')).toBe(false);
  });

  test('extracts domain from raw_log text', () => {
    const c = extractCandidates({ raw_log: 'beacon to evil-c2.top observed' });
    expect(c.Domain.has('evil-c2.top')).toBe(true);
  });
});
