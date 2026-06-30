'use strict';
const { haversineKm, isPrivate } = require('../../src/services/geoip');

describe('geoip', () => {
  test('isPrivate recognizes RFC1918 / loopback ranges', () => {
    expect(isPrivate('10.0.1.50')).toBe(true);
    expect(isPrivate('192.168.1.66')).toBe(true);
    expect(isPrivate('172.16.0.5')).toBe(true);
    expect(isPrivate('127.0.0.1')).toBe(true);
    expect(isPrivate(null)).toBe(true);
  });

  test('isPrivate treats public IPs as not private', () => {
    expect(isPrivate('185.220.101.47')).toBe(false);
    expect(isPrivate('8.8.8.8')).toBe(false);
  });

  test('haversineKm computes a sane distance between two known points', () => {
    // London (51.5074, -0.1278) to Paris (48.8566, 2.3522) is ~344km
    const km = haversineKm({ lat: 51.5074, lon: -0.1278 }, { lat: 48.8566, lon: 2.3522 });
    expect(km).toBeGreaterThan(300);
    expect(km).toBeLessThan(400);
  });

  test('haversineKm returns ~0 for identical points', () => {
    const km = haversineKm({ lat: 10, lon: 10 }, { lat: 10, lon: 10 });
    expect(km).toBeCloseTo(0, 5);
  });
});
