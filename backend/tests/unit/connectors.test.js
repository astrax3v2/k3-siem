'use strict';
// Each connector must report "not configured" honestly when its env vars are absent —
// this is what lets SOAR execution degrade safely instead of silently faking success.
describe('connector isConfigured() gating', () => {
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    delete process.env.SLACK_WEBHOOK_URL;
    delete process.env.JIRA_BASE_URL;
    delete process.env.VIRUSTOTAL_API_KEY;
    delete process.env.ABUSEIPDB_API_KEY;
    delete process.env.SHODAN_API_KEY;
  });

  afterAll(() => { process.env = ORIGINAL_ENV; });

  test('slack reports not configured without webhook url', () => {
    const slack = require('../../src/services/connectors/slack');
    expect(slack.isConfigured()).toBe(false);
  });

  test('slack reports configured once webhook url is set', () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/test';
    const slack = require('../../src/services/connectors/slack');
    expect(slack.isConfigured()).toBe(true);
  });

  test('jira requires all four env vars before reporting configured', () => {
    process.env.JIRA_BASE_URL = 'https://example.atlassian.net';
    process.env.JIRA_EMAIL = 'soc@example.com';
    const jira = require('../../src/services/connectors/jira');
    expect(jira.isConfigured()).toBe(false);
    process.env.JIRA_API_TOKEN = 'token';
    process.env.JIRA_PROJECT_KEY = 'SEC';
    jest.resetModules();
    const jira2 = require('../../src/services/connectors/jira');
    expect(jira2.isConfigured()).toBe(true);
  });

  test('virustotal lookupIp returns null when not configured (no network call)', async () => {
    const vt = require('../../src/services/connectors/virustotal');
    await expect(vt.lookupIp('8.8.8.8')).resolves.toBeNull();
  });

  test('virustotal lookupDomain returns null when not configured (no network call)', async () => {
    const vt = require('../../src/services/connectors/virustotal');
    await expect(vt.lookupDomain('example.com')).resolves.toBeNull();
  });

  test('shodan reports not configured without an api key', () => {
    const shodan = require('../../src/services/connectors/shodan');
    expect(shodan.isConfigured()).toBe(false);
  });

  test('shodan lookupIp returns null when not configured (no network call)', async () => {
    const shodan = require('../../src/services/connectors/shodan');
    await expect(shodan.lookupIp('8.8.8.8')).resolves.toBeNull();
  });

  test('shodan reports configured once an api key is set', () => {
    process.env.SHODAN_API_KEY = 'test-key';
    const shodan = require('../../src/services/connectors/shodan');
    expect(shodan.isConfigured()).toBe(true);
  });
});
