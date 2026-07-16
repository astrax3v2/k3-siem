'use strict';
// generateInstallScript's 'native' variant points at the k3-agent-cpp installer artifacts
// (built by .github/workflows/build-agent.yml) instead of the Python agent.py/config.yaml
// bundle the default 'python' variant embeds — confirms both variants produce a script
// referencing the right filenames/flags for each OS without crashing.
const { generateInstallScript, NATIVE_INSTALLER_FILENAMES } = require('../../src/services/deployer');

describe('deployer.generateInstallScript', () => {
  test('python variant (default) embeds agent.py download for linux', () => {
    const script = generateInstallScript('linux', 'https://siem.example.com', 'key123');
    expect(script).toContain('agent.py');
    expect(script).toContain('https://siem.example.com');
    expect(script).toContain('key123');
  });

  test('native variant downloads the linux .bin and passes --api-key', () => {
    const script = generateInstallScript('linux', 'https://siem.example.com', 'key123', 'native');
    expect(script).toContain(NATIVE_INSTALLER_FILENAMES.linux);
    expect(script).toContain('--api-key "key123"');
    expect(script).toContain('--siem-url "https://siem.example.com"');
  });

  test('native variant downloads the macos .dmg and mounts it', () => {
    const script = generateInstallScript('macos', 'https://siem.example.com', 'key123', 'native');
    expect(script).toContain(NATIVE_INSTALLER_FILENAMES.macos);
    expect(script).toContain('hdiutil attach');
    expect(script).toContain('installer -pkg');
  });

  test('native variant downloads the windows .exe with silent install flags', () => {
    const script = generateInstallScript('windows', 'https://siem.example.com', 'key123', 'native');
    expect(script).toContain(NATIVE_INSTALLER_FILENAMES.windows);
    expect(script).toContain('/SIEMURL=https://siem.example.com');
    expect(script).toContain('/APIKEY=key123');
  });
});
