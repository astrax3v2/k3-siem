'use strict';
// Centralized required-secret loading. Import this (after dotenv.config()) instead of
// reading process.env.JWT_SECRET / INGEST_API_KEY directly with a hardcoded fallback —
// a missing secret should fail loudly at boot, not silently default to a known value.

const REQUIRED = ['JWT_SECRET', 'INGEST_API_KEY'];
const MIN_SECRET_LENGTH = 16;

const missing = REQUIRED.filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`[Config] Missing required environment variable(s): ${missing.join(', ')}`);
  console.error('[Config] Copy backend/.env.example to backend/.env and set real values, or set them in your deployment environment. Refusing to start.');
  process.exit(1);
}

const weak = REQUIRED.filter((key) => process.env[key].length < MIN_SECRET_LENGTH);
if (weak.length) {
  console.error(`[Config] Environment variable(s) too short (min ${MIN_SECRET_LENGTH} chars): ${weak.join(', ')}`);
  process.exit(1);
}

module.exports = {
  JWT_SECRET: process.env.JWT_SECRET,
  INGEST_API_KEY: process.env.INGEST_API_KEY,
};
