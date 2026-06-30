'use strict';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-not-for-production-use-0000';
process.env.INGEST_API_KEY = process.env.INGEST_API_KEY || 'test-ingest-key-not-for-production-0000';
process.env.CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
process.env.DB_PATH = process.env.DB_PATH || './data/test-siem.db';
process.env.GEOIP_DISABLED = 'true';
