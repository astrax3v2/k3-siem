'use strict';
const fs = require('fs');
const path = require('path');
const express = require('express');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const TEST_DB = path.resolve(__dirname, '../../data/test-auth.db');

describe('auth integration', () => {
  let app, db, initDb;

  beforeAll(async () => {
    process.env.DB_PATH = TEST_DB;
    if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
    ({ db, initDb } = require('../../src/models/db'));
    await initDb();

    const d = db();
    const pwHash = bcrypt.hashSync('Test@1234', 10);
    await d.prepare('INSERT INTO users(id,username,email,password_hash,role,full_name) VALUES(?,?,?,?,?,?)')
      .run(uuidv4(), 'testuser', 'testuser@example.com', pwHash, 'admin', 'Test User');

    const authRouter = require('../../src/routes/auth');
    app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
  });

  afterAll(async () => {
    await db().close();
    try { if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB); } catch { /* Windows may hold a brief handle */ }
  });

  test('rejects invalid credentials', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'testuser', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('rejects missing fields', async () => {
    const res = await request(app).post('/api/auth/login').send({ username: 'testuser' });
    expect(res.status).toBe(400);
  });

  test('issues a JWT for valid credentials and /me resolves it', async () => {
    const login = await request(app).post('/api/auth/login').send({ username: 'testuser', password: 'Test@1234' });
    expect(login.status).toBe(200);
    expect(login.body.token).toBeTruthy();
    expect(login.body.user.username).toBe('testuser');

    const me = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${login.body.token}`);
    expect(me.status).toBe(200);
    expect(me.body.user.username).toBe('testuser');
  });

  test('rejects requests with no token', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });
});
