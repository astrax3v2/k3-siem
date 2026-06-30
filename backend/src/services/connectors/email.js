'use strict';
let nodemailer;
try { nodemailer = require('nodemailer'); } catch { /* optional dependency */ }

function isConfigured() {
  return !!(nodemailer && process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.ALERT_EMAIL_TO);
}

async function send(subject, text) {
  if (!nodemailer) return { ok: false, detail: 'Email not configured (nodemailer not installed — run npm install)' };
  if (!isConfigured()) return { ok: false, detail: 'Email not configured (SMTP_HOST/SMTP_USER/SMTP_PASS/ALERT_EMAIL_TO unset)' };
  try {
    const transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_PORT === '465',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    });
    await transport.sendMail({
      from: process.env.ALERT_EMAIL_FROM || process.env.SMTP_USER,
      to: process.env.ALERT_EMAIL_TO,
      subject, text,
    });
    return { ok: true, detail: `Email sent to ${process.env.ALERT_EMAIL_TO}` };
  } catch (e) { return { ok: false, detail: `Email error: ${e.message}` }; }
}

module.exports = { isConfigured, send };
