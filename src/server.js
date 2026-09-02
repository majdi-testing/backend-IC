import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import Database from 'better-sqlite3';
import { z } from 'zod';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';

const port = Number(process.env.PORT || 8080);
const databasePath = path.resolve(process.env.DATABASE_PATH || './data/islamic-circle.db');
const uploadDir = path.resolve(process.env.UPLOAD_DIR || './uploads');
fs.mkdirSync(path.dirname(databasePath), { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const database = new Database(databasePath);
database.pragma('journal_mode = WAL');
database.exec(`
  CREATE TABLE IF NOT EXISTS content (id TEXT PRIMARY KEY, kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, media_url TEXT, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS announcements (id TEXT PRIMARY KEY, title TEXT NOT NULL, message TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'Normal', published INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS courses (id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, price_cents INTEGER NOT NULL DEFAULT 0, access_code_hash TEXT, media_url TEXT, published INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, course_id TEXT NOT NULL, user_email TEXT NOT NULL, transaction_ref TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS enrollments (id TEXT PRIMARY KEY, course_id TEXT NOT NULL, user_name TEXT NOT NULL, user_email TEXT NOT NULL, user_phone TEXT NOT NULL, payment_screenshot_url TEXT, transaction_ref TEXT, status TEXT NOT NULL DEFAULT 'PENDING', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS fcm_tokens (token TEXT PRIMARY KEY, user_email TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
`);

const storedJwtSecret = database.prepare('SELECT value FROM settings WHERE key = ?').get('system.jwtSecret');
let jwtSecret = process.env.JWT_SECRET || (storedJwtSecret ? JSON.parse(storedJwtSecret.value) : null);
if (!jwtSecret || jwtSecret.length < 32) {
  jwtSecret = crypto.randomBytes(48).toString('base64url');
  database.prepare('INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)').run('system.jwtSecret', JSON.stringify(jwtSecret), new Date().toISOString());
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: (process.env.ALLOWED_ORIGINS || '').split(',').map((value) => value.trim()).filter(Boolean) }));
app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(uploadDir, { maxAge: '1d' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300 }));

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const setting = (key, fallback = null) => {
  const row = database.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (!row) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
};
const settingText = (key, fallback = '') => String(setting(key, fallback) ?? fallback);
const hashAccessCode = (value) => crypto.createHash('sha256').update(value.trim().toUpperCase()).digest('hex');
const firebaseMessaging = () => {
  const serviceAccount = setting('firebase.serviceAccount');
  if (!serviceAccount?.project_id || !serviceAccount?.client_email || !serviceAccount?.private_key) return null;
  try {
    const app = getApps().find((candidate) => candidate.name === 'dynamic-firebase') || initializeApp({
      credential: cert({
        projectId: serviceAccount.project_id,
        clientEmail: serviceAccount.client_email,
        privateKey: serviceAccount.private_key.replace(/\\n/g, '\n')
      })
    }, 'dynamic-firebase');
    return getMessaging(app);
  } catch { return null; }
};
const adminOnly = (request, response, next) => {
  try {
    const token = request.headers.authorization?.replace(/^Bearer\s+/i, '');
    request.admin = jwt.verify(token, jwtSecret);
    if (request.admin.role !== 'admin') throw new Error('forbidden');
    next();
  } catch {
    response.status(401).json({ error: 'Admin authentication required' });
  }
};

app.get('/', (_request, response) => 
  response.json({ 
    ok: true, 
    service: 'islamic-circle-backend', 
    status: 'running' 
  })
);
app.get('/health', (_request, response) => response.json({ ok: true, service: 'islamic-circle-backend', time: now() }));
app.get('/api/health', (_request, response) => response.json({ ok: true, service: 'islamic-circle-backend', time: now() }));
app.post('/api/admin/login', (request, response) => {
  const input = z.object({ email: z.string().email(), password: z.string().min(8) }).safeParse(request.body);
  const adminEmail = settingText('admin.email', process.env.ADMIN_EMAIL);
  const adminPassword = settingText('admin.password', process.env.ADMIN_PASSWORD);
  if (!input.success || input.data.email !== adminEmail || input.data.password !== adminPassword) return response.status(401).json({ error: 'Invalid credentials' });
  response.json({ token: jwt.sign({ role: 'admin', email: input.data.email }, jwtSecret, { expiresIn: '8h' }) });
});

app.get('/api/content', (_request, response) => {
  const rows = database.prepare('SELECT * FROM content ORDER BY updated_at DESC').all().map((row) => ({ ...row, metadata: JSON.parse(row.metadata) }));
  response.json(rows);
});
app.post('/api/admin/content', adminOnly, (request, response) => {
  const input = z.object({ kind: z.enum(['video', 'audio', 'quran', 'banner', 'course']), title: z.string().min(1).max(200), body: z.string().default(''), mediaUrl: z.string().url().optional(), metadata: z.record(z.any()).default({}) }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const timestamp = now(); const contentId = id();
  database.prepare('INSERT INTO content (id, kind, title, body, media_url, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(contentId, input.data.kind, input.data.title, input.data.body, input.data.mediaUrl || null, JSON.stringify(input.data.metadata), timestamp, timestamp);
  response.status(201).json({ id: contentId });
});
app.patch('/api/admin/content/:contentId', adminOnly, (request, response) => {
  const input = z.object({ title: z.string().min(1).max(200).optional(), body: z.string().optional(), mediaUrl: z.string().url().nullable().optional(), metadata: z.record(z.any()).optional() }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const current = database.prepare('SELECT * FROM content WHERE id = ?').get(request.params.contentId);
  if (!current) return response.status(404).json({ error: 'Content not found' });
  database.prepare('UPDATE content SET title = ?, body = ?, media_url = ?, metadata = ?, updated_at = ? WHERE id = ?').run(input.data.title ?? current.title, input.data.body ?? current.body, input.data.mediaUrl === undefined ? current.media_url : input.data.mediaUrl, JSON.stringify(input.data.metadata ?? JSON.parse(current.metadata)), now(), request.params.contentId);
  response.json({ ok: true });
});
app.delete('/api/admin/content/:contentId', adminOnly, (request, response) => {
  const result = database.prepare('DELETE FROM content WHERE id = ?').run(request.params.contentId);
  if (!result.changes) return response.status(404).json({ error: 'Content not found' });
  response.status(204).end();
});

app.get('/api/announcements', (_request, response) => response.json(database.prepare('SELECT * FROM announcements WHERE published = 1 ORDER BY created_at DESC').all()));
app.post('/api/admin/announcements', adminOnly, (request, response) => {
  const input = z.object({ title: z.string().min(1).max(200), message: z.string().min(1).max(5000), priority: z.enum(['Normal', 'High', 'Urgent']).default('Normal') }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const announcementId = id(); database.prepare('INSERT INTO announcements (id, title, message, priority, created_at) VALUES (?, ?, ?, ?, ?)').run(announcementId, input.data.title, input.data.message, input.data.priority, now());
  response.status(201).json({ id: announcementId });
});

app.get('/api/courses', (_request, response) => response.json(database.prepare('SELECT id, title, description, price_cents, media_url, published, created_at, updated_at FROM courses WHERE published = 1 ORDER BY updated_at DESC').all()));
app.post('/api/admin/courses', adminOnly, (request, response) => {
  const input = z.object({ title: z.string().min(1).max(200), description: z.string().min(1), priceCents: z.number().int().min(0), accessCode: z.string().min(8).optional(), mediaUrl: z.string().url().optional(), published: z.boolean().default(false) }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const courseId = id(); const timestamp = now(); const codeHash = input.data.accessCode ? hashAccessCode(input.data.accessCode) : null;
  database.prepare('INSERT INTO courses (id, title, description, price_cents, access_code_hash, media_url, published, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(courseId, input.data.title, input.data.description, input.data.priceCents, codeHash, input.data.mediaUrl || null, input.data.published ? 1 : 0, timestamp, timestamp);
  response.status(201).json({ id: courseId });
});
app.patch('/api/admin/courses/:courseId', adminOnly, (request, response) => {
  const input = z.object({ title: z.string().min(1).max(200).optional(), description: z.string().min(1).optional(), priceCents: z.number().int().min(0).optional(), mediaUrl: z.string().url().nullable().optional(), published: z.boolean().optional() }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const current = database.prepare('SELECT * FROM courses WHERE id = ?').get(request.params.courseId);
  if (!current) return response.status(404).json({ error: 'Course not found' });
  database.prepare('UPDATE courses SET title = ?, description = ?, price_cents = ?, media_url = ?, published = ?, updated_at = ? WHERE id = ?').run(input.data.title ?? current.title, input.data.description ?? current.description, input.data.priceCents ?? current.price_cents, input.data.mediaUrl === undefined ? current.media_url : input.data.mediaUrl, input.data.published === undefined ? current.published : input.data.published ? 1 : 0, now(), request.params.courseId);
  response.json({ ok: true });
});
app.delete('/api/admin/courses/:courseId', adminOnly, (request, response) => {
  const result = database.prepare('DELETE FROM courses WHERE id = ?').run(request.params.courseId);
  if (!result.changes) return response.status(404).json({ error: 'Course not found' });
  response.status(204).end();
});

const enrollmentInput = z.object({ courseId: z.string().uuid(), userName: z.string().min(2).max(120), userEmail: z.string().email(), userPhone: z.string().min(6).max(30), transactionRef: z.string().min(4).max(120).optional(), paymentScreenshotUrl: z.string().url().optional() }).refine((value) => Boolean(value.transactionRef || value.paymentScreenshotUrl), { message: 'Provide a transaction reference or payment screenshot' });
app.get('/api/payment-settings', (_request, response) => response.json({ upiId: settingText('payment.upiId'), qrCodeUrl: settingText('payment.qrCodeUrl'), whatsappNumber: settingText('payment.whatsappNumber') }));
app.post('/api/enrollments', (request, response) => {
  const input = enrollmentInput.safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const course = database.prepare('SELECT id, title, price_cents, published FROM courses WHERE id = ?').get(input.data.courseId);
  if (!course || !course.published) return response.status(404).json({ error: 'Course not found' });
  const enrollmentId = id(); const timestamp = now();
  database.prepare('INSERT INTO enrollments (id, course_id, user_name, user_email, user_phone, payment_screenshot_url, transaction_ref, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(enrollmentId, course.id, input.data.userName, input.data.userEmail, input.data.userPhone, input.data.paymentScreenshotUrl || null, input.data.transactionRef || null, 'PENDING', timestamp, timestamp);
  response.status(201).json({ id: enrollmentId, status: 'PENDING', courseId: course.id });
});
app.get('/api/enrollments/:enrollmentId', (request, response) => {
  const enrollment = database.prepare('SELECT * FROM enrollments WHERE id = ?').get(request.params.enrollmentId);
  if (!enrollment) return response.status(404).json({ error: 'Enrollment not found' });
  response.json(enrollment);
});
app.get('/api/courses/:courseId/content', (request, response) => {
  const email = String(request.query.email || '').trim().toLowerCase();
  const enrollment = database.prepare("SELECT id FROM enrollments WHERE course_id = ? AND lower(user_email) = ? AND status = 'APPROVED' ORDER BY updated_at DESC LIMIT 1").get(request.params.courseId, email);
  if (!enrollment) return response.status(403).json({ error: 'Approved enrollment required' });
  response.json(database.prepare("SELECT * FROM content WHERE kind = 'course' AND json_extract(metadata, '$.courseId') = ? ORDER BY updated_at DESC").all(request.params.courseId));
});
app.post('/api/admin/enrollments', adminOnly, (request, response) => {
  const rows = database.prepare('SELECT * FROM enrollments ORDER BY created_at DESC').all();
  response.json(rows);
});
app.get('/api/admin/enrollments', adminOnly, (_request, response) => response.json(database.prepare('SELECT * FROM enrollments ORDER BY created_at DESC').all()));
app.patch('/api/admin/enrollments/:enrollmentId', adminOnly, (request, response) => {
  const input = z.object({ status: z.enum(['PENDING', 'APPROVED', 'REJECTED']) }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const result = database.prepare('UPDATE enrollments SET status = ?, updated_at = ? WHERE id = ?').run(input.data.status, now(), request.params.enrollmentId);
  if (!result.changes) return response.status(404).json({ error: 'Enrollment not found' });
  response.json({ ok: true, status: input.data.status });
});
app.get('/api/admin/payments', adminOnly, (_request, response) => response.json(database.prepare('SELECT * FROM payments ORDER BY created_at DESC').all()));
app.patch('/api/admin/payments/:paymentId', adminOnly, (request, response) => {
  const status = z.object({ status: z.enum(['APPROVED', 'REJECTED', 'PENDING']) }).safeParse(request.body);
  if (!status.success) return response.status(400).json({ error: status.error.flatten() });
  const result = database.prepare('UPDATE payments SET status = ?, updated_at = ? WHERE id = ?').run(status.data.status, now(), request.params.paymentId);
  if (!result.changes) return response.status(404).json({ error: 'Payment not found' });
  response.json({ ok: true });
});

app.get('/api/admin/settings', adminOnly, (_request, response) => {
  const values = Object.fromEntries(database.prepare('SELECT key, value FROM settings').all().map((row) => {
    const value = JSON.parse(row.value);
    const secret = /password|secret|token|private.?key|api.?key/i.test(row.key);
    return [row.key, secret ? { configured: Boolean(value), masked: '********' } : value];
  }));
  response.json(values);
});
app.put('/api/admin/settings/:key', adminOnly, (request, response) => {
  const key = z.string().regex(/^[a-zA-Z0-9_.-]{1,80}$/).parse(request.params.key);
  if (key === 'system.jwtSecret') return response.status(403).json({ error: 'JWT secret cannot be changed through the API' });
  const value = z.unknown().parse(request.body.value);
  database.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').run(key, JSON.stringify(value), now());
  response.json({ ok: true });
});

app.get('/api/admin/settings/health', adminOnly, (_request, response) => response.json({
  backend: true,
  firebaseConfigured: Boolean(setting('firebase.serviceAccount')),
  oneSignalConfigured: Boolean(setting('onesignal.appId') && setting('onesignal.restApiKey')),
  paymentConfigured: Boolean(settingText('payment.upiId') || settingText('payment.qrCodeUrl'))
}));

const maxBytes = Number(process.env.MAX_UPLOAD_MB || 100) * 1024 * 1024;
const upload = multer({ limits: { fileSize: maxBytes }, storage: multer.diskStorage({ destination: uploadDir, filename: (_request, file, callback) => callback(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`) }) });
app.post('/api/admin/uploads', adminOnly, upload.single('file'), (request, response) => {
  if (!request.file) return response.status(400).json({ error: 'file is required' });
  response.status(201).json({ url: `/uploads/${request.file.filename}`, originalName: request.file.originalname, bytes: request.file.size });
});
app.post('/api/uploads/payment-proof', upload.single('file'), (request, response) => {
  if (!request.file) return response.status(400).json({ error: 'file is required' });
  response.status(201).json({ url: `/uploads/${request.file.filename}`, originalName: request.file.originalname, bytes: request.file.size });
});
app.post('/api/admin/payment-settings', adminOnly, upload.single('qrCode'), (request, response) => {
  const input = z.object({ upiId: z.string().max(200).optional(), whatsappNumber: z.string().max(40).optional() }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const values = { 'payment.upiId': input.data.upiId || '', 'payment.whatsappNumber': input.data.whatsappNumber || '' };
  if (request.file) values['payment.qrCodeUrl'] = `/uploads/${request.file.filename}`;
  const statement = database.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at');
  const timestamp = now(); database.transaction(() => Object.entries(values).forEach(([key, value]) => statement.run(key, JSON.stringify(value), timestamp)))();
  response.json({ ok: true, paymentSettings: { upiId: values['payment.upiId'], whatsappNumber: values['payment.whatsappNumber'], qrCodeUrl: settingText('payment.qrCodeUrl') } });
});

app.post('/api/users/register-fcm-token', (request, response) => {
  const input = z.object({ token: z.string().min(20).max(4096), userEmail: z.string().email().optional() }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const timestamp = now();
  database.prepare('INSERT INTO fcm_tokens (token, user_email, created_at, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(token) DO UPDATE SET user_email = excluded.user_email, updated_at = excluded.updated_at').run(input.data.token, input.data.userEmail || null, timestamp, timestamp);
  response.status(201).json({ ok: true });
});

app.post('/api/admin/send-notification', adminOnly, async (request, response) => {
  const input = z.object({ title: z.string().min(1).max(200), body: z.string().min(1).max(5000), imageUrl: z.string().url().optional(), data: z.record(z.string()).default({}), topic: z.string().regex(/^[a-zA-Z0-9_-]{1,80}$/).default('all_users') }).safeParse(request.body);
  if (!input.success) return response.status(400).json({ error: input.error.flatten() });
  const results = [];
  const messaging = firebaseMessaging();
  if (messaging) {
    try {
      results.push({ provider: 'fcm', id: await messaging.send({ topic: input.data.topic, notification: { title: input.data.title, body: input.data.body, ...(input.data.imageUrl ? { imageUrl: input.data.imageUrl } : {}) }, data: input.data.data }) });
    } catch (error) { results.push({ provider: 'fcm', error: error.message }); }
  }
  const oneSignalAppId = settingText('onesignal.appId'); const oneSignalKey = settingText('onesignal.restApiKey');
  if (oneSignalAppId && oneSignalKey) {
    const oneSignalResponse = await fetch('https://onesignal.com/api/v1/notifications', { method: 'POST', headers: { Authorization: `Basic ${oneSignalKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ app_id: oneSignalAppId, included_segments: ['Subscribed Users'], headings: { en: input.data.title }, contents: { en: input.data.body }, ...(input.data.imageUrl ? { big_picture: input.data.imageUrl } : {}) }) });
    results.push({ provider: 'onesignal', ok: oneSignalResponse.ok, response: await oneSignalResponse.json() });
  }
  if (!results.length) return response.status(503).json({ error: 'No push provider is configured in admin settings' });
  response.json({ ok: results.some((result) => result.id || result.ok), results });
});

app.use((error, _request, response, _next) => response.status(400).json({ error: error.message || 'Request failed' }));
app.listen(port, () => console.log(`Islamic Circle backend listening on :${port}`));
