# Islamic Circle Backend

This is a separate Node.js service for production content and admin operations. It stores courses, announcements, payments, app settings, and uploaded media in SQLite plus a local upload directory.

## Run locally

```bash
cd backend
cp .env.example .env
npm install
npm start
```

Set `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ALLOWED_ORIGINS` before deployment. `JWT_SECRET` is optional: when omitted, the service generates a random secret once and persists it in SQLite. Put object storage (S3-compatible storage or your store's media service) behind the upload endpoint for multi-instance deployments; local uploads are suitable only for a single persistent server.

## Admin API

1. `POST /api/admin/login` returns an 8-hour admin bearer token.
2. Send `Authorization: Bearer <token>` to admin endpoints.
3. Use `/api/admin/uploads` for video/audio/banner files.
4. Use `/api/admin/enrollments` and `PATCH /api/admin/enrollments/:id` to review manual payment submissions.
5. Store payment values through `/api/admin/payment-settings` and provider credentials through `/api/admin/settings/:key`; secret values are masked in admin reads and never returned to public endpoints.
6. Use `/api/admin/send-notification` after storing Firebase service-account JSON under `firebase.serviceAccount`, or OneSignal values under `onesignal.appId` and `onesignal.restApiKey`.

The mobile app includes the native FCM receiver and an admin backend configuration client. Remote course/content synchronization still requires setting your deployed backend base URL and wiring the remaining screen repositories; bundled content remains as an offline-safe fallback. Manual payment has no automated gateway: admins approve or reject each enrollment. Push delivery requires valid Firebase service-account or OneSignal credentials.