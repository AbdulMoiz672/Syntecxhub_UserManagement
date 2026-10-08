# User Management API

This project implements the user management API and a simple browser-based operator interface described in the provided functional requirements.

## Features

- Express.js REST API for CRUD user operations
- MongoDB persistence with Mongoose
- Single administrator account with MongoDB-backed, hashed password authentication
- Email-based password reset using one-time, expiring tokens
- Optional TOTP multi-factor authentication with QR-code enrollment
- HttpOnly, expiring server-side login sessions
- Validation for user name, email, and phone
- Consistent JSON response envelopes
- CORS support for separate frontend origins
- Responsive operator dashboard for login, CRUD, search, filtering, sorting, pagination, and audit history
- Request rate limiting and production configuration checks

## Prerequisites

- Node.js 18+
- MongoDB running locally or a reachable MongoDB Atlas connection string

## Setup

1. Install dependencies:
   npm install
2. Copy `.env.example` to `.env` and update values.
3. Start MongoDB.
4. Start the app:
   npm start

## Environment variables

- `PORT`: server port, default `3000`
- `MONGODB_URI`: Mongo connection string. This project uses the separate `user_management_api` database; do not point it at the `FileUploader` database.
- `API_USERNAME`: initial administrator username, used only when the MongoDB administrator account is first created
- `API_PASSWORD`: initial administrator password, used only when the MongoDB administrator account is first created
- `ADMIN_EMAIL`: email address for administrator password-reset messages
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`: SMTP server settings for password-reset delivery
- `MFA_ENCRYPTION_KEY`: 32-byte key encoded as 64 hexadecimal characters, used to encrypt TOTP secrets in MongoDB. Generate it with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` and keep it private and stable.
- `SESSION_TTL_HOURS`: server-side session lifetime in hours, default `8` (maximum `720`)
- `FRONTEND_ORIGIN`: frontend origin for CORS, default `*` for local development. Production requires an explicit origin (or comma-separated origin list).
- `NODE_ENV`: use `production` for deployment so production configuration checks are enforced.
- `TRUST_PROXY_HOPS`: number of trusted reverse proxies before the app, default `0`. Set this to the actual proxy hop count when deployed behind a proxy so rate limiting uses client IPs; do not set it unless the app is reachable only through that trusted proxy chain.

Never commit `.env` or share production credentials. Serve the deployed app behind HTTPS. In production, configure a strong initial password, administrator email, SMTP delivery, stable MFA encryption key, explicit HTTPS frontend origin(s), and the production database URI before starting the app.

The first server startup creates one administrator account from `API_USERNAME`, `API_PASSWORD`, and `ADMIN_EMAIL`; its password is stored as a scrypt hash. Later edits to `API_USERNAME` and `API_PASSWORD` do not overwrite the MongoDB account. Use the password-reset flow to change a bootstrapped password. Configure SMTP variables before requesting a reset. Reset tokens are random, stored only as hashes, expire after 30 minutes, and are invalidated after use. A password reset revokes all active sessions.

For Gmail delivery, set `SMTP_USER` to the sending Gmail address and `SMTP_PASSWORD` to a Google App Password (not the regular account password). Google requires 2-Step Verification to create an App Password. Keep the App Password only in the ignored `.env` file, then restart the server. The recipient is configured with `ADMIN_EMAIL`.

Password-reset email is optional and does not prevent the server from starting. If SMTP credentials are missing, the reset request responds with a configuration error; configure the Gmail App Password in `.env` and restart to enable delivery. `.env.example` is only a template and is not loaded by the application.

For a separately hosted frontend, configure exact `FRONTEND_ORIGIN` values and keep the frontend and API on the same site so the `SameSite=Strict` session cookie is sent.

The administrator can enable MFA from the account security controls after configuring `MFA_ENCRYPTION_KEY`. Scan the displayed QR code with an authenticator app and verify a current six-digit code to activate it. Once enabled, the code is required on each login. MFA secrets are encrypted at rest; losing or changing the encryption key prevents those secrets from being decrypted.

## MongoDB database naming convention

Use a unique, lowercase `snake_case` database name for each project:

`<project>_<purpose>_<environment>`

Examples:

- `user_management_api_dev`
- `file_uploader_files_dev`
- `inventory_api_test`
- `inventory_api_prod`

Use the same name in the URI path and when checking MongoDB Compass. Keep development, test, and production databases separate, and never reuse another project's database name. This project currently uses `user_management_api`; changing the database name later makes MongoDB connect to a different database, so migrate or back up any existing records before switching it.

## API routes

All routes under `/api/users` require an authenticated administrator session. Sign-in credentials are submitted to `/api/auth/login`; sessions are held in an HttpOnly cookie and stored server-side with an expiration.

Authentication routes:

- `POST /api/auth/login` — authenticate with username/password and, when enabled, a TOTP code
- `POST /api/auth/logout` — revoke the current session
- `GET /api/auth/session` — return the authenticated administrator and MFA status
- `POST /api/auth/password-reset/request` — send a reset link to the configured admin email
- `POST /api/auth/password-reset/confirm` — set a new password using an unexpired, unused token
- `POST /api/auth/mfa/setup` — generate an MFA enrollment QR code and manual key
- `POST /api/auth/mfa/verify` — verify enrollment and enable TOTP
- `POST /api/auth/mfa/disable` — disable TOTP using a valid current code

- `POST /api/users` — create a user
- `GET /api/users` — list users; accepts `q`, `hasPhone`, `page`, `limit`, `sort`, and `order`
- `GET /api/users/:id`
- `PATCH /api/users/:id`
- `DELETE /api/users/:id`
- `GET /api/users/audit` — paginated create/update/delete audit events

List query details:

- `q`: case-insensitive literal substring search across name and email
- `hasPhone`: `true` or `false`
- `page`: one-based page number (default `1`)
- `limit`: page size (default `10`, maximum `100`)
- `sort`: `name`, `email`, `createdAt`, or `updatedAt` (default `createdAt`)
- `order`: `asc` or `desc` (default `desc`)

List and audit responses include pagination values in `meta`. The API limits requests to 100 per IP in a 15-minute window and returns `429` when the limit is exceeded. The default limiter is in-memory; deployments with multiple API instances should configure a shared rate-limit store.

Authentication limits are applied only to sensitive operations: failed logins (10 per 15 minutes), password-reset requests (5 per hour), reset confirmations (10 per 15 minutes), and MFA code verification/disable attempts (10 per 15 minutes). Normal session checks and MFA setup do not consume those limits.

Every successful user create, update, or delete writes an audit event recording the administrator username, target user ID/email, action, changed field names, and timestamp. If the user operation succeeds but audit persistence fails, the API returns `500 AUDIT_LOG_FAILURE` and tells the operator to verify current state before retrying.

## Notes

- Passwords are hashed with scrypt. Session identifiers and reset tokens are stored only as hashes. Authenticator secrets are encrypted with AES-256-GCM.
- Credentials are not stored in persistent browser storage; logout clears the session and its HttpOnly cookie.
- Signing out revokes the administrator's server-side session and clears the browser's in-memory credentials and cached user display. It does not delete user records or audit history; they remain stored in MongoDB and are available after the administrator signs in again.
- Response envelopes follow the project specification.
- Validation rejects malformed or unsupported fields.
- Audit events record changed field names, not before/after field values.
