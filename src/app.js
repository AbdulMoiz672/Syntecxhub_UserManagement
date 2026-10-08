const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { env } = require('./config/env');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();
app.set('trust proxy', env.TRUST_PROXY_HOPS || false);

const allowedOrigins = env.FRONTEND_ORIGIN === '*'
  ? '*'
  : (env.FRONTEND_ORIGIN || '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const isAllowedOrigin = env.FRONTEND_ORIGIN === '*' || (!origin || allowedOrigins.includes(origin));

  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', env.FRONTEND_ORIGIN === '*' ? '*' : (origin || env.FRONTEND_ORIGIN));
    res.setHeader('Vary', 'Origin');
    if (env.FRONTEND_ORIGIN !== '*') {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  }

  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler(req, res) {
    return res.status(429).json({
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests. Please try again later.'
      }
    });
  }
});

app.use(express.static(path.join(__dirname, '../public')));
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

function createAuthLimiter({ windowMs, limit, code, message, skipSuccessfulRequests = false }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests,
    message: { error: { code, message } }
  });
}

const loginLimiter = createAuthLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  code: 'LOGIN_RATE_LIMIT_EXCEEDED',
  message: 'Too many failed sign-in attempts. Please wait before trying again.',
  skipSuccessfulRequests: true
});
const resetRequestLimiter = createAuthLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
  message: 'Too many password-reset requests. Please wait before requesting another.'
});
const resetConfirmLimiter = createAuthLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
  message: 'Too many password-reset attempts. Please wait before trying again.'
});
const mfaVerifyLimiter = createAuthLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  code: 'MFA_RATE_LIMIT_EXCEEDED',
  message: 'Too many authenticator code attempts. Please wait before trying again.'
});

app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/password-reset/request', resetRequestLimiter);
app.use('/api/auth/password-reset/confirm', resetConfirmLimiter);
app.use('/api/auth/mfa/verify', mfaVerifyLimiter);
app.use('/api/auth/mfa/disable', mfaVerifyLimiter);
app.use('/api/auth', authRoutes);
app.use('/api/users', apiLimiter, userRoutes);

app.use((req, res) => {
  res.status(404).json({
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found.'
    }
  });
});

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({
      error: {
        code: 'INVALID_JSON',
        message: 'Malformed JSON payload.'
      }
    });
  }

  if (error && error.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: {
        code: 'INVALID_JSON',
        message: 'Malformed JSON payload.'
      }
    });
  }

  console.error('Unhandled request error:', error.message);
  return res.status(500).json({
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Unexpected server error.'
    }
  });
});

module.exports = app;
