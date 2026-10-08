const { randomBytes } = require('crypto');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const Admin = require('../models/Admin');
const AdminSession = require('../models/AdminSession');
const { env } = require('../config/env');
const {
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  encryptTotpSecret,
  decryptTotpSecret,
  verifyTotp,
  hashToken
} = require('../utils/auth');

const SESSION_COOKIE = 'um_session';
const SESSION_MAX_AGE = env.SESSION_TTL_HOURS * 60 * 60 * 1000;
const RESET_TOKEN_MAX_AGE = 30 * 60 * 1000;
const TOTP_SETUP_MAX_AGE = 10 * 60 * 1000;

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api',
    maxAge
  };
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api'
  });
}

async function createSession(admin, res) {
  const token = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_MAX_AGE);
  await AdminSession.create({ tokenHash: hashToken(token), adminId: admin._id, expiresAt });
  res.cookie(SESSION_COOKIE, token, cookieOptions(SESSION_MAX_AGE));
}

async function login(req, res, next) {
  const { username, password, totpCode } = req.body || {};
  if (typeof username !== 'string' || !username.trim() || username.trim().length > 100 ||
      typeof password !== 'string' || !password || password.length > 128) {
    return res.status(400).json({
      error: { code: 'VALIDATION_ERROR', message: 'Enter a username (up to 100 characters) and password (up to 128 characters).' }
    });
  }

  try {
    const admin = await Admin.findOne({ singleton: true });
    const passwordValid = admin && admin.username === username.trim() &&
      await verifyPassword(password, admin.passwordHash);
    if (!passwordValid) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid username or password.' } });
    }

    if (admin.mfaEnabled) {
      if (!env.MFA_ENCRYPTION_KEY) {
        return res.status(503).json({
          error: { code: 'MFA_NOT_CONFIGURED', message: 'MFA_ENCRYPTION_KEY is missing. Contact the system operator.' }
        });
      }
      if (typeof totpCode !== 'string') {
        return res.status(200).json({ mfaRequired: true });
      }
      if (!verifyTotp(decryptTotpSecret(admin.totpSecretEncrypted, env.MFA_ENCRYPTION_KEY), totpCode)) {
        return res.status(401).json({ error: { code: 'INVALID_MFA_CODE', message: 'Invalid authenticator code.' } });
      }
    }

    await createSession(admin, res);
    return res.status(200).json({ authenticated: true });
  } catch (error) {
    return next(error);
  }
}

async function logout(req, res, next) {
  try {
    const cookie = req.headers.cookie || '';
    const sessionCookie = cookie.split(';').map((part) => part.trim())
      .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
    if (sessionCookie) {
      try {
        const token = decodeURIComponent(sessionCookie.slice(SESSION_COOKIE.length + 1));
        await AdminSession.deleteOne({ tokenHash: hashToken(token) });
      } catch (error) {
        if (!(error instanceof URIError)) throw error;
      }
    }
    clearSessionCookie(res);
    return res.status(204).send();
  } catch (error) {
    return next(error);
  }
}

async function getSession(req, res) {
  return res.status(200).json({
    authenticated: true,
    username: req.admin.username,
    mfaEnabled: req.admin.mfaEnabled
  });
}

async function requestPasswordReset(req, res, next) {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Enter a valid email address.' } });
  }

  const gmailCredentialsMissing = env.SMTP_HOST.toLowerCase() === 'smtp.gmail.com' &&
    (!env.SMTP_USER || !env.SMTP_PASSWORD);
  const missingSettings = [
    ...(!env.ADMIN_EMAIL ? ['ADMIN_EMAIL'] : []),
    ...(!env.SMTP_HOST ? ['SMTP_HOST'] : []),
    ...(!env.SMTP_FROM ? ['SMTP_FROM'] : []),
    ...(gmailCredentialsMissing
      ? [
          ...(!env.SMTP_USER ? ['SMTP_USER'] : []),
          ...(!env.SMTP_PASSWORD ? ['SMTP_PASSWORD (Google App Password)'] : [])
        ]
      : [])
  ];
  if (missingSettings.length > 0) {
    console.error('Password reset requested, but email delivery settings or required Gmail SMTP credentials are missing.');
    return res.status(503).json({
      error: {
        code: 'EMAIL_UNAVAILABLE',
        message: `Password reset email is not fully configured. Set ${missingSettings.join(', ')} in .env, then restart the server.`
      }
    });
  }

  try {
    const admin = await Admin.findOne({ singleton: true, email });
    if (admin) {
      const token = randomBytes(32).toString('hex');
      admin.resetTokenHash = hashToken(token);
      admin.resetTokenExpiresAt = new Date(Date.now() + RESET_TOKEN_MAX_AGE);
      await admin.save();

      const frontendOrigin = env.FRONTEND_ORIGIN === '*'
        ? `http://localhost:${env.PORT}`
        : env.FRONTEND_ORIGIN.split(',')[0].trim();
      const resetUrl = new URL('/', frontendOrigin);
      resetUrl.searchParams.set('resetToken', token);
      const transport = nodemailer.createTransport({
        host: env.SMTP_HOST,
        port: env.SMTP_PORT,
        secure: env.SMTP_SECURE,
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 20000,
        ...(env.SMTP_USER ? { auth: { user: env.SMTP_USER, pass: env.SMTP_PASSWORD } } : {})
      });
      try {
        await transport.sendMail({
          from: env.SMTP_FROM,
          to: admin.email,
          subject: 'User Management password reset',
          text: `Use this link to reset your password. It expires in 30 minutes and can only be used once:\n\n${resetUrl.href}\n`
        });
      } catch (error) {
        admin.resetTokenHash = undefined;
        admin.resetTokenExpiresAt = undefined;
        await admin.save();
        console.error('Unable to send password reset email:', error.message);
        return res.status(502).json({
          error: { code: 'EMAIL_DELIVERY_FAILED', message: 'Unable to send reset email. Please try again later.' }
        });
      }
    }
    return res.status(202).json({ message: 'If the administrator email matches, reset instructions will be sent.' });
  } catch (error) {
    return next(error);
  }
}

async function confirmPasswordReset(req, res, next) {
  const { token, password } = req.body || {};
  if (typeof token !== 'string' || !/^[a-f0-9]{64}$/i.test(token) ||
      typeof password !== 'string' || password.length < 12 || password.length > 128) {
    return res.status(400).json({
      error: { code: 'VALIDATION_ERROR', message: 'Use a valid reset link and a password between 12 and 128 characters.' }
    });
  }

  try {
    const admin = await Admin.findOneAndUpdate(
      {
        singleton: true,
        resetTokenHash: hashToken(token),
        resetTokenExpiresAt: { $gt: new Date() }
      },
      { $unset: { resetTokenHash: 1, resetTokenExpiresAt: 1 } },
      { new: true }
    );
    if (!admin) {
      return res.status(400).json({
        error: { code: 'INVALID_RESET_TOKEN', message: 'This reset link is invalid or expired. Request another.' }
      });
    }

    admin.passwordHash = await hashPassword(password);
    await admin.save();
    await AdminSession.deleteMany({ adminId: admin._id });
    clearSessionCookie(res);
    return res.status(200).json({ message: 'Password updated. Sign in with your new password.' });
  } catch (error) {
    return next(error);
  }
}

async function setupMfa(req, res, next) {
  if (!env.MFA_ENCRYPTION_KEY) {
    return res.status(503).json({
      error: { code: 'MFA_NOT_CONFIGURED', message: 'MFA_ENCRYPTION_KEY must be configured before setting up MFA.' }
    });
  }
  try {
    const secret = generateTotpSecret();
    req.admin.pendingTotpSecretEncrypted = encryptTotpSecret(secret, env.MFA_ENCRYPTION_KEY);
    req.admin.pendingTotpExpiresAt = new Date(Date.now() + TOTP_SETUP_MAX_AGE);
    await req.admin.save();

    const label = encodeURIComponent(`User Management:${req.admin.username}`);
    const issuer = encodeURIComponent('User Management');
    const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
    return res.status(200).json({ secret, qrCodeDataUrl });
  } catch (error) {
    return next(error);
  }
}

async function verifyMfaSetup(req, res, next) {
  const { code } = req.body || {};
  if (!env.MFA_ENCRYPTION_KEY) {
    return res.status(503).json({
      error: { code: 'MFA_NOT_CONFIGURED', message: 'MFA_ENCRYPTION_KEY must be configured before verifying MFA.' }
    });
  }
  if (!req.admin.pendingTotpSecretEncrypted || !req.admin.pendingTotpExpiresAt ||
      req.admin.pendingTotpExpiresAt <= new Date()) {
    return res.status(400).json({ error: { code: 'MFA_SETUP_EXPIRED', message: 'Start MFA setup again to get a fresh QR code.' } });
  }
  try {
    const pendingSecret = decryptTotpSecret(req.admin.pendingTotpSecretEncrypted, env.MFA_ENCRYPTION_KEY);
    if (!verifyTotp(pendingSecret, code)) {
      return res.status(400).json({ error: { code: 'INVALID_MFA_CODE', message: 'Authenticator code is invalid.' } });
    }

    req.admin.totpSecretEncrypted = req.admin.pendingTotpSecretEncrypted;
    req.admin.pendingTotpSecretEncrypted = undefined;
    req.admin.pendingTotpExpiresAt = undefined;
    req.admin.mfaEnabled = true;
    await req.admin.save();
    return res.status(200).json({ mfaEnabled: true });
  } catch (error) {
    return next(error);
  }
}

async function disableMfa(req, res, next) {
  const { code } = req.body || {};
  if (!env.MFA_ENCRYPTION_KEY) {
    return res.status(503).json({
      error: { code: 'MFA_NOT_CONFIGURED', message: 'MFA_ENCRYPTION_KEY is missing. Contact the system operator.' }
    });
  }
  try {
    if (!req.admin.mfaEnabled ||
        !verifyTotp(decryptTotpSecret(req.admin.totpSecretEncrypted, env.MFA_ENCRYPTION_KEY), code)) {
      return res.status(400).json({ error: { code: 'INVALID_MFA_CODE', message: 'Authenticator code is invalid.' } });
    }

    req.admin.totpSecretEncrypted = undefined;
    req.admin.pendingTotpSecretEncrypted = undefined;
    req.admin.pendingTotpExpiresAt = undefined;
    req.admin.mfaEnabled = false;
    await req.admin.save();
    return res.status(200).json({ mfaEnabled: false });
  } catch (error) {
    return next(error);
  }
}

module.exports = {
  login,
  logout,
  getSession,
  requestPasswordReset,
  confirmPasswordReset,
  setupMfa,
  verifyMfaSetup,
  disableMfa
};
