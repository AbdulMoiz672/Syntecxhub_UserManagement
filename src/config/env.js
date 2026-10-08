require('dotenv').config();

const requiredEnv = ['MONGODB_URI', 'API_USERNAME', 'API_PASSWORD'];

const env = {
  PORT: Number(process.env.PORT || 3000),
  MONGODB_URI: process.env.MONGODB_URI,
  API_USERNAME: process.env.API_USERNAME,
  API_PASSWORD: process.env.API_PASSWORD,
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || '',
  SMTP_HOST: process.env.SMTP_HOST || '',
  SMTP_PORT: Number(process.env.SMTP_PORT || 587),
  SMTP_SECURE: process.env.SMTP_SECURE === 'true',
  SMTP_USER: process.env.SMTP_USER || '',
  SMTP_PASSWORD: process.env.SMTP_PASSWORD || '',
  SMTP_FROM: process.env.SMTP_FROM || '',
  MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY || '',
  SESSION_TTL_HOURS: Number(process.env.SESSION_TTL_HOURS || 8),
  FRONTEND_ORIGIN: process.env.FRONTEND_ORIGIN || '*',
  NODE_ENV: process.env.NODE_ENV || 'development',
  TRUST_PROXY_HOPS: Number(process.env.TRUST_PROXY_HOPS || 0)
};

for (const key of requiredEnv) {
  if (!env[key] || !String(env[key]).trim()) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
}

if (!Number.isInteger(env.PORT) || env.PORT < 1 || env.PORT > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535.');
}

if (!Number.isInteger(env.TRUST_PROXY_HOPS) || env.TRUST_PROXY_HOPS < 0 || env.TRUST_PROXY_HOPS > 10) {
  throw new Error('TRUST_PROXY_HOPS must be an integer between 0 and 10.');
}

if (!Number.isInteger(env.SMTP_PORT) || env.SMTP_PORT < 1 || env.SMTP_PORT > 65535) {
  throw new Error('SMTP_PORT must be an integer between 1 and 65535.');
}

if (process.env.SMTP_SECURE && !['true', 'false'].includes(process.env.SMTP_SECURE)) {
  throw new Error('SMTP_SECURE must be true or false.');
}

if (env.SMTP_PASSWORD && !env.SMTP_USER) {
  throw new Error('SMTP_USER is required when SMTP_PASSWORD is set.');
}

if (env.ADMIN_EMAIL && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(env.ADMIN_EMAIL)) {
  throw new Error('ADMIN_EMAIL must be a valid email address.');
}

if (!Number.isInteger(env.SESSION_TTL_HOURS) || env.SESSION_TTL_HOURS < 1 || env.SESSION_TTL_HOURS > 720) {
  throw new Error('SESSION_TTL_HOURS must be an integer between 1 and 720.');
}

if (env.MFA_ENCRYPTION_KEY && !/^[a-f0-9]{64}$/i.test(env.MFA_ENCRYPTION_KEY)) {
  throw new Error('MFA_ENCRYPTION_KEY must be a 32-byte key encoded as 64 hexadecimal characters.');
}

if (env.NODE_ENV === 'production') {
  if (
    env.API_PASSWORD.length < 16 ||
    env.API_PASSWORD === 'admin123' ||
    env.API_PASSWORD === env.API_USERNAME ||
    env.API_PASSWORD.startsWith('replace-with-')
  ) {
    throw new Error('In production, API_PASSWORD must be a unique secret of at least 16 characters and must not be an example value.');
  }

  if (env.API_USERNAME.startsWith('replace-with-')) {
    throw new Error('In production, API_USERNAME must be a real operator name.');
  }

  if (env.FRONTEND_ORIGIN === '*' || !env.FRONTEND_ORIGIN.trim()) {
    throw new Error('In production, FRONTEND_ORIGIN must explicitly list the allowed frontend origin(s).');
  }

  const origins = env.FRONTEND_ORIGIN.split(',').map((origin) => origin.trim());
  if (origins.some((origin) => {
    try {
      const parsedOrigin = new URL(origin);
      return parsedOrigin.protocol !== 'https:' || parsedOrigin.origin !== origin;
    } catch (error) {
      return true;
    }
  })) {
    throw new Error('In production, each FRONTEND_ORIGIN must be a valid HTTPS origin.');
  }

  if (!env.ADMIN_EMAIL || !env.SMTP_HOST || !env.SMTP_FROM || !env.MFA_ENCRYPTION_KEY) {
    throw new Error('In production, ADMIN_EMAIL, SMTP_HOST, SMTP_FROM, and MFA_ENCRYPTION_KEY are required for authentication security features.');
  }
}

module.exports = { env };
