const { promisify } = require('util');
const {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt: scryptCallback,
  timingSafeEqual
} = require('crypto');

const scrypt = promisify(scryptCallback);
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  const [algorithm, saltHex, hashHex] = String(storedHash).split('$');
  if (algorithm !== 'scrypt' || !/^[a-f0-9]{32}$/i.test(saltHex || '') || !/^[a-f0-9]{128}$/i.test(hashHex || '')) {
    return false;
  }

  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
  return timingSafeEqual(actual, expected);
}

function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value) {
  let bits = 0;
  let buffer = 0;
  const output = [];
  for (const character of value.toUpperCase().replace(/=+$/, '')) {
    const digit = BASE32_ALPHABET.indexOf(character);
    if (digit === -1) throw new Error('Invalid base32 secret.');
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTotpSecret() {
  return encodeBase32(randomBytes(20));
}

function encryptTotpSecret(secret, keyHex) {
  if (!/^[a-f0-9]{64}$/i.test(keyHex || '')) {
    throw new Error('MFA_ENCRYPTION_KEY must be configured as a 32-byte hexadecimal key.');
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ciphertext].map((part) => part.toString('hex')).join('.');
}

function decryptTotpSecret(encryptedSecret, keyHex) {
  if (!/^[a-f0-9]{64}$/i.test(keyHex || '')) {
    throw new Error('MFA_ENCRYPTION_KEY must be configured as a 32-byte hexadecimal key.');
  }
  const [ivHex, tagHex, ciphertextHex] = encryptedSecret.split('.');
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

function totpAt(secret, timestamp) {
  const counter = Math.floor(timestamp / 30000);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decodeBase32(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

function verifyTotp(secret, candidate, now = Date.now()) {
  if (typeof candidate !== 'string' || !/^\d{6}$/.test(candidate)) return false;
  for (const window of [-1, 0, 1]) {
    const expected = Buffer.from(totpAt(secret, now + window * 30000));
    const actual = Buffer.from(candidate);
    if (timingSafeEqual(expected, actual)) return true;
  }
  return false;
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  encryptTotpSecret,
  decryptTotpSecret,
  verifyTotp,
  hashToken
};
