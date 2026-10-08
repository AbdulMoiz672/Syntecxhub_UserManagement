const test = require('node:test');
const assert = require('node:assert/strict');
const {
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  encryptTotpSecret,
  decryptTotpSecret,
  verifyTotp,
  hashToken
} = require('../src/utils/auth');

test('password hashes verify only the original password', async () => {
  const hash = await hashPassword('long-and-random-password');
  assert.equal(await verifyPassword('long-and-random-password', hash), true);
  assert.equal(await verifyPassword('different-password', hash), false);
});

test('TOTP verification matches RFC 6238 SHA-1 test vector', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(verifyTotp(secret, '287082', 59000), true);
  assert.equal(verifyTotp(secret, '287083', 59000), false);
});

test('MFA secrets are encrypted at rest and can be recovered with the configured key', () => {
  const secret = generateTotpSecret();
  const key = 'a'.repeat(64);
  const encrypted = encryptTotpSecret(secret, key);
  assert.notEqual(encrypted, secret);
  assert.equal(decryptTotpSecret(encrypted, key), secret);
  assert.throws(() => decryptTotpSecret(encrypted, 'b'.repeat(64)));
});

test('session and reset tokens are stored as irreversible hashes', () => {
  const token = 'f'.repeat(64);
  const hash = hashToken(token);
  assert.notEqual(hash, token);
  assert.equal(hash, hashToken(token));
});
