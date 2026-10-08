const express = require('express');
const {
  login,
  logout,
  getSession,
  requestPasswordReset,
  confirmPasswordReset,
  setupMfa,
  verifyMfaSetup,
  disableMfa
} = require('../controllers/authController');
const { requireSessionAuth } = require('../middleware/sessionAuth');

const router = express.Router();

router.post('/login', login);
router.post('/logout', logout);
router.get('/session', requireSessionAuth, getSession);
router.post('/password-reset/request', requestPasswordReset);
router.post('/password-reset/confirm', confirmPasswordReset);
router.post('/mfa/setup', requireSessionAuth, setupMfa);
router.post('/mfa/verify', requireSessionAuth, verifyMfaSetup);
router.post('/mfa/disable', requireSessionAuth, disableMfa);

module.exports = router;
