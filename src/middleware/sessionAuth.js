const Admin = require('../models/Admin');
const AdminSession = require('../models/AdminSession');
const { hashToken } = require('../utils/auth');

function getSessionToken(req) {
  const cookieHeader = req.headers.cookie || '';
  const cookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith('um_session='));
  if (!cookie) return null;
  try {
    return decodeURIComponent(cookie.slice('um_session='.length));
  } catch (error) {
    return null;
  }
}

async function requireSessionAuth(req, res, next) {
  const token = getSessionToken(req);
  if (!token) {
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required.' }
    });
  }

  try {
    const session = await AdminSession.findOne({
      tokenHash: hashToken(token),
      expiresAt: { $gt: new Date() }
    });
    if (!session) {
      return res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required.' }
      });
    }

    const admin = await Admin.findById(session.adminId);
    if (!admin) {
      await AdminSession.deleteOne({ _id: session._id });
      return res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Authentication required.' }
      });
    }
    req.authenticatedUser = { username: admin.username, adminId: admin._id };
    req.admin = admin;
    return next();
  } catch (error) {
    return next(error);
  }
}

module.exports = { requireSessionAuth };
