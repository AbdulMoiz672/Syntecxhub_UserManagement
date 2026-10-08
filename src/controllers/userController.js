const mongoose = require('mongoose');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { errorResponse } = require('../utils/responses');

const ALLOWED_FIELDS = ['name', 'email', 'phone'];
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SORT_FIELDS = ['name', 'email', 'createdAt', 'updatedAt'];
const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 100;
const NETWORK_ERROR_CODES = new Set([6, 7, 89, 91, 11600, 11602, 13435, 13436]);

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parsePositiveInteger(value, fallback) {
  if (value === undefined) return fallback;
  if (!/^[1-9]\d*$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

async function recordAudit({ action, user, actor, changedFields }) {
  try {
    await AuditLog.create({
      action,
      userId: String(user._id),
      userEmail: user.email,
      actor,
      changedFields
    });
  } catch (error) {
    error.auditWriteFailed = true;
    throw error;
  }
}

function auditFailure(res) {
  return res.status(500).json({
    error: {
      code: 'AUDIT_LOG_FAILURE',
      message: 'The user change completed, but its audit event could not be saved. Verify the current user state before retrying.'
    }
  });
}

function databaseFailure(res, message, error) {
  const unavailable = mongoose.connection.readyState !== 1 ||
    error?.name === 'MongoServerSelectionError' ||
    NETWORK_ERROR_CODES.has(error?.code);
  return res.status(unavailable ? 503 : 500).json({
    error: {
      code: unavailable ? 'SERVICE_UNAVAILABLE' : 'DATABASE_ERROR',
      message: unavailable ? 'The database is temporarily unavailable.' : message
    }
  });
}

function normalizePayload(payload, { allowPartial = false } = {}) {
  const details = [];
  const data = {};

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      error: errorResponse('VALIDATION_ERROR', 'Request body must be a JSON object.', null, 400)
    };
  }

  const unknownFields = Object.keys(payload).filter((field) => !ALLOWED_FIELDS.includes(field));
  if (unknownFields.length > 0) {
    return {
      error: errorResponse(
        'VALIDATION_ERROR',
        'Unsupported fields provided.',
        unknownFields.map((field) => ({ field, message: `Field "${field}" is not allowed.` })),
        400
      )
    };
  }

  if (!allowPartial) {
    if (!Object.prototype.hasOwnProperty.call(payload, 'name') || payload.name === undefined) {
      details.push({ field: 'name', message: 'Name is required.' });
    }

    if (!Object.prototype.hasOwnProperty.call(payload, 'email') || payload.email === undefined) {
      details.push({ field: 'email', message: 'Email is required.' });
    }
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'name')) {
    const value = typeof payload.name === 'string' ? payload.name.trim() : payload.name;
    if (value === '' || value === null || value === undefined) {
      details.push({ field: 'name', message: 'Name cannot be blank.' });
    } else if (value.length < 2 || value.length > 100) {
      details.push({ field: 'name', message: 'Name must be between 2 and 100 characters.' });
    } else {
      data.name = value;
    }
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'email')) {
    const value = typeof payload.email === 'string' ? payload.email.trim().toLowerCase() : payload.email;
    if (value === '' || value === null || value === undefined) {
      details.push({ field: 'email', message: 'Email cannot be blank.' });
    } else if (!EMAIL_REGEX.test(value) || value.length > 254) {
      details.push({ field: 'email', message: 'Email must be a valid email address.' });
    } else {
      data.email = value;
    }
  }

  if (Object.prototype.hasOwnProperty.call(payload, 'phone')) {
    const value = typeof payload.phone === 'string' ? payload.phone.trim() : payload.phone;
    if (value === null || value === undefined || value === '') {
      details.push({ field: 'phone', message: 'Phone cannot be blank if provided.' });
    } else if (!/^(?:\+)?[0-9]{7,15}$/.test(value)) {
      details.push({ field: 'phone', message: 'Phone must be 7 to 15 digits with an optional leading +.' });
    } else {
      data.phone = value;
    }
  }

  if (details.length > 0) {
    return {
      error: errorResponse('VALIDATION_ERROR', 'Validation failed.', details, 400)
    };
  }

  if (allowPartial && Object.keys(data).length === 0) {
    return {
      error: errorResponse('VALIDATION_ERROR', 'At least one valid field must be supplied for update.', null, 400)
    };
  }

  return { value: data };
}

async function listUsers(req, res) {
  const page = parsePositiveInteger(req.query.page, 1);
  const requestedLimit = parsePositiveInteger(req.query.limit, DEFAULT_PAGE_SIZE);
  const sort = req.query.sort || 'createdAt';
  const order = req.query.order || 'desc';
  const hasPhone = req.query.hasPhone;

  if (page === null || requestedLimit === null) {
    return res.status(400).json({
      error: { code: 'INVALID_QUERY', message: 'page and limit must be positive integers.' }
    });
  }

  if (!SORT_FIELDS.includes(sort) || !['asc', 'desc'].includes(order)) {
    return res.status(400).json({
      error: { code: 'INVALID_QUERY', message: 'sort or order is not supported.' }
    });
  }

  if (hasPhone !== undefined && !['true', 'false'].includes(hasPhone)) {
    return res.status(400).json({
      error: { code: 'INVALID_QUERY', message: 'hasPhone must be true or false.' }
    });
  }

  const limit = Math.min(requestedLimit, MAX_PAGE_SIZE);
  const conditions = [];
  const search = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (search.length > 100) {
    return res.status(400).json({
      error: { code: 'INVALID_QUERY', message: 'q must be no longer than 100 characters.' }
    });
  }
  if (search) {
    const safeSearch = new RegExp(escapeRegex(search), 'i');
    conditions.push({ $or: [{ name: safeSearch }, { email: safeSearch }] });
  }
  if (hasPhone === 'true') conditions.push({ phone: { $exists: true, $ne: null } });
  if (hasPhone === 'false') conditions.push({ phone: null });
  const filter = conditions.length > 1
    ? { $and: conditions }
    : (conditions[0] || {});

  try {
    const sortDirection = order === 'asc' ? 1 : -1;
    const [users, total] = await Promise.all([
      User.find(filter)
        .sort({ [sort]: sortDirection, _id: sortDirection })
        .skip((page - 1) * limit)
        .limit(limit),
      User.countDocuments(filter)
    ]);

    return res.status(200).json({
      data: users,
      meta: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        sort,
        order
      }
    });
  } catch (error) {
    return databaseFailure(res, 'Unable to fetch users.', error);
  }
}

async function listAuditLogs(req, res) {
  const page = parsePositiveInteger(req.query.page, 1);
  const requestedLimit = parsePositiveInteger(req.query.limit, DEFAULT_PAGE_SIZE);
  if (page === null || requestedLimit === null) {
    return res.status(400).json({
      error: { code: 'INVALID_QUERY', message: 'page and limit must be positive integers.' }
    });
  }

  const limit = Math.min(requestedLimit, MAX_PAGE_SIZE);
  try {
    const [entries, total] = await Promise.all([
      AuditLog.find({})
        .sort({ createdAt: -1, _id: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('action userId userEmail actor changedFields createdAt'),
      AuditLog.countDocuments({})
    ]);

    return res.status(200).json({
      data: entries,
      meta: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (error) {
    return databaseFailure(res, 'Unable to fetch audit history.', error);
  }
}

async function getUserById(req, res) {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      error: {
        code: 'INVALID_ID',
        message: 'User ID is invalid.'
      }
    });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found.'
        }
      });
    }

    return res.status(200).json({ data: user });
  } catch (error) {
    return databaseFailure(res, 'Unable to fetch user.', error);
  }
}

async function createUser(req, res) {
  if (!req.is('application/json')) {
    return res.status(415).json({
      error: {
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'Content-Type must be application/json.'
      }
    });
  }

  const payload = normalizePayload(req.body, { allowPartial: false });
  if (payload.error) {
    return res.status(payload.error.statusCode || 400).json(payload.error.body);
  }

  try {
    const user = await User.create(payload.value);
    await recordAudit({
      action: 'create',
      user,
      actor: req.authenticatedUser.username,
      changedFields: Object.keys(payload.value)
    });
    return res.status(201).json({ data: user });
  } catch (error) {
    if (error.auditWriteFailed) return auditFailure(res);
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(409).json({
        error: {
          code: 'EMAIL_EXISTS',
          message: 'A user with this email already exists.'
        }
      });
    }

    return databaseFailure(res, 'Unable to create user.', error);
  }
}

async function updateUser(req, res) {
  if (!req.is('application/json')) {
    return res.status(415).json({
      error: {
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'Content-Type must be application/json.'
      }
    });
  }

  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      error: {
        code: 'INVALID_ID',
        message: 'User ID is invalid.'
      }
    });
  }

  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).length === 0) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Update payload cannot be empty.'
      }
    });
  }

  const payload = normalizePayload(req.body, { allowPartial: true });
  if (payload.error) {
    return res.status(payload.error.statusCode || 400).json(payload.error.body);
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found.'
        }
      });
    }

    const changedFields = Object.keys(payload.value).filter(
      (field) => user[field] !== payload.value[field]
    );
    Object.assign(user, payload.value);
    await user.save();
    if (changedFields.length > 0) {
      await recordAudit({
        action: 'update',
        user,
        actor: req.authenticatedUser.username,
        changedFields
      });
    }

    return res.status(200).json({ data: user });
  } catch (error) {
    if (error.auditWriteFailed) return auditFailure(res);
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      return res.status(409).json({
        error: {
          code: 'EMAIL_EXISTS',
          message: 'A user with this email already exists.'
        }
      });
    }

    return databaseFailure(res, 'Unable to update user.', error);
  }
}

async function deleteUser(req, res) {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({
      error: {
        code: 'INVALID_ID',
        message: 'User ID is invalid.'
      }
    });
  }

  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        error: {
          code: 'NOT_FOUND',
          message: 'User not found.'
        }
      });
    }

    await User.findByIdAndDelete(id);
    await recordAudit({
      action: 'delete',
      user,
      actor: req.authenticatedUser.username,
      changedFields: ALLOWED_FIELDS.filter((field) => user[field] !== undefined && user[field] !== null)
    });
    return res.status(204).send();
  } catch (error) {
    if (error.auditWriteFailed) return auditFailure(res);
    return databaseFailure(res, 'Unable to delete user.', error);
  }
}

module.exports = {
  listUsers,
  listAuditLogs,
  getUserById,
  createUser,
  updateUser,
  deleteUser
};
