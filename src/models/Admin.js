const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema(
  {
    singleton: {
      type: Boolean,
      unique: true,
      default: true
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    email: {
      type: String,
      default: '',
      lowercase: true,
      trim: true
    },
    passwordHash: {
      type: String,
      required: true
    },
    resetTokenHash: String,
    resetTokenExpiresAt: Date,
    totpSecretEncrypted: String,
    pendingTotpSecretEncrypted: String,
    pendingTotpExpiresAt: Date,
    mfaEnabled: {
      type: Boolean,
      default: false
    }
  },
  { timestamps: true, versionKey: false }
);

module.exports = mongoose.model('Admin', adminSchema);
