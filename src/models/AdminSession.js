const mongoose = require('mongoose');

const adminSessionSchema = new mongoose.Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true
    },
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Admin',
      required: true,
      index: true
    },
    expiresAt: {
      type: Date,
      required: true,
      expires: 0
    }
  },
  { timestamps: true, versionKey: false }
);

module.exports = mongoose.model('AdminSession', adminSessionSchema);
