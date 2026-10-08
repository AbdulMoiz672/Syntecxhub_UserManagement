const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      enum: ['create', 'update', 'delete'],
      required: true
    },
    userId: {
      type: String,
      required: true,
      index: true
    },
    userEmail: {
      type: String,
      required: true
    },
    actor: {
      type: String,
      required: true
    },
    changedFields: {
      type: [String],
      default: []
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false
  }
);

auditLogSchema.index({ createdAt: -1, _id: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
