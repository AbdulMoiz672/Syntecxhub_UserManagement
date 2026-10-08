const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 100
    },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      unique: true,
      maxlength: 254
    },
    phone: {
      type: String,
      trim: true,
      default: null,
      validate: {
        validator(value) {
          if (value === null || value === undefined || value === '') return true;
          return /^(?:\+)?[0-9]{7,15}$/.test(value);
        },
        message: 'Phone must be 7 to 15 digits with an optional leading +.'
      }
    }
  },
  {
    timestamps: true,
    versionKey: false,
    toJSON: {
      transform(doc, ret) {
        delete ret.__v;
      }
    }
  }
);

const User = mongoose.model('User', userSchema);

module.exports = User;
