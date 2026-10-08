const mongoose = require('mongoose');
const { env } = require('./env');
const Admin = require('../models/Admin');
const { hashPassword } = require('../utils/auth');

async function connectDB() {
  try {
    await mongoose.connect(env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000
    });
    await Admin.updateOne(
      { singleton: true },
      {
        $setOnInsert: {
          username: env.API_USERNAME,
          email: env.ADMIN_EMAIL.toLowerCase(),
          passwordHash: await hashPassword(env.API_PASSWORD),
          mfaEnabled: false
        }
      },
      { upsert: true }
    );
    if (env.ADMIN_EMAIL) {
      await Admin.updateOne({ singleton: true }, { $set: { email: env.ADMIN_EMAIL.toLowerCase() } });
    }
    console.log('MongoDB connected successfully.');
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    throw error;
  }
}

module.exports = { connectDB };
