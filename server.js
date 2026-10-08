const dotenv = require('dotenv');

dotenv.config();

const app = require('./src/app');
const { connectDB } = require('./src/config/db');
const { env } = require('./src/config/env');

async function startServer() {
  try {
    await connectDB();
    const port = env.PORT || 3000;
    app.listen(port, () => {
      console.log(`User Management API running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error('Failed to start application:', error.message);
    process.exit(1);
  }
}

startServer();
