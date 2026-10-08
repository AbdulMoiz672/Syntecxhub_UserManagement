const express = require('express');
const {
  listUsers,
  listAuditLogs,
  getUserById,
  createUser,
  updateUser,
  deleteUser
} = require('../controllers/userController');
const { requireSessionAuth } = require('../middleware/sessionAuth');

const router = express.Router();

router.use(requireSessionAuth);

router.get('/audit', listAuditLogs);
router.get('/', listUsers);
router.post('/', createUser);
router.get('/:id', getUserById);
router.patch('/:id', updateUser);
router.delete('/:id', deleteUser);

module.exports = router;
