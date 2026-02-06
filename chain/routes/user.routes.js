import { Router } from 'express';
import {
  registerUser,
  deleteUser,
  getAllUsers,
  getUserDetail,
  getUserCount,
  hasUser,
} from '../store/index.js';

const router = Router();

/**
 * POST /register
 * Register a new user with authPks and pubKey
 */
router.post('/register', (req, res) => {
  try {
    const { authPks, pubKey } = req.body;
    const id = req.body.id?.toString();

    if (!authPks) {
      return res.status(400).json({
        success: false,
        error: "authPks is required for registration",
      });
    }

    const result = registerUser({ authPks, pubKey, id });

    if (!result.success) {
      const status = result.error.includes('already exists') ? 409 : 400;
      return res.status(status).json(result);
    }

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      id: result.id,
      numKeys: result.numKeys,
      hasPubKey: true,
      registeredAt: result.registeredAt,
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /users
 * List all registered users
 */
router.get('/users', (req, res) => {
  res.json({
    success: true,
    totalUsers: getUserCount(),
    users: getAllUsers(),
  });
});

/**
 * GET /users/:id
 * Get specific user details
 */
router.get('/users/:id', (req, res) => {
  const { id } = req.params;

  const detail = getUserDetail(id);
  if (!detail) {
    return res.status(404).json({
      success: false,
      error: `User '${id}' not found`,
    });
  }

  res.json({ success: true, ...detail });
});

/**
 * DELETE /users/:id
 * Unregister a user
 */
router.delete('/users/:id', (req, res) => {
  const { id } = req.params;

  const result = deleteUser(id);
  if (!result.success) {
    return res.status(404).json(result);
  }

  res.json({
    success: true,
    message: `User '${id}' unregistered successfully`,
  });
});

export default router;
