import { Router } from 'express';
import {
  registerUser,
  deleteUser,
  getAllUsers,
  getUserDetail,
  getUserCount,
  hasUser,
  getUser,
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
 * GET /users/:id/path
 * Get the stored encrypted path for a user
 */
router.get('/users/:id/path', (req, res) => {
  const { id } = req.params;

  if (!hasUser(id)) {
    return res.status(404).json({
      success: false,
      error: `User '${id}' not found`,
    });
  }

  const detail = getUserDetail(id);
  if (!detail || !detail.hasEncryptedPath) {
    return res.status(404).json({
      success: false,
      error: `User '${id}' does not have a stored encrypted path`,
    });
  }

  const user = getUser(id);
  res.json({
    success: true,
    id,
    encryptedPath: user.encryptedPath,
    pathLength: user.encryptedPath.length,
  });
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

/**
 * GET /users/:id/blindPath
 * Get the stored blind path for a user (Requested by Platoon Leader)
 */
router.get('/users/:id/blindPath', (req, res) => {
  const { id } = req.params;

  if (!hasUser(id)) {
    return res.status(404).json({ success: false, error: `User '${id}' not found` });
  }

  const user = getUser(id);
  if (!user.hasBlindPath || !user.blindPath) {
    return res.status(404).json({ success: false, error: `User '${id}' does not have a stored blind path` });
  }

  res.json({
    success: true,
    id,
    blindPath: user.blindPath, // Array of C_blind strings
    pathLength: user.blindPath.length,
  });
});

export default router;
