import { parsePubKey } from '../helpers/paillier.helper.js';

const userStore = new Map();


export function generateUserId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `0x${timestamp}${random}`.toUpperCase();
}

// ============== USER MANAGEMENT ==============

export function hasUser(id) {
  return userStore.has(id);
}

export function getUser(id) {
  return userStore.get(id);
}

export function getUserCount() {
  return userStore.size;
}

export function registerUser({ authPks, pubKey, id }) {
  if (!authPks || !Array.isArray(authPks) || !authPks.every(Array.isArray)) {
    return {
      success: false,
      error: "authPks must be an array of arrays (k serialized public keys)",
    };
  }

  if (!pubKey || !pubKey.n || !pubKey.g) {
    return {
      success: false,
      error: "pubKey with n, g, n2 is required for registration",
    };
  }

  if (!id) {
    id = generateUserId();
  } else if (userStore.has(id)) {
    return {
      success: false,
      error: `ID '${id}' already exists. Use a different ID or omit to auto-generate.`,
    };
  }

  const storedPubKey = parsePubKey(pubKey);

  userStore.set(id, {
    authPks,
    pubKey: storedPubKey,
    numKeys: authPks.length,
    registeredAt: new Date().toISOString(),
  });

  console.log(`User registered: ${id} (${authPks.length} auth keys, pubKey set)`);

  return {
    success: true,
    id,
    numKeys: authPks.length,
    registeredAt: userStore.get(id).registeredAt,
  };
}

export function deleteUser(id) {
  if (!userStore.has(id)) {
    return { success: false, error: `User '${id}' not found` };
  }

  userStore.delete(id);
  console.log(`User unregistered: ${id}`);
  return { success: true };
}

export function getAllUsers() {
  return Array.from(userStore.entries()).map(([id, data]) => ({
    id,
    numKeys: data.numKeys,
    hasPubKey: !!data.pubKey,
    registeredAt: data.registeredAt,
    hasEncryptedPath: !!data.encryptedPath,
    pathLength: data.encryptedPath?.length || 0,
  }));
}

export function getUserDetail(id) {
  if (!userStore.has(id)) return null;

  const user = userStore.get(id);
  return {
    id,
    numKeys: user.numKeys,
    hasPubKey: !!user.pubKey,
    registeredAt: user.registeredAt,
    hasEncryptedPath: !!user.encryptedPath,
    pathLength: user.encryptedPath?.length || 0,
    pathVerifiedAt: user.pathVerifiedAt || null,
  };
}

export function storeUserPath(id, encryptedPath) {
  const user = userStore.get(id);
  if (user) {
    user.encryptedPath = encryptedPath;
    user.pathVerifiedAt = new Date().toISOString();
    userStore.set(id, user);
    console.log(`Path verified and stored for user ${id}`);
  }
}
