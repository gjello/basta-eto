import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { FieldValue, getFirestore } from "firebase-admin/firestore";

const MEMBERS = ["Jhury","Mark","Melissa","Janjan","E.A.","Cassy","Tita Cheche","Angela","Bien","Tito","Elsa","Jone","Janica","Jaypee","Lester","Apple","Jicker","Dennis","Zowie"];
const SESSION_SECONDS = 12 * 60 * 60;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT = 5;
const SESSION_SECRET = process.env.SESSION_SECRET;
const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;

function getDb() {
  if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
    throw new Error("SESSION_SECRET must be set to a random value of at least 32 characters.");
  }
  if (!serviceAccountJson) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT must be set in Netlify environment variables.");
  }
  if (!getApps().length) {
    initializeApp({ credential: cert(JSON.parse(serviceAccountJson)) });
  }
  return getFirestore();
}

const docId = name => encodeURIComponent(name);
const memberRef = (db, name) => db.collection("members").doc(docId(name));
const legacyRef = (db, name) => db.collection("wishlists").doc(docId(name));
const statusRef = db => db.collection("public").doc("status");
const validMember = name => MEMBERS.includes(name);
const validWish = wish => typeof wish === "string" && wish.length <= 10000;
const hasWish = wish => typeof wish === "string" && wish.trim().length >= 3;
const json = (statusCode, body) => ({
  statusCode,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  body: JSON.stringify(body)
});
const readBody = event => {
  try { return JSON.parse(event.body || "{}"); }
  catch { return {}; }
};

async function getWishlist(db, name) {
  const current = await memberRef(db, name).get();
  if (current.exists) return current.data().wish || "";
  const legacy = await legacyRef(db, name).get();
  return legacy.exists && typeof legacy.data().wish === "string" ? legacy.data().wish : "";
}

function makeSession(member, sessionVersion) {
  const payload = Buffer.from(JSON.stringify({
    member,
    sessionVersion,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  })).toString("base64url");
  const signature = createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + signature;
}

function verifySession(event) {
  const headers = event.headers || {};
  const authorization = headers.authorization || headers.Authorization || "";
  if (!authorization.startsWith("Bearer ")) return null;
  const parts = authorization.slice(7).split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  if (!payload || !signature) return null;
  const expected = createHmac("sha256", SESSION_SECRET).update(payload).digest();
  let actual;
  try { actual = Buffer.from(signature, "base64url"); }
  catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return validMember(value.member)
      && typeof value.sessionVersion === "string"
      && Number.isInteger(value.exp)
      && value.exp > Date.now() / 1000
      ? { member:value.member, sessionVersion:value.sessionVersion }
      : null;
  } catch {
    return null;
  }
}

function pinHash(pin, salt) {
  return scryptSync(pin, salt, 64).toString("hex");
}

function matchesPin(pin, salt, hash) {
  if (typeof salt !== "string" || typeof hash !== "string") return false;
  const expected = Buffer.from(hash, "hex");
  const actual = Buffer.from(pinHash(pin, salt), "hex");
  return expected.length === actual.length && timingSafeEqual(actual, expected);
}

function matchesLegacyPin(name, pin, hash) {
  if (typeof hash !== "string" || !/^[0-9a-f]{64}$/.test(hash)) return false;
  const actual = createHash("sha256").update("gx:" + name + ":" + pin).digest();
  const expected = Buffer.from(hash, "hex");
  return timingSafeEqual(actual, expected);
}

function assignmentFor(index) {
  const rng = seed => () => {
    seed |= 0;
    seed = seed + 0x6D2B79F5 | 0;
    let value = Math.imul(seed ^ seed >>> 15, 1 | seed);
    value = value + Math.imul(value ^ value >>> 7, 61 | value) ^ value;
    return ((value ^ value >>> 14) >>> 0) / 4294967296;
  };
  const order = MEMBERS.map((_, i) => i);
  const random = rng(2026);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order[(order.indexOf(index) + 1) % order.length];
}

async function getStatus(db) {
  const ref = statusRef(db);
  const existing = await ref.get();
  if (existing.exists) return existing.data().members || {};
  const records = await Promise.all(MEMBERS.map(async name => {
    const current = await memberRef(db, name).get();
    if (current.exists) return [name, hasWish(current.data().wish)];
    const legacy = await legacyRef(db, name).get();
    return [name, legacy.exists && hasWish(legacy.data().wish)];
  }));
  const members = Object.fromEntries(records);
  await db.runTransaction(async transaction => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists) transaction.set(ref, { members, updatedAt: FieldValue.serverTimestamp() });
  });
  const saved = await ref.get();
  return saved.data().members || members;
}

async function updateStatus(db, name, wish) {
  const ref = statusRef(db);
  await db.runTransaction(async transaction => {
    const snapshot = await transaction.get(ref);
    const members = snapshot.exists ? (snapshot.data().members || {}) : {};
    members[name] = hasWish(wish);
    transaction.set(ref, { members, updatedAt: FieldValue.serverTimestamp() });
  });
}

function clientIp(event) {
  return event.headers["x-nf-client-connection-ip"] || "unknown";
}

function rateLimitRef(db, name, ip) {
  const key = createHash("sha256").update(name + ":" + ip).digest("hex");
  return db.collection("pinAttempts").doc(key);
}

async function reservePinAttempt(db, name, ip) {
  const ref = rateLimitRef(db, name, ip);
  await db.runTransaction(async transaction => {
    const snapshot = await transaction.get(ref);
    const now = Date.now();
    const previous = snapshot.exists ? snapshot.data() : {};
    const startedAt = Number(previous.startedAt) || 0;
    const attempts = startedAt > now - RATE_WINDOW_MS ? Number(previous.attempts) || 0 : 0;
    if (attempts >= RATE_LIMIT) {
      throw Object.assign(new Error("Too many incorrect PIN attempts. Please wait 15 minutes and try again."), { statusCode: 429 });
    }
    transaction.set(ref, { startedAt: attempts ? startedAt : now, attempts: attempts + 1 });
  });
}

async function authenticate(db, name, pin, ip) {
  await reservePinAttempt(db, name, ip);
  const ref = memberRef(db, name);
  const current = await ref.get();
  if (current.exists) {
    const data = current.data();
    if (!matchesPin(pin, data.pinSalt, data.pinHash)) {
      throw Object.assign(new Error("That PIN doesn’t match. Please try again."), { statusCode: 401 });
    }
    await rateLimitRef(db, name, ip).delete();
    return data.sessionVersion;
  }

  const legacySnapshot = await legacyRef(db, name).get();
  const legacy = legacySnapshot.exists ? legacySnapshot.data() : {};
  if (legacy.pin && !matchesLegacyPin(name, pin, legacy.pin)) {
    throw Object.assign(new Error("That PIN doesn’t match. Please try again."), { statusCode: 401 });
  }

  const salt = randomBytes(16).toString("hex");
  const data = {
    pinSalt: salt,
    pinHash: pinHash(pin, salt),
    sessionVersion: randomBytes(16).toString("hex"),
    wish: validWish(legacy.wish) ? legacy.wish : "",
    drawDone: legacy.drawDone === true,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp()
  };
  await db.runTransaction(async transaction => {
    const snapshot = await transaction.get(ref);
    if (!snapshot.exists) transaction.create(ref, data);
  });
  const after = await ref.get();
  if (!matchesPin(pin, after.data().pinSalt, after.data().pinHash)) {
    throw Object.assign(new Error("That PIN doesn’t match. Please try again."), { statusCode: 401 });
  }
  await updateStatus(db, name, data.wish);
  await rateLimitRef(db, name, ip).delete();
  return after.data().sessionVersion;
}

export async function handler(event) {
  try {
    if (typeof event.body === "string" && event.body.length > 20000) {
      return json(413, { error: "The request is too large." });
    }
    const db = getDb();
    const action = event.queryStringParameters?.action || readBody(event).action;
    if (event.httpMethod === "GET" && action === "status") {
      return json(200, { members: await getStatus(db) });
    }

    if (event.httpMethod === "POST" && action === "auth") {
      const { member, pin } = readBody(event);
      if (!validMember(member) || typeof pin !== "string" || !/^\d{4}$/.test(pin)) {
        return json(400, { error: "Choose a family name and enter a 4-digit PIN." });
      }
      const sessionVersion = await authenticate(db, member, pin, clientIp(event));
      return json(200, { token: makeSession(member, sessionVersion) });
    }

    const session = verifySession(event);
    if (!session) return json(401, { error: "Your session expired. Enter your name and PIN again." });
    const member = session.member;
    const sessionSnapshot = await memberRef(db, member).get();
    if (!sessionSnapshot.exists || sessionSnapshot.data().sessionVersion !== session.sessionVersion) {
      return json(401, { error: "Your session expired. Enter your name and PIN again." });
    }

    if (event.httpMethod === "GET" && action === "me") {
      const snapshot = await memberRef(db, member).get();
      if (!snapshot.exists) return json(404, { error: "Member record not found. Enter your name and PIN again." });
      const data = snapshot.data();
      if (data.drawDone === true) {
        const recipient = MEMBERS[assignmentFor(MEMBERS.indexOf(member))];
        return json(200, {
          wish: data.wish || "",
          drawDone: true,
          result: { recipient, wish: await getWishlist(db, recipient) }
        });
      }
      return json(200, { wish: data.wish || "", drawDone: false });
    }

    if (event.httpMethod === "POST" && action === "wishlist") {
      const { wish } = readBody(event);
      if (!validWish(wish) || wish.trim().length < 3) return json(400, { error: "Please enter a valid wishlist." });
      const ref = memberRef(db, member);
      await db.runTransaction(async transaction => {
        const snapshot = await transaction.get(ref);
        if (!snapshot.exists) throw Object.assign(new Error("Member record not found. Enter your name and PIN again."), { statusCode: 404 });
        transaction.update(ref, { wish, updatedAt: FieldValue.serverTimestamp() });
      });
      await updateStatus(db, member, wish);
      return json(200, { saved: true });
    }

    if (event.httpMethod === "POST" && action === "draw") {
      const status = await getStatus(db);
      if (!MEMBERS.every(name => status[name] === true)) {
        return json(409, { error: "Everyone must save a wishlist before the draw." });
      }
      const ownRef = memberRef(db, member);
      const ownSnapshot = await ownRef.get();
      if (!ownSnapshot.exists || !hasWish(ownSnapshot.data().wish)) {
        return json(409, { error: "Save your wishlist before drawing." });
      }
      const ownIndex = MEMBERS.indexOf(member);
      const recipient = MEMBERS[assignmentFor(ownIndex)];
      const [recipientWish, latestOwnSnapshot] = await Promise.all([getWishlist(db, recipient), ownRef.get()]);
      if (!hasWish(recipientWish)) return json(409, { error: "The recipient wishlist is unavailable." });
      if (!latestOwnSnapshot.data().drawDone) {
        await ownRef.update({ drawDone: true, updatedAt: FieldValue.serverTimestamp() });
      }
      return json(200, { recipient, wish: recipientWish });
    }

    return json(404, { error: "Unknown API action." });
  } catch (error) {
    console.error("Exchange API error:", error);
    return json(error.statusCode || 500, {
      error: error.statusCode ? error.message : "The shared service is unavailable. Please try again."
    });
  }
}
