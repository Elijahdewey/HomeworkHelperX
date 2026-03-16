const path = require("path");
const crypto = require("crypto");

const express = require("express");
const { DatabaseSync } = require("node:sqlite");

const SUBJECTS = [
  { subject: "Bible", teacher: "Stukey, Tyler" },
  { subject: "English", teacher: "Anderson, Audra" },
  { subject: "Geography", teacher: "O'Steen, Ashley" },
  { subject: "Life Science", teacher: "Ladner, Katelyn" },
  { subject: "Math", teacher: "Cato, Stacy" },
];

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.GRADEFLOW_DB_PATH || path.join(__dirname, "gradeflow.sqlite3");
const SESSION_COOKIE = "gf_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function isEmail(s) {
  if (typeof s !== "string") return false;
  const email = s.trim();
  if (email.length < 5 || email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }
  return out;
}

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString("base64")}$${key.toString("base64")}`;
}

function verifyPassword(password, stored) {
  try {
    const [alg, saltB64, keyB64] = String(stored || "").split("$");
    if (alg !== "scrypt" || !saltB64 || !keyB64) return false;
    const salt = Buffer.from(saltB64, "base64");
    const expected = Buffer.from(keyB64, "base64");
    const actual = crypto.scryptSync(String(password), salt, expected.length);
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function isSecureRequest(req) {
  if (req.secure) return true;
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0].trim();
  return proto === "https";
}

function initDb(db) {
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec(`
    CREATE TABLE IF NOT EXISTS Users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS Grades (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      subject TEXT NOT NULL,
      teacher TEXT NOT NULL,
      grade INTEGER NOT NULL,
      updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS Sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      expires_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_grades_user ON Grades(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON Sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON Sessions(expires_at);
  `);
}

function transaction(db, fn) {
  db.exec("BEGIN");
  try {
    const out = fn();
    db.exec("COMMIT");
    return out;
  } catch (e) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // ignore
    }
    throw e;
  }
}

function jsonError(res, status, error) {
  res.status(status).json({ error });
}

function requireUser(db) {
  return (req, res, next) => {
    const cookies = parseCookies(req);
    const token = cookies[SESSION_COOKIE];
    if (!token) return jsonError(res, 401, "Not logged in.");

    const tokenHash = sha256Hex(token);
    const session = db
      .prepare(
        `
        SELECT Sessions.user_id, Sessions.expires_at, Users.email
        FROM Sessions
        JOIN Users ON Users.id = Sessions.user_id
        WHERE Sessions.token_hash = ?
      `,
      )
      .get(tokenHash);

    if (!session) return jsonError(res, 401, "Session expired. Please log in again.");
    if (Number(session.expires_at) <= nowSec()) {
      db.prepare("DELETE FROM Sessions WHERE token_hash = ?").run(tokenHash);
      return jsonError(res, 401, "Session expired. Please log in again.");
    }

    req.user = { id: session.user_id, email: session.email };
    req.sessionTokenHash = tokenHash;
    next();
  };
}

function createSession(db, userId) {
  const token = base64url(crypto.randomBytes(32));
  const tokenHash = sha256Hex(token);
  const expiresAt = nowSec() + SESSION_TTL_SECONDS;

  db.prepare("INSERT INTO Sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)").run(
    userId,
    tokenHash,
    expiresAt,
  );

  return { token, expiresAt };
}

function cleanupExpiredSessions(db) {
  db.prepare("DELETE FROM Sessions WHERE expires_at <= ?").run(nowSec());
}

const app = express();
app.set("trust proxy", 1);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

app.use(express.json({ limit: "32kb" }));

const db = new DatabaseSync(DB_PATH);
initDb(db);
cleanupExpiredSessions(db);

app.post("/api/auth/signup", (req, res) => {
  const emailRaw = req.body?.email;
  const password = req.body?.password;

  if (!isEmail(emailRaw)) return jsonError(res, 400, "Enter a valid email.");
  if (typeof password !== "string" || password.length < 8) return jsonError(res, 400, "Password must be 8+ characters.");

  const email = emailRaw.trim().toLowerCase();
  const pwHash = hashPassword(password);

  let userId;
  try {
    userId = transaction(db, () => {
      const info = db.prepare("INSERT INTO Users (email, password) VALUES (?, ?)").run(email, pwHash);
      const newUserId = Number(info.lastInsertRowid);

      const stmt = db.prepare("INSERT INTO Grades (user_id, subject, teacher, grade) VALUES (?, ?, ?, ?)");
      for (const s of SUBJECTS) stmt.run(newUserId, s.subject, s.teacher, 100);

      return newUserId;
    });
  } catch (e) {
    if (String(e?.message || "").includes("UNIQUE")) return jsonError(res, 409, "That email is already in use.");
    return jsonError(res, 500, "Could not create account.");
  }

  const { token } = createSession(db, userId);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecureRequest(req),
    path: "/",
    maxAge: SESSION_TTL_SECONDS * 1000,
  });

  res.json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const emailRaw = req.body?.email;
  const password = req.body?.password;

  if (!isEmail(emailRaw)) return jsonError(res, 400, "Enter a valid email.");
  if (typeof password !== "string" || password.length < 1) return jsonError(res, 400, "Enter your password.");

  const email = emailRaw.trim().toLowerCase();
  const user = db.prepare("SELECT id, email, password FROM Users WHERE email = ?").get(email);
  if (!user) return jsonError(res, 401, "Invalid email or password.");
  if (!verifyPassword(password, user.password)) return jsonError(res, 401, "Invalid email or password.");

  const { token } = createSession(db, user.id);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: isSecureRequest(req),
    path: "/",
    maxAge: SESSION_TTL_SECONDS * 1000,
  });

  res.json({ ok: true });
});

app.post("/api/auth/logout", requireUser(db), (req, res) => {
  db.prepare("DELETE FROM Sessions WHERE token_hash = ?").run(req.sessionTokenHash);
  res.clearCookie(SESSION_COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", requireUser(db), (req, res) => {
  res.json({ id: req.user.id, email: req.user.email });
});

app.get("/api/grades", requireUser(db), (req, res) => {
  const grades = db
    .prepare("SELECT id, subject, teacher, grade FROM Grades WHERE user_id = ? ORDER BY subject ASC")
    .all(req.user.id);
  res.json({ grades });
});

app.put("/api/grades/:id", requireUser(db), (req, res) => {
  const id = Number(req.params.id);
  const grade = Number(req.body?.grade);

  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid grade id.");
  if (!Number.isFinite(grade)) return jsonError(res, 400, "Invalid grade value.");
  const g = Math.max(0, Math.min(100, Math.round(grade)));

  const row = db.prepare("SELECT id FROM Grades WHERE id = ? AND user_id = ?").get(id, req.user.id);
  if (!row) return jsonError(res, 404, "Grade not found.");

  db.prepare("UPDATE Grades SET grade = ?, updated_at = strftime('%s','now') WHERE id = ? AND user_id = ?").run(
    g,
    id,
    req.user.id,
  );

  res.json({ ok: true, id, grade: g });
});

app.use(express.static(__dirname, { extensions: ["html"] }));

app.listen(PORT, () => {
  console.log(`GradeFlow running on http://localhost:${PORT}`);
  console.log(`DB: ${DB_PATH}`);
});
