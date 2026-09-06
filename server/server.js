const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const ROOT = path.join(__dirname, "..");
const PUBLIC = path.join(ROOT, "public");
const DATA = path.join(ROOT, "data");

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(PUBLIC, { recursive: true });

const db = new Database(path.join(DATA, "chicken_farm.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

/* =====================================================
DATABASE
===================================================== */

db.exec(`
CREATE TABLE IF NOT EXISTS players (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    mobile TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    farm_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    coins INTEGER NOT NULL DEFAULT 300,
    created_at TEXT NOT NULL,
    deleted_at TEXT,
    chat_ban_until TEXT
);

CREATE TABLE IF NOT EXISTS farms (
    player_id TEXT PRIMARY KEY,
    day INTEGER NOT NULL DEFAULT 1,
    chickens INTEGER NOT NULL DEFAULT 100,
    feed REAL NOT NULL DEFAULT 100,
    water REAL NOT NULL DEFAULT 100,
    eggs INTEGER NOT NULL DEFAULT 0,
    health REAL NOT NULL DEFAULT 100,
    level INTEGER NOT NULL DEFAULT 1,
    egg_price REAL NOT NULL DEFAULT 1,
    fed_morning INTEGER NOT NULL DEFAULT 0,
    fed_evening INTEGER NOT NULL DEFAULT 0,
    watered INTEGER NOT NULL DEFAULT 0,
    last_day_change TEXT,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chicken_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    age INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feed_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id TEXT NOT NULL,
    amount REAL NOT NULL,
    purchase_day INTEGER NOT NULL,
    price REAL NOT NULL,
    type TEXT NOT NULL,
    quality REAL NOT NULL DEFAULT 100,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id TEXT NOT NULL,
    title TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    player_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    player_id TEXT NOT NULL,
    type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(player_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS follows (
    follower_id TEXT NOT NULL,
    following_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES players(id) ON DELETE CASCADE,
    FOREIGN KEY(following_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS market_listings (
    id TEXT PRIMARY KEY,
    seller_id TEXT NOT NULL,
    type TEXT NOT NULL,
    amount INTEGER NOT NULL,
    price REAL NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(seller_id) REFERENCES players(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(sender_id) REFERENCES players(id) ON DELETE CASCADE
);
`);

/* =====================================================
HELPERS
===================================================== */

function now() {
    return new Date().toISOString();
}

function id() {
    return crypto.randomUUID();
}

function normalizeDigits(value) {
    return String(value || "")
        .replace(/[۰-۹]/g, function (d) {
            return String("۰۱۲۳۴۵۶۷۸۹".indexOf(d));
        })
        .replace(/[٠-٩]/g, function (d) {
            return String("٠١٢٣٤٥٦٧٨٩".indexOf(d));
        });
}

function normalizeMobile(value) {
    let mobile = normalizeDigits(value)
        .trim()
        .replace(/[\s\-()]/g, "");

    if (mobile.startsWith("+98")) {
        mobile = "0" + mobile.slice(3);
    } else if (mobile.startsWith("98")) {
        mobile = "0" + mobile.slice(2);
    }

    return mobile;
}

function normalizeEmail(value) {
    return String(value || "")
        .trim()
        .toLowerCase();
}

function normalizeUsername(value) {
    return String(value || "")
        .trim()
        .toLowerCase();
}

function json(res, status, data) {
    const body = JSON.stringify(data);

    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
    });

    res.end(body);
}

function error(res, status, message, extra = {}) {
    return json(res, status, {
        error: message,
        ...extra
    });
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk;

            if (body.length > 1024 * 1024) {
                reject(new Error("BODY_TOO_LARGE"));
                req.destroy();
            }
        });

        req.on("end", () => {
            if (!body) {
                return resolve({});
            }

            try {
                resolve(JSON.parse(body));
            } catch {
                reject(new Error("INVALID_JSON"));
            }
        });

        req.on("error", reject);
    });
}

function bearer(req) {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
        return null;
    }

    return header.slice(7).trim();
}

function auth(req) {
    const token = bearer(req);

    if (!token) {
        return null;
    }

    const row = db.prepare(`
        SELECT p.*
        FROM sessions s
        JOIN players p ON p.id = s.player_id
        WHERE s.token_hash = ?
          AND s.expires_at > ?
          AND p.deleted_at IS NULL
    `).get(
        hashToken(token),
        now()
    );

    return row || null;
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function createSession(playerId) {
    const token = crypto
        .randomBytes(48)
        .toString("hex");

    const expires = new Date(
        Date.now() +
        30 * 24 * 60 * 60 * 1000
    ).toISOString();

    db.prepare(`
        INSERT INTO sessions
        (token_hash, player_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    `).run(
        hashToken(token),
        playerId,
        now(),
        expires
    );

    return token;
}

function addNotification(playerId, title, text) {
    db.prepare(`
        INSERT INTO notifications
        (player_id, title, text, created_at)
        VALUES (?, ?, ?, ?)
    `).run(
        playerId,
        title,
        text,
        now()
    );
}

function addTransaction(
    playerId,
    type,
    amount,
    description
) {
    db.prepare(`
        INSERT INTO transactions
        (id, player_id, type, amount, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        id(),
        playerId,
        type,
        amount,
        description || "",
        now()
    );
}

/* =====================================================
GAME CALCULATIONS
===================================================== */

function temperature(day) {
    let avg;

    if (day <= 93) {
        avg = 18;
    } else if (day <= 186) {
        avg = 30;
    } else if (day <= 279) {
        avg = 17;
    } else {
        avg = 5;
    }

    const variation =
        Math.sin(day * 0.73) * 3 +
        Math.sin(day *
