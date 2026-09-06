const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";

const ROOT = path.join(__dirname, "..");
const PUBLIC = path.join(ROOT, "public");
const DATA = path.join(ROOT, "data");

fs.mkdirSync(DATA, { recursive: true });

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

function hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
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

function error(res, status, message) {
    return json(res, status, { error: message });
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
            if (!body) return resolve({});

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
    const h = req.headers.authorization || "";

    if (!h.startsWith("Bearer ")) {
        return null;
    }

    return h.slice(7).trim();
}

function auth(req) {
    const token = bearer(req);

    if (!token) return null;

    const row = db.prepare(`
        SELECT p.*
        FROM sessions s
        JOIN players p ON p.id = s.player_id
        WHERE s.token_hash = ?
        AND s.expires_at > ?
        AND p.deleted_at IS NULL
    `).get(hashToken(token), now());

    return row || null;
}

function createSession(playerId) {
    const token = crypto.randomBytes(48).toString("hex");

    const expires = new Date(
        Date.now() + 30 * 24 * 60 * 60 * 1000
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
    `).run(playerId, title, text, now());
}

function addTransaction(playerId, type, amount, description) {
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

    if (day <= 93) avg = 18;
    else if (day <= 186) avg = 30;
    else if (day <= 279) avg = 17;
    else avg = 5;

    const variation =
        Math.sin(day * 0.73) * 3 +
        Math.sin(day * 0.19) * 1.5;

    return Math.round((avg + variation) * 10) / 10;
}

function activeChickens(playerId) {
    const groups = db.prepare(`
        SELECT amount, age
        FROM chicken_groups
        WHERE player_id = ?
    `).all(playerId);

    return groups
        .filter(g => g.age > 0 && g.age < 500)
        .reduce((sum, g) => sum + g.amount, 0);
}

function totalChickens(playerId) {
    const row = db.prepare(`
        SELECT COALESCE(SUM(amount),0) AS total
        FROM chicken_groups
        WHERE player_id = ?
    `).get(playerId);

    return row.total;
}

function feedForMeal(chickens) {
    return chickens * 0.05;
}

function waterForMeal(chickens) {
    return chickens * 0.08;
}

function eggProduction(farm) {
    const active = activeChickens(farm.player_id);

    if (active <= 0) return 0;

    let efficiency = 0.80;

    const normalFeed = db.prepare(`
        SELECT COALESCE(SUM(amount),0) AS amount
        FROM feed_batches
        WHERE player_id = ?
        AND type = 'normal'
        AND amount > 0
    `).get(farm.player_id).amount;

    const economicFeed = db.prepare(`
        SELECT COALESCE(SUM(amount),0) AS amount
        FROM feed_batches
        WHERE player_id = ?
        AND type = 'economic'
        AND amount > 0
    `).get(farm.player_id).amount;

    if (normalFeed <= 0 && economicFeed > 0) {
        efficiency = 0.60;
    }

    const temp = temperature(farm.day);

    if (temp < 24) {
        efficiency *= Math.max(0, 1 - ((24 - temp) * 0.05));
    } else {
        efficiency *= Math.max(0, 1 - ((temp - 24) * 0.03));
    }

    if (!farm.fed_morning || !farm.fed_evening) {
        efficiency *= 0.70;
    }

    if (!farm.watered) {
        efficiency *= 0.70;
    }

    if (farm.health < 100) {
        efficiency *= farm.health / 100;
    }

    return Math.max(
        0,
        Math.floor(active * efficiency)
    );
}

function consumeFeed(playerId, amount) {
    let remaining = amount;

    const batches = db.prepare(`
        SELECT *
        FROM feed_batches
        WHERE player_id = ?
        AND amount > 0
        ORDER BY purchase_day ASC, id ASC
    `).all(playerId);

    const update = db.prepare(`
        UPDATE feed_batches
        SET amount = ?
        WHERE id = ?
    `);

    for (const batch of batches) {
        if (remaining <= 0) break;

        const used = Math.min(batch.amount, remaining);

        update.run(
            batch.amount - used,
            batch.id
        );

        remaining -= used;
    }

    return remaining <= 0;
}

function expireFeed(playerId, day) {
    db.prepare(`
        DELETE FROM feed_batches
        WHERE player_id = ?
        AND purchase_day <= ?
    `).run(playerId, day - 180);
}

/* =====================================================
   AUTH REGISTER
===================================================== */

async function register(req, res) {
    const body = await readBody(req);

    const email = String(body.email || "").trim().toLowerCase();
    const mobile = String(body.mobile || "").trim();
    const username = String(body.username || "").trim();
    const farmName = String(body.farmName || "").trim();
    const password = String(body.password || "");

    if (
        !email ||
        !mobile ||
        !username ||
        !farmName ||
        password.length < 8
    ) {
        return error(
            res,
            400,
            "اطلاعات ثبت‌نام کامل نیست یا رمز باید حداقل ۸ کاراکتر باشد."
        );
    }

    const exists = db.prepare(`
        SELECT id
        FROM players
        WHERE email = ?
        OR mobile = ?
        OR username = ?
    `).get(email, mobile, username);

    if (exists) {
        return error(
            res,
            409,
            "ایمیل، موبایل یا نام کاربری قبلاً استفاده شده است."
        );
    }

    const playerId = id();
    const passwordHash = await bcrypt.hash(password, 12);

    const tx = db.transaction(() => {

        db.prepare(`
            INSERT INTO players
            (id,email,mobile,username,farm_name,password_hash,coins,created_at)
            VALUES (?,?,?,?,?,?,?,?)
        `).run(
            playerId,
            email,
            mobile,
            username,
            farmName,
            passwordHash,
            300,
            now()
        );

        db.prepare(`
            INSERT INTO farms
            (player_id,day,chickens,feed,water,eggs,health,level,egg_price)
            VALUES (?,1,100,100,100,0,100,1,1)
        `).run(playerId);

        db.prepare(`
            INSERT INTO chicken_groups
            (player_id,amount,age)
            VALUES (?,100,0)
        `).run(playerId);

        addTransaction(
            playerId,
            "WELCOME",
            300,
            "هدیه شروع بازی"
        );

        addNotification(
            playerId,
            "خوش آمدید",
            "۳۰۰ توکن اولیه به حساب شما اضافه شد."
        );
    });

    tx();

    const token = createSession(playerId);

    return json(res, 201, {
        token
    });
}

/* =====================================================
   AUTH LOGIN
===================================================== */

async function login(req, res) {
    const body = await readBody(req);

    const username = String(body.username || "")
        .trim()
        .toLowerCase();

    const password = String(body.password || "");

    const player = db.prepare(`
        SELECT *
        FROM players
        WHERE deleted_at IS NULL
        AND (
            lower(email) = ?
            OR mobile = ?
            OR lower(username) = ?
        )
    `).get(username, username, username);

    if (!player) {
        return error(res, 401, "نام کاربری یا رمز عبور اشتباه است.");
    }

    const valid = await bcrypt.compare(
        password,
        player.password_hash
    );

    if (!valid) {
        return error(res, 401, "نام کاربری یا رمز عبور اشتباه است.");
    }

    const token = createSession(player.id);

    return json(res, 200, { token });
}

/* =====================================================
   ME
===================================================== */

function me(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    return json(res, 200, {
        player: {
            id: player.id,
            email: player.email,
            mobile: player.mobile,
            username: player.username,
            farmName: player.farm_name,
            coins: player.coins
        },

        farm: {
            day: farm.day,
            chickens: totalChickens(player.id),
            feed: farm.feed,
            water: farm.water,
            eggs: farm.eggs,
            health: farm.health,
            level: farm.level,
            eggPrice: farm.egg_price
        }
    });
}

/* =====================================================
   FEED
===================================================== */

function feed(req, res, meal) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (farm[meal === "morning" ? "fed_morning" : "fed_evening"]) {
        return error(res, 400, "این وعده قبلاً ثبت شده است.");
    }

    const chickens = totalChickens(player.id);
    const required = feedForMeal(chickens);

    if (farm.feed < required) {
        return error(res, 400, "خوراک کافی نیست.");
    }

    const success = consumeFeed(
        player.id,
        required
    );

    if (!success) {
        return error(res, 400, "موجودی خوراک کافی نیست.");
    }

    const field =
        meal === "morning"
            ? "fed_morning"
            : "fed_evening";

    db.prepare(`
        UPDATE farms
        SET feed = feed - ?,
            ${field} = 1
        WHERE player_id = ?
    `).run(required, player.id);

    return json(res, 200, {
        success: true,
        consumed: required
    });
}

/* =====================================================
   WATER
===================================================== */

function water(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (farm.watered) {
        return error(res, 400, "آب امروز قبلاً ثبت شده است.");
    }

    const chickens = totalChickens(player.id);
    const required = waterForMeal(chickens) * 2;

    if (farm.water < required) {
        return error(res, 400, "آب کافی نیست.");
    }

    db.prepare(`
        UPDATE farms
        SET water = water - ?,
            watered = 1
        WHERE player_id = ?
    `).run(required, player.id);

    return json(res, 200, {
        success: true,
        consumed: required
    });
}

/* =====================================================
   COLLECT EGGS
===================================================== */

function collectEggs(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (farm.eggs <= 0) {
        return error(res, 400, "تخم‌مرغی برای جمع‌آوری وجود ندارد.");
    }

    return json(res, 200, {
        success: true,
        eggs: farm.eggs
    });
}

/* =====================================================
   END DAY
===================================================== */

function endDay(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    const produced = eggProduction(farm);

    const temp = temperature(farm.day);

    let health = farm.health;

    if (temp >= 38 || temp <= 10) {
        health = Math.max(0, health - 10);
    }

    if (!farm.fed_morning || !farm.fed_evening) {
        health = Math.max(0, health - 8);
    }

    if (!farm.watered) {
        health = Math.max(0, health - 8);
    }

    const newDay = farm.day + 1;

    const tx = db.transaction(() => {

        db.prepare(`
            UPDATE farms
            SET
                day = ?,
                eggs = eggs + ?,
                health = ?,
                fed_morning = 0,
                fed_evening = 0,
                watered = 0,
                egg_price = ?
            WHERE player_id = ?
        `).run(
            newDay,
            produced,
            health,
            Math.min(
                1.1,
                Math.max(
                    0.9,
                    1 + (Math.random() * 0.04 - 0.02)
                )
            ),
            player.id
        );

        db.prepare(`
            UPDATE chicken_groups
            SET age = age + 1
            WHERE player_id = ?
        `).run(player.id);

        expireFeed(player.id, newDay);

        addNotification(
            player.id,
            "روز جدید",
            `روز ${newDay} شروع شد. تولید امروز بر اساس وضعیت واقعی مزرعه محاسبه می‌شود.`
        );

        if (produced > 0) {
            addNotification(
                player.id,
                "تولید تخم‌مرغ",
                `${produced} عدد تخم‌مرغ برای امروز تولید شد.`
            );
        }

        if (health < 80) {
            addNotification(
                player.id,
                "هشدار سلامت",
                "سلامت گله کاهش یافته است."
            );
        }
    });

    tx();

    return json(res, 200, {
        success: true,
        produced,
        day: newDay,
        temperature: temp,
        health
    });
}

/* =====================================================
   EGG MARKET
===================================================== */

function sellEggs(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    return readBody(req).then(body => {

        const amount = Math.floor(Number(body.amount));

        if (!Number.isInteger(amount) || amount <= 0) {
            return error(res, 400, "تعداد نامعتبر است.");
        }

        const farm = db.prepare(`
            SELECT *
            FROM farms
            WHERE player_id = ?
        `).get(player.id);

        if (farm.eggs < amount) {
            return error(res, 400, "تخم‌مرغ کافی ندارید.");
        }

        const revenue = Math.floor(
            amount * farm.egg_price
        );

        const tx = db.transaction(() => {

            db.prepare(`
                UPDATE farms
                SET eggs = eggs - ?
                WHERE player_id = ?
            `).run(amount, player.id);

            db.prepare(`
                UPDATE players
                SET coins = coins + ?
                WHERE id = ?
            `).run(revenue, player.id);

            addTransaction(
                player.id,
                "EGG_SALE",
                revenue,
                `فروش ${amount} تخم‌مرغ`
            );
        });

        tx();

        return json(res, 200, {
            success: true,
            amount,
            revenue
        });
    });
}

/* =====================================================
   MARKET
===================================================== */

function market(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    db.prepare(`
        DELETE FROM market_listings
        WHERE expires_at <= ?
    `).run(now());

    const listings = db.prepare(`
        SELECT
            m.id,
            m.type,
            m.amount,
            m.price,
            p.username
        FROM market_listings m
        JOIN players p ON p.id = m.seller_id
        WHERE m.expires_at > ?
        ORDER BY m.created_at ASC
    `).all(now());

    return json(res, 200, { listings });
}

/* =====================================================
   SOCIAL SEARCH
===================================================== */

function socialSearch(req, res, query) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const q = `%${String(query || "").trim()}%`;

    const players = db.prepare(`
        SELECT
            p.id,
            p.username,
            p.farm_name AS farmName,
            f.chickens,
            f.level
        FROM players p
        JOIN farms f ON f.player_id = p.id
        WHERE p.deleted_at IS NULL
        AND p.id != ?
        AND (
            p.username LIKE ?
            OR p.farm_name LIKE ?
        )
        ORDER BY p.username
        LIMIT 50
    `).all(
        player.id,
        q,
        q
    ).map(p => ({
        ...p,
        chickens: totalChickens(p.id)
    }));

    return json(res, 200, { players });
}

/* =====================================================
   FOLLOW
===================================================== */

async function follow(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const body = await readBody(req);
    const target = String(body.playerId || "");

    if (!target || target === player.id) {
        return error(res, 400, "بازیکن نامعتبر است.");
    }

    const exists = db.prepare(`
        SELECT id
        FROM players
        WHERE id = ?
        AND deleted_at IS NULL
    `).get(target);

    if (!exists) {
        return error(res, 404, "بازیکن پیدا نشد.");
    }

    db.prepare(`
        INSERT OR IGNORE INTO follows
        (follower_id, following_id, created_at)
        VALUES (?, ?, ?)
    `).run(
        player.id,
        target,
        now()
    );

    return json(res, 200, {
        success: true
    });
}

/* =====================================================
   RANKING
===================================================== */

function ranking(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const rows = db.prepare(`
        SELECT
            p.id,
            p.username,
            p.farm_name AS farmName,
            p.coins,
            f.level,
            f.eggs
        FROM players p
        JOIN farms f ON f.player_id = p.id
        WHERE p.deleted_at IS NULL
        ORDER BY f.level DESC, p.coins DESC
        LIMIT 100
    `).all();

    const players = rows.map(p => ({
        ...p,
        chickens: totalChickens(p.id)
    }));

    return json(res, 200, { players });
}

/* =====================================================
   NOTIFICATIONS
===================================================== */

function notifications(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const list = db.prepare(`
        SELECT id,title,text,created_at AS createdAt
        FROM notifications
        WHERE player_id = ?
        ORDER BY id DESC
        LIMIT 100
    `).all(player.id);

    return json(res, 200, {
        notifications: list
    });
}

/* =====================================================
   REFERRAL
===================================================== */

function referral(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const code = player.id
        .replaceAll("-", "")
        .slice(0, 8)
        .toUpperCase();

    return json(res, 200, {
        code,
        successful: 0,
        maximum: 10
    });
}

/* =====================================================
   WALLET HISTORY
===================================================== */

function walletHistory(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    const transactions = db.prepare(`
        SELECT
            id,
            type,
            amount,
            description,
            created_at AS createdAt
        FROM transactions
        WHERE player_id = ?
        ORDER BY created_at DESC
        LIMIT 200
    `).all(player.id);

    return json(res, 200, {
        transactions
    });
}

/* =====================================================
   LOGOUT
===================================================== */

function logout(req, res) {
    const player = auth(req);

    if (!player) {
        return json(res, 200, { success: true });
    }

    const token = bearer(req);

    db.prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
    `).run(hashToken(token));

    return json(res, 200, {
        success: true
    });
}

function logoutAll(req, res) {
    const player = auth(req);

    if (!player) {
        return error(res, 401, "نیاز به ورود دارید.");
    }

    db.prepare(`
        DELETE FROM sessions
        WHERE player_id = ?
    `).run(player.id);

    return json(res, 200, {
        success: true
    });
}

/* =====================================================
   ROUTER
===================================================== */

async function router(req, res) {

    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
        });
        return res.end();
    }

    const url = new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
    );

    try {

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/register"
        ) {
            return register(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/login"
        ) {
            return login(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/me"
        ) {
            return me(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/feed"
        ) {
            const body = await readBody(req);

            const meal =
                body.meal === "evening"
                    ? "evening"
                    : "morning";

            req.body = body;

            return feed(req, res, meal);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/water"
        ) {
            return water(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/collect-eggs"
        ) {
            return collectEggs(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/end-day"
        ) {
            return endDay(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/market/sell-eggs"
        ) {
            return sellEggs(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/market"
        ) {
            return market(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/social/search"
        ) {
            return socialSearch(
                req,
                res,
                url.searchParams.get("q") || ""
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/social/follow"
        ) {
            return follow(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/ranking"
        ) {
            return ranking(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/notifications"
        ) {
            return notifications(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/referral"
        ) {
            return referral(req, res);
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/wallet/history"
        ) {
            return walletHistory(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/logout"
        ) {
            return logout(req, res);
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/logout-all"
        ) {
            return logoutAll(req, res);
        }

        /* health check */

        if (
            req.method === "GET" &&
            url.pathname === "/health"
        ) {
            return json(res, 200, {
                ok: true,
                service: "vahid-chicken-farm",
                time: now()
            });
        }

        /* static files */

        let filePath = url.pathname === "/"
            ? path.join(PUBLIC, "index.html")
            : path.join(
                PUBLIC,
                path.normalize(url.pathname)
            );

        if (!filePath.startsWith(PUBLIC)) {
            return error(res, 403, "Forbidden");
        }

        if (fs.existsSync(filePath) &&
            fs.statSync(filePath).isFile()) {

            const ext = path.extname(filePath);

            const types = {
                ".html": "text/html; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".json": "application/json; charset=utf-8",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".svg": "image/svg+xml",
                ".ico": "image/x-icon"
            };

            res.writeHead(200, {
                "Content-Type":
                    types[ext] ||
                    "application/octet-stream"
            });

            return fs.createReadStream(filePath).pipe(res);
        }

        return error(res, 404, "Not Found");

    } catch (err) {

        console.error(err);

        return error(
            res,
            500,
            "خطای داخلی سرور"
        );
    }
}

/* =====================================================
   SERVER
===================================================== */

const server = http.createServer(router);

server.listen(PORT, HOST, () => {
    console.log(`
=========================================
 Vahid Chicken Farm Server
=========================================
 HTTP: ${HOST}:${PORT}
 Database: SQLite
 Players: REAL
 Game State: SERVER AUTHORITATIVE
=========================================
`);
});
