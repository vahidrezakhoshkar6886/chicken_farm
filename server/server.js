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
        .filter(group =>
            group.age > 0 &&
            group.age < 500
        )
        .reduce(
            (sum, group) => sum + group.amount,
            0
        );
}

function totalChickens(playerId) {
    const row = db.prepare(`
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM chicken_groups
        WHERE player_id = ?
    `).get(playerId);

    return Number(row.total || 0);
}

function feedForMeal(chickens) {
    return chickens * 0.05;
}

function waterForMeal(chickens) {
    return chickens * 0.08;
}

function availableFeed(playerId, type = null) {
    if (type) {
        return Number(
            db.prepare(`
                SELECT COALESCE(SUM(amount), 0) AS amount
                FROM feed_batches
                WHERE player_id = ?
                  AND type = ?
                  AND amount > 0
            `).get(playerId, type).amount || 0
        );
    }

    return Number(
        db.prepare(`
            SELECT COALESCE(SUM(amount), 0) AS amount
            FROM feed_batches
            WHERE player_id = ?
              AND amount > 0
        `).get(playerId).amount || 0
    );
}

function syncFeedBalance(playerId) {
    const total = availableFeed(playerId);

    db.prepare(`
        UPDATE farms
        SET feed = ?
        WHERE player_id = ?
    `).run(total, playerId);

    return total;
}

function eggProduction(farm) {
    const active = activeChickens(farm.player_id);

    if (active <= 0) {
        return 0;
    }

    let efficiency = 0.80;

    const normalFeed = availableFeed(
        farm.player_id,
        "normal"
    );

    const economicFeed = availableFeed(
        farm.player_id,
        "economic"
    );

    if (
        normalFeed <= 0 &&
        economicFeed > 0
    ) {
        efficiency = 0.60;
    }

    const temp = temperature(farm.day);

    if (temp < 24) {
        efficiency *= Math.max(
            0,
            1 - ((24 - temp) * 0.05)
        );
    } else {
        efficiency *= Math.max(
            0,
            1 - ((temp - 24) * 0.03)
        );
    }

    if (
        !farm.fed_morning ||
        !farm.fed_evening
    ) {
        efficiency *= 0.70;
    }

    if (!farm.watered) {
        efficiency *= 0.70;
    }

    if (farm.health < 100) {
        efficiency *= Math.max(
            0,
            farm.health / 100
        );
    }

    return Math.max(
        0,
        Math.floor(active * efficiency)
    );
}

function consumeFeed(playerId, amount) {
    let remaining = Number(amount);

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
        if (remaining <= 0) {
            break;
        }

        const used = Math.min(
            Number(batch.amount),
            remaining
        );

        update.run(
            Number(batch.amount) - used,
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
    `).run(
        playerId,
        day - 180
    );

    syncFeedBalance(playerId);
}

/* =====================================================
AUTH REGISTER
===================================================== */

async function register(req, res) {
    const body = await readBody(req);

    const email = normalizeEmail(body.email);
    const mobile = normalizeMobile(body.mobile);
    const username = normalizeUsername(body.username);
    const farmName = String(
        body.farmName || ""
    ).trim();
    const password = String(
        body.password || ""
    );

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

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return error(
            res,
            400,
            "ایمیل واردشده معتبر نیست."
        );
    }

    if (!/^09\d{9}$/.test(mobile)) {
        return error(
            res,
            400,
            "شماره موبایل معتبر نیست. شماره را به صورت 09xxxxxxxxx وارد کنید."
        );
    }

    if (!/^[a-z0-9_.-]{3,30}$/.test(username)) {
        return error(
            res,
            400,
            "نام کاربری باید بین ۳ تا ۳۰ کاراکتر و شامل حروف انگلیسی، عدد، نقطه، خط تیره یا زیرخط باشد."
        );
    }

    const duplicate = db.prepare(`
        SELECT email, mobile, username
        FROM players
        WHERE email = ?
           OR mobile = ?
           OR username = ?
        LIMIT 1
    `).get(
        email,
        mobile,
        username
    );

    if (duplicate) {
        if (duplicate.email === email) {
            return error(
                res,
                409,
                "این ایمیل قبلاً استفاده شده است."
            );
        }

        if (duplicate.mobile === mobile) {
            return error(
                res,
                409,
                "این شماره موبایل قبلاً استفاده شده است."
            );
        }

        if (duplicate.username === username) {
            return error(
                res,
                409,
                "این نام کاربری قبلاً استفاده شده است."
            );
        }

        return error(
            res,
            409,
            "اطلاعات ثبت‌نام قبلاً استفاده شده است."
        );
    }

    const playerId = id();

    const passwordHash = await bcrypt.hash(
        password,
        12
    );

    const transaction = db.transaction(() => {
        db.prepare(`
            INSERT INTO players
            (
                id,
                email,
                mobile,
                username,
                farm_name,
                password_hash,
                coins,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
            (
                player_id,
                day,
                chickens,
                feed,
                water,
                eggs,
                health,
                level,
                egg_price
            )
            VALUES (?, 1, 100, 100, 100, 0, 100, 1, 1)
        `).run(playerId);

        db.prepare(`
            INSERT INTO chicken_groups
            (
                player_id,
                amount,
                age
            )
            VALUES (?, 100, 0)
        `).run(playerId);

        /*
         * موجودی اولیه خوراک واقعی در جدول batch.
         * مقدار 100 کیلوگرم، مطابق موجودی شروع بازی.
         */
        db.prepare(`
            INSERT INTO feed_batches
            (
                player_id,
                amount,
                purchase_day,
                price,
                type,
                quality
            )
            VALUES (?, 100, 1, 0, 'normal', 100)
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

    try {
        transaction();
    } catch (err) {
        console.error(
            "REGISTER_TRANSACTION_ERROR:",
            err
        );

        if (
            String(err.message || "")
                .includes("UNIQUE constraint failed")
        ) {
            return error(
                res,
                409,
                "یکی از اطلاعات ثبت‌نام قبلاً استفاده شده است."
            );
        }

        throw err;
    }

    const token = createSession(
        playerId
    );

    return json(
        res,
        201,
        {
            token,
            player: {
                id: playerId,
                email,
                mobile,
                username,
                farmName,
                coins: 300
            }
        }
    );
}

/* =====================================================
AUTH LOGIN
===================================================== */

async function login(req, res) {
    const body = await readBody(req);

    /*
     * نسخه قدیمی کلاینت identifier می‌فرستاد.
     * نسخه قدیمی سرور username می‌خواند.
     * اینجا هر دو را قبول می‌کنیم.
     */
    const identifierRaw =
        body.identifier ??
        body.username ??
        body.email ??
        body.mobile ??
        "";

    const identifier = String(
        identifierRaw
    ).trim();

    const normalizedIdentifier =
        identifier.includes("@")
            ? normalizeEmail(identifier)
            : normalizeUsername(identifier);

    const mobileIdentifier =
        normalizeMobile(identifier);

    const password = String(
        body.password || ""
    );

    if (!identifier || !password) {
        return error(
            res,
            400,
            "نام کاربری/ایمیل/موبایل و رمز عبور را وارد کنید."
        );
    }

    const player = db.prepare(`
        SELECT *
        FROM players
        WHERE deleted_at IS NULL
          AND (
              lower(email) = ?
              OR mobile = ?
              OR lower(username) = ?
          )
        LIMIT 1
    `).get(
        normalizedIdentifier,
        mobileIdentifier,
        normalizedIdentifier
    );

    if (!player) {
        return error(
            res,
            401,
            "نام کاربری، ایمیل یا موبایل پیدا نشد."
        );
    }

    const valid = await bcrypt.compare(
        password,
        player.password_hash
    );

    if (!valid) {
        return error(
            res,
            401,
            "رمز عبور اشتباه است."
        );
    }

    const token = createSession(
        player.id
    );

    return json(
        res,
        200,
        {
            token,
            player: {
                id: player.id,
                email: player.email,
                mobile: player.mobile,
                username: player.username,
                farmName: player.farm_name,
                coins: player.coins
            }
        }
    );
}

/* =====================================================
ME / GAME STATE
===================================================== */

function me(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "اطلاعات مزرعه پیدا نشد."
        );
    }

    const currentFeed =
        syncFeedBalance(player.id);

    return json(
        res,
        200,
        {
            player: {
                id: player.id,
                email: player.email,
                mobile: player.mobile,
                username: player.username,
                farmName: player.farm_name,
                coins: player.coins,
                tokens: player.coins
            },

            farm: {
                name: player.farm_name,
                farmName: player.farm_name,
                day: farm.day,
                chickens: totalChickens(player.id),
                feed: currentFeed,
                water: farm.water,
                eggs: farm.eggs,
                health: farm.health,
                level: farm.level,
                eggPrice: farm.egg_price,
                temperature: temperature(farm.day),
                fedMorning: Boolean(farm.fed_morning),
                fedEvening: Boolean(farm.fed_evening),
                watered: Boolean(farm.watered)
            }
        }
    );
}

/* =====================================================
FEED
===================================================== */

async function feed(req, res, meal) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "مزرعه پیدا نشد."
        );
    }

    const field =
        meal === "evening"
            ? "fed_evening"
            : "fed_morning";

    if (farm[field]) {
        return error(
            res,
            400,
            "این وعده قبلاً ثبت شده است."
        );
    }

    const chickens =
        totalChickens(player.id);

    const required =
        feedForMeal(chickens);

    const available =
        availableFeed(player.id);

    if (available < required) {
        syncFeedBalance(player.id);

        return error(
            res,
            400,
            "خوراک کافی نیست."
        );
    }

    const success =
        consumeFeed(
            player.id,
            required
        );

    if (!success) {
        syncFeedBalance(player.id);

        return error(
            res,
            400,
            "موجودی خوراک کافی نیست."
        );
    }

    db.prepare(`
        UPDATE farms
        SET
            feed = ?,
            ${field} = 1
        WHERE player_id = ?
    `).run(
        availableFeed(player.id),
        player.id
    );

    return json(
        res,
        200,
        {
            success: true,
            meal,
            consumed: required,
            feedRemaining:
                availableFeed(player.id)
        }
    );
}

/* =====================================================
WATER
===================================================== */

function water(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "مزرعه پیدا نشد."
        );
    }

    if (farm.watered) {
        return error(
            res,
            400,
            "آب امروز قبلاً ثبت شده است."
        );
    }

    const chickens =
        totalChickens(player.id);

    const required =
        waterForMeal(chickens) * 2;

    if (farm.water < required) {
        return error(
            res,
            400,
            "آب کافی نیست."
        );
    }

    db.prepare(`
        UPDATE farms
        SET
            water = water - ?,
            watered = 1
        WHERE player_id = ?
    `).run(
        required,
        player.id
    );

    return json(
        res,
        200,
        {
            success: true,
            consumed: required
        }
    );
}

/* =====================================================
COLLECT EGGS
===================================================== */

function collectEggs(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "مزرعه پیدا نشد."
        );
    }

    if (farm.eggs <= 0) {
        return error(
            res,
            400,
            "تخم‌مرغی برای جمع‌آوری وجود ندارد."
        );
    }

    /*
     * در این نسخه تخم‌مرغ تولیدشده قبلاً
     * در موجودی مزرعه ثبت شده است.
     * انتقال کامل به سردخانه در ماژول
     * ذخیره‌سازی نهایی اضافه خواهد شد.
     */

    return json(
        res,
        200,
        {
            success: true,
            eggs: farm.eggs
        }
    );
}

/* =====================================================
END DAY
===================================================== */

function endDay(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "مزرعه پیدا نشد."
        );
    }

    const produced =
        eggProduction(farm);

    const temp =
        temperature(farm.day);

    let health =
        Number(farm.health);

    if (
        temp >= 38 ||
        temp <= 10
    ) {
        health = Math.max(
            0,
            health - 10
        );
    }

    if (
        !farm.fed_morning ||
        !farm.fed_evening
    ) {
        health = Math.max(
            0,
            health - 8
        );
    }

    if (!farm.watered) {
        health = Math.max(
            0,
            health - 8
        );
    }

    const newDay =
        farm.day + 1;

    const newEggPrice = Math.min(
        1.1,
        Math.max(
            0.9,
            Number(farm.egg_price) +
            (Math.random() * 0.04 - 0.02)
        )
    );

    const transaction =
        db.transaction(() => {
            db.prepare(`
                UPDATE farms
                SET
                    day = ?,
                    eggs = eggs + ?,
                    health = ?,
                    fed_morning = 0,
                    fed_evening = 0,
                    watered = 0,
                    egg_price = ?,
                    last_day_change = ?
                WHERE player_id = ?
            `).run(
                newDay,
                produced,
                health,
                newEggPrice,
                now(),
                player.id
            );

            db.prepare(`
                UPDATE chicken_groups
                SET age = age + 1
                WHERE player_id = ?
            `).run(player.id);

            expireFeed(
                player.id,
                newDay
            );

            addNotification(
                player.id,
                "روز جدید",
                `روز ${newDay} شروع شد.`
            );

            if (produced > 0) {
                addNotification(
                    player.id,
                    "تولید تخم‌مرغ",
                    `${produced} عدد تخم‌مرغ تولید شد.`
                );
            }

            if (health < 80) {
                addNotification(
                    player.id,
                    "هشدار سلامت",
                    "سلامت گله کاهش یافته است."
                );
            }

            if (temp >= 38) {
                addNotification(
                    player.id,
                    "هشدار دما",
                    "دمای مزرعه بسیار بالا است."
                );
            }

            if (temp <= 10) {
                addNotification(
                    player.id,
                    "هشدار دما",
                    "دمای مزرعه بسیار پایین است."
                );
            }
        });

    transaction();

    return json(
        res,
        200,
        {
            success: true,
            produced,
            day: newDay,
            temperature: temp,
            health,
            eggPrice: newEggPrice
        }
    );
}

/* =====================================================
EGG MARKET
===================================================== */

async function sellEggs(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const body = await readBody(req);

    const amount =
        Math.floor(
            Number(body.amount)
        );

    if (
        !Number.isInteger(amount) ||
        amount <= 0
    ) {
        return error(
            res,
            400,
            "تعداد نامعتبر است."
        );
    }

    const farm = db.prepare(`
        SELECT *
        FROM farms
        WHERE player_id = ?
    `).get(player.id);

    if (!farm) {
        return error(
            res,
            404,
            "مزرعه پیدا نشد."
        );
    }

    if (farm.eggs < amount) {
        return error(
            res,
            400,
            "تخم‌مرغ کافی ندارید."
        );
    }

    const revenue = Math.floor(
        amount * farm.egg_price
    );

    const transaction =
        db.transaction(() => {
            db.prepare(`
                UPDATE farms
                SET eggs = eggs - ?
                WHERE player_id = ?
            `).run(
                amount,
                player.id
            );

            db.prepare(`
                UPDATE players
                SET coins = coins + ?
                WHERE id = ?
            `).run(
                revenue,
                player.id
            );

            addTransaction(
                player.id,
                "EGG_SALE",
                revenue,
                `فروش ${amount} تخم‌مرغ`
            );
        });

    transaction();

    return json(
        res,
        200,
        {
            success: true,
            amount,
            revenue,
            price: farm.egg_price
        }
    );
}

/* =====================================================
MARKET
===================================================== */

function market(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    db.prepare(`
        DELETE FROM market_listings
        WHERE expires_at <= ?
    `).run(now());

    const listings =
        db.prepare(`
            SELECT
                m.id,
                m.type,
                m.amount,
                m.price,
                m.created_at AS createdAt,
                m.expires_at AS expiresAt,
                p.username,
                p.farm_name AS farmName
            FROM market_listings m
            JOIN players p
              ON p.id = m.seller_id
            WHERE m.expires_at > ?
              AND p.deleted_at IS NULL
            ORDER BY m.created_at ASC
        `).all(now());

    return json(
        res,
        200,
        {
            listings
        }
    );
}

/* =====================================================
SOCIAL SEARCH
===================================================== */

function socialSearch(
    req,
    res,
    query
) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const cleanQuery =
        String(query || "")
            .trim();

    const q =
        `%${cleanQuery}%`;

    const players =
        db.prepare(`
            SELECT
                p.id,
                p.username,
                p.farm_name AS farmName,
                f.level
            FROM players p
            JOIN farms f
              ON f.player_id = p.id
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
        ).map(item => ({
            ...item,
            chickens:
                totalChickens(item.id)
        }));

    return json(
        res,
        200,
        {
            players
        }
    );
}

/* =====================================================
FOLLOW
===================================================== */

async function follow(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const body =
        await readBody(req);

    const target =
        String(
            body.playerId || ""
        ).trim();

    if (
        !target ||
        target === player.id
    ) {
        return error(
            res,
            400,
            "بازیکن نامعتبر است."
        );
    }

    const exists =
        db.prepare(`
            SELECT id
            FROM players
            WHERE id = ?
              AND deleted_at IS NULL
        `).get(target);

    if (!exists) {
        return error(
            res,
            404,
            "بازیکن پیدا نشد."
        );
    }

    const followingCount =
        db.prepare(`
            SELECT COUNT(*) AS count
            FROM follows
            WHERE follower_id = ?
        `).get(player.id).count;

    const alreadyFollowing =
        db.prepare(`
            SELECT 1
            FROM follows
            WHERE follower_id = ?
              AND following_id = ?
        `).get(
            player.id,
            target
        );

    if (
        !alreadyFollowing &&
        Number(followingCount) >= 1000
    ) {
        return error(
            res,
            400,
            "حداکثر تعداد دنبال‌شده‌ها ۱۰۰۰ نفر است."
        );
    }

    db.prepare(`
        INSERT OR IGNORE INTO follows
        (
            follower_id,
            following_id,
            created_at
        )
        VALUES (?, ?, ?)
    `).run(
        player.id,
        target,
        now()
    );

    return json(
        res,
        200,
        {
            success: true
        }
    );
}

/* =====================================================
RANKING
===================================================== */

function ranking(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const rows =
        db.prepare(`
            SELECT
                p.id,
                p.username,
                p.farm_name AS farmName,
                p.coins,
                f.level,
                f.eggs
            FROM players p
            JOIN farms f
              ON f.player_id = p.id
            WHERE p.deleted_at IS NULL
            ORDER BY
                f.level DESC,
                p.coins DESC,
                p.id ASC
            LIMIT 100
        `).all();

    const players =
        rows.map(item => ({
            ...item,
            tokens: item.coins,
            chickens:
                totalChickens(item.id)
        }));

    return json(
        res,
        200,
        {
            players
        }
    );
}

/* =====================================================
NOTIFICATIONS
===================================================== */

function notifications(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const list =
        db.prepare(`
            SELECT
                id,
                title,
                text,
                text AS body,
                created_at AS createdAt
            FROM notifications
            WHERE player_id = ?
              AND created_at >= datetime('now', '-90 days')
            ORDER BY id DESC
            LIMIT 100
        `).all(player.id);

    return json(
        res,
        200,
        {
            notifications: list
        }
    );
}

/* =====================================================
REFERRAL
===================================================== */

function referral(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const code =
        player.id
            .replaceAll("-", "")
            .slice(0, 8)
            .toUpperCase();

    return json(
        res,
        200,
        {
            code,
            successful: 0,
            maximum: 10
        }
    );
}

/* =====================================================
WALLET HISTORY
===================================================== */

function walletHistory(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    const transactions =
        db.prepare(`
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

    return json(
        res,
        200,
        {
            balance: player.coins,
            coins: player.coins,
            tokens: player.coins,
            transactions
        }
    );
}

/* =====================================================
LOGOUT
===================================================== */

function logout(req, res) {
    const token =
        bearer(req);

    if (!token) {
        return json(
            res,
            200,
            {
                success: true
            }
        );
    }

    db.prepare(`
        DELETE FROM sessions
        WHERE token_hash = ?
    `).run(
        hashToken(token)
    );

    return json(
        res,
        200,
        {
            success: true
        }
    );
}

function logoutAll(req, res) {
    const player = auth(req);

    if (!player) {
        return error(
            res,
            401,
            "نیاز به ورود دارید."
        );
    }

    db.prepare(`
        DELETE FROM sessions
        WHERE player_id = ?
    `).run(player.id);

    return json(
        res,
        200,
        {
            success: true
        }
    );
}

/* =====================================================
ROUTER
===================================================== */

async function router(req, res) {
    if (req.method === "OPTIONS") {
        res.writeHead(204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers":
                "Content-Type, Authorization",
            "Access-Control-Allow-Methods":
                "GET,POST,OPTIONS"
        });

        return res.end();
    }

    const url =
        new URL(
            req.url,
            `http://${req.headers.host || "localhost"}`
        );

    try {

        /* ---------------- AUTH ---------------- */

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/register"
        ) {
            return register(
                req,
                res
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/login"
        ) {
            return login(
                req,
                res
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/logout"
        ) {
            return logout(
                req,
                res
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/auth/logout-all"
        ) {
            return logoutAll(
                req,
                res
            );
        }

        /* ---------------- PLAYER / STATE ---------------- */

        if (
            req.method === "GET" &&
            (
                url.pathname === "/api/me" ||
                url.pathname === "/api/game/state"
            )
        ) {
            return me(
                req,
                res
            );
        }

        /* ---------------- GAME ---------------- */

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/feed"
        ) {
            const body =
                await readBody(req);

            const meal =
                body.meal === "evening"
                    ? "evening"
                    : "morning";

            return feed(
                {
                    ...req,
                    body
                },
                res,
                meal
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/water"
        ) {
            return water(
                req,
                res
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/collect-eggs"
        ) {
            return collectEggs(
                req,
                res
            );
        }

        if (
            req.method === "POST" &&
            url.pathname === "/api/game/end-day"
        ) {
            return endDay(
                req,
                res
            );
        }

        /* ---------------- EGG MARKET ---------------- */

        if (
            req.method === "POST" &&
            url.pathname === "/api/market/sell-eggs"
        ) {
            return sellEggs(
                req,
                res
            );
        }

        if (
            req.method === "GET" &&
            url.pathname === "/api/market"
        ) {
            return market(
                req,
                res
            );
        }

        /* ---------------- SOCIAL ---------------- */

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
            return follow(
                req,
                res
            );
        }

        if (
            req.method === "GET" &&
            (
                url.pathname === "/api/ranking" ||
                url.pathname === "/api/social/ranking"
            )
        ) {
            return ranking(
                req,
                res
            );
        }

        /* ---------------- NOTIFICATIONS ---------------- */

        if (
            req.method === "GET" &&
            url.pathname === "/api/notifications"
        ) {
            return notifications(
                req,
                res
            );
        }

        /* ---------------- REFERRAL ---------------- */

        if (
            req.method === "GET" &&
            url.pathname === "/api/referral"
        ) {
            return referral(
                req,
                res
            );
        }

        /* ---------------- WALLET ---------------- */

        if (
            req.method === "GET" &&
            (
                url.pathname === "/api/wallet/history" ||
                url.pathname === "/api/wallet"
            )
        ) {
            return walletHistory(
                req,
                res
            );
        }

        /* ---------------- HEALTH ---------------- */

        if (
            req.method === "GET" &&
            url.pathname === "/health"
        ) {
            return json(
                res,
                200,
                {
                    ok: true,
                    service:
                        "vahid-chicken-farm",
                    time: now()
                }
            );
        }

        /* ---------------- STATIC FILES ---------------- */

        let requestedPath =
            decodeURIComponent(
                url.pathname
            );

        if (
            requestedPath === "/" ||
            requestedPath === ""
        ) {
            requestedPath =
                "/index.html";
        }

        const relativePath =
            path.normalize(
                requestedPath
                    .replace(/^[/\\]+/, "")
            );

        const filePath =
            path.resolve(
                PUBLIC,
                relativePath
            );

        const publicPath =
            path.resolve(PUBLIC);

        if (
            filePath !== publicPath &&
            !filePath.startsWith(
                publicPath + path.sep
            )
        ) {
            return error(
                res,
                403,
                "Forbidden"
            );
        }

        if (
            fs.existsSync(filePath) &&
            fs.statSync(filePath).isFile()
        ) {
            const ext =
                path.extname(filePath)
                    .toLowerCase();

            const types = {
                ".html":
                    "text/html; charset=utf-8",
                ".js":
                    "application/javascript; charset=utf-8",
                ".css":
                    "text/css; charset=utf-8",
                ".json":
                    "application/json; charset=utf-8",
                ".png":
                    "image/png",
                ".jpg":
                    "image/jpeg",
                ".jpeg":
                    "image/jpeg",
                ".svg":
                    "image/svg+xml",
                ".ico":
                    "image/x-icon",
                ".webp":
                    "image/webp"
            };

            res.writeHead(
                200,
                {
                    "Content-Type":
                        types[ext] ||
                        "application/octet-stream",
                    "Cache-Control":
                        ext === ".html"
                            ? "no-cache"
                            : "public, max-age=3600"
                }
            );

            return fs
                .createReadStream(filePath)
                .pipe(res);
        }

        return error(
            res,
            404,
            "Not Found"
        );

    } catch (err) {
        console.error(
            "SERVER_ERROR:",
            err
        );

        if (
            err &&
            err.message === "INVALID_JSON"
        ) {
            return error(
                res,
                400,
                "داده ارسالی معتبر نیست."
            );
        }

        if (
            err &&
            err.message === "BODY_TOO_LARGE"
        ) {
            return error(
                res,
                413,
                "حجم اطلاعات ارسالی بیش از حد مجاز است."
            );
        }

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

const server =
    http.createServer(router);

server.listen(
    PORT,
    HOST,
    () => {
        console.log(`
========================================
Vahid Chicken Farm Server
========================================
HTTP: ${HOST}:${PORT}
Database: SQLite
Players: REAL
Game State: SERVER AUTHORITATIVE
========================================
`);
    }
);

process.on(
    "SIGTERM",
    () => {
        try {
            db.close();
        } catch {}

        server.close(
            () => process.exit(0)
        );
    }
);

process.on(
    "SIGINT",
    () => {
        try {
            db.close();
        } catch {}

        server.close(
            () => process.exit(0)
        );
    }
);
