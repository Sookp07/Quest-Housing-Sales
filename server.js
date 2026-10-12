/* =========================================================
   Quest Housing Sales — Server
   Tasks covered:
     Task 1 — 3 external APIs (currency, weather + appointment forecast, geolocation)
     Task 2 — DB integration + appointments table + transactions
     Task 3 — Security: bcrypt hashing, prepared statements,
              manual input validation, XSS escaping
     Task 4 — .env configuration for deployment
   ========================================================= */

require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const escapeHtml = require('escape-html');

const app = express();
const PORT = process.env.PORT || 3000;

/* ----- MIDDLEWARE ----- */

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));


/* ----- DATABASE ----- */

const db = mysql.createConnection({
    host: process.env.DB_HOST || process.env.MYSQLHOST || 'localhost',
    port: process.env.DB_PORT || process.env.MYSQLPORT || 3306,
    user: process.env.DB_USER || process.env.MYSQLUSER || 'root',
    password: process.env.DB_PASSWORD ?? process.env.MYSQLPASSWORD ?? '',
    database: process.env.DB_NAME || process.env.MYSQLDATABASE || 'housing_sales'
});

db.connect((err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        return;
    }
    console.log('✅ Connected to MySQL');
});


/* ----- VALIDATION HELPERS ----- */

const VALID_UNIT_TYPES = ['Condo', 'Landed House', 'Terrace House', 'Townhouse', 'Semi-Detached', 'Bungalow'];
const VALID_UNIT_STATUSES = ['Available', 'Sold'];
const VALID_BUYER_STATUSES = ['Pending', 'Sold', 'Cancelled'];
const VALID_APPT_STATUSES = ['Scheduled', 'Completed', 'Cancelled', 'NoShow'];
const VALID_CURRENCIES = ['USD', 'MYR', 'SGD', 'EUR', 'GBP', 'JPY', 'AUD'];

const isValidEnum = (value, allowed) =>
    typeof value === 'string' && allowed.includes(value);

const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0;

const isPositiveNumber = (v) => typeof v === 'number' && isFinite(v) && v > 0;

function sanitizeRow(row, fields) {
    const out = { ...row };
    for (const f of fields) {
        if (out[f] != null) out[f] = escapeHtml(String(out[f]));
    }
    return out;
}


/* =========================================================
   AUTHENTICATION
   ========================================================= */

const SALT_ROUNDS = 10;

app.post('/api/signup', async (req, res) => {
    const { username, password, date_of_birth } = req.body;

    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (username.length < 3 || username.length > 50) {
        return res.status(400).json({ error: 'Username must be 3-50 characters' });
    }
    if (password.length < 6 || password.length > 100) {
        return res.status(400).json({ error: 'Password must be 6-100 characters' });
    }
    if (!date_of_birth) {
        return res.status(400).json({ error: 'Date of birth required (for password recovery)' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date_of_birth)) {
        return res.status(400).json({ error: 'Date of birth must be YYYY-MM-DD' });
    }

    try {
        const hashed = await bcrypt.hash(password, SALT_ROUNDS);
        const sql = 'INSERT INTO users (username, password, date_of_birth) VALUES (?, ?, ?)';
        db.query(sql, [username, hashed, date_of_birth], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({
                message: 'User created successfully',
                id: result.insertId,
                username
            });
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to hash password' });
    }
});


/*

==== Login ====

*/
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!isNonEmptyString(username) || !isNonEmptyString(password)) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    const sql = 'SELECT id, username, password FROM users WHERE username = ?';
    db.query(sql, [username], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = results[0];
        const isHashed = typeof user.password === 'string' && user.password.startsWith('$2');

        let ok = false;
        if (isHashed) {
            ok = await bcrypt.compare(password, user.password);
        } else {
            ok = password === user.password;
            if (ok) {
                const newHash = await bcrypt.hash(password, SALT_ROUNDS);
                db.query('UPDATE users SET password = ? WHERE id = ?', [newHash, user.id], () => {});
            }
        }

        if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

        res.json({ message: 'Login successful', id: user.id, username: user.username });
    });
});

/* =========================================================
   PASSWORD RESET
   ========================================================= */

// Step 1 — Verify identity via username + date of birth
app.post('/api/verify-identity', (req, res) => {
    const { username, date_of_birth } = req.body;

    if (!isNonEmptyString(username) || !isNonEmptyString(date_of_birth)) {
        return res.status(400).json({ error: 'Username and date of birth required' });
    }

    const sql = 'SELECT id, date_of_birth FROM users WHERE username = ?';
    db.query(sql, [username], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        if (results.length === 0) {
            return res.status(401).json({ error: 'Username or date of birth is incorrect' });
        }

        const user = results[0];

        // Normalize both dates to YYYY-MM-DD before comparing
        const normalizeDate = (d) => {
            if (!d) return null;
            const date = new Date(d);
            if (isNaN(date.getTime())) return null;
            const pad = (n) => String(n).padStart(2, '0');
            return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
        };

        const stored = normalizeDate(user.date_of_birth);
        const submitted = normalizeDate(date_of_birth);

        console.log('🔐 Comparing:', { stored, submitted, raw: date_of_birth });

        if (!stored || stored !== submitted) {
            return res.status(401).json({ error: 'Username or date of birth is incorrect' });
        }

        res.json({
            message: 'Identity verified',
            userId: user.id
        });
    });
});

// Step 2 — Reset the password (requires verified userId from Step 1)
app.post('/api/reset-password', async (req, res) => {
    const { userId, newPassword } = req.body;

    if (!userId || !Number.isInteger(Number(userId))) {
        return res.status(400).json({ error: 'Valid userId required' });
    }
    if (!isNonEmptyString(newPassword)) {
        return res.status(400).json({ error: 'New password required' });
    }
    if (newPassword.length < 6 || newPassword.length > 100) {
        return res.status(400).json({ error: 'Password must be 6-100 characters' });
    }

    try {
        const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
        const sql = 'UPDATE users SET password = ? WHERE id = ?';
        db.query(sql, [hashed, userId], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({ message: 'Password reset successful' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to hash password' });
    }
});


/* =========================================================
   UNITS
   ========================================================= */

app.get('/api/units', (req, res) => {
    const sql = 'SELECT id, name, type, location, status, price, currency, image_data FROM units ORDER BY id';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results.map(r => sanitizeRow(r, ['name', 'location'])));
    });
});

app.post('/api/units', (req, res) => {
    const { name, type, location, status, price, currency, image_data } = req.body;

    if (!isNonEmptyString(name)) return res.status(400).json({ error: 'Unit name required' });
    if (!isNonEmptyString(location)) return res.status(400).json({ error: 'Location required' });
    if (!isValidEnum(type, VALID_UNIT_TYPES)) return res.status(400).json({ error: 'Invalid unit type' });
    if (!isValidEnum(status, VALID_UNIT_STATUSES)) return res.status(400).json({ error: 'Invalid unit status' });
    if (!isPositiveNumber(Number(price))) return res.status(400).json({ error: 'Valid price required' });
    if (currency !== undefined && !isValidEnum(currency, VALID_CURRENCIES)) {
        return res.status(400).json({ error: 'Invalid currency' });
    }

    const sql = 'INSERT INTO units (name, type, location, status, price, currency, image_data) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name.trim(), type, location.trim(), status, price, currency || 'USD', image_data || null], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const readSql = 'SELECT id, name, type, location, status, price, currency, image_data FROM units WHERE id = ?';
        db.query(readSql, [result.insertId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json(sanitizeRow(rows[0], ['name', 'location']));
        });
    });
});

app.put('/api/units/:id', (req, res) => {
    const { name, type, location, status, price, currency, image_data } = req.body;
    const id = req.params.id;

    if (!isNonEmptyString(name)) return res.status(400).json({ error: 'Unit name required' });
    if (!isNonEmptyString(location)) return res.status(400).json({ error: 'Location required' });
    if (!isValidEnum(type, VALID_UNIT_TYPES)) return res.status(400).json({ error: 'Invalid unit type' });
    if (!isValidEnum(status, VALID_UNIT_STATUSES)) return res.status(400).json({ error: 'Invalid unit status' });
    if (!isPositiveNumber(Number(price))) return res.status(400).json({ error: 'Valid price required' });
    if (currency !== undefined && !isValidEnum(currency, VALID_CURRENCIES)) {
        return res.status(400).json({ error: 'Invalid currency' });
    }

    const sql = 'UPDATE units SET name=?, type=?, location=?, status=?, price=?, currency=?, image_data=? WHERE id=?';
    db.query(sql, [name.trim(), type, location.trim(), status, price, currency || 'USD', image_data || null, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Unit not found' });

        const readSql = 'SELECT id, name, type, location, status, price, currency, image_data FROM units WHERE id = ?';
        db.query(readSql, [id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(sanitizeRow(rows[0], ['name', 'location']));
        });
    });
});

app.delete('/api/units/:id', (req, res) => {
    db.query('DELETE FROM units WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Unit not found' });
        res.json({ message: 'Unit deleted' });
    });
});


/* =========================================================
   BUYERS
   ========================================================= */

app.get('/api/buyers', (req, res) => {
    const sql = 'SELECT id, name, agent, viewing_date, viewing_time, unit, status FROM buyers ORDER BY id';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results.map(r => sanitizeRow(r, ['name', 'agent', 'unit'])));
    });
});

app.post('/api/buyers', (req, res) => {
    const { name, agent, viewing_date, viewing_time, unit, status } = req.body;

    if (!isNonEmptyString(name)) return res.status(400).json({ error: 'Buyer name required' });
    if (status !== undefined && !isValidEnum(status, VALID_BUYER_STATUSES)) {
        return res.status(400).json({ error: 'Invalid buyer status' });
    }

    const sql = 'INSERT INTO buyers (name, agent, viewing_date, viewing_time, unit, status) VALUES (?, ?, ?, ?, ?, ?)';
    const params = [
        name.trim(),
        (agent && agent.trim()) || 'Unassigned',
        viewing_date || null,
        viewing_time || null,
        unit || null,
        status || 'Pending'
    ];
    db.query(sql, params, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const readSql = 'SELECT id, name, agent, viewing_date, viewing_time, unit, status FROM buyers WHERE id = ?';
        db.query(readSql, [result.insertId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json(sanitizeRow(rows[0], ['name', 'agent', 'unit']));
        });
    });
});

app.put('/api/buyers/:id', (req, res) => {
    const { name, agent, viewing_date, viewing_time, unit, status } = req.body;
    const id = req.params.id;

    if (!isNonEmptyString(name)) return res.status(400).json({ error: 'Buyer name required' });
    if (!isValidEnum(status, VALID_BUYER_STATUSES)) return res.status(400).json({ error: 'Invalid buyer status' });

    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ error: err.message });

        const sql = 'UPDATE buyers SET name=?, agent=?, viewing_date=?, viewing_time=?, unit=?, status=? WHERE id=?';
        db.query(sql, [name.trim(), agent, viewing_date, viewing_time, unit, status, id], (err, result) => {
            if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
            if (result.affectedRows === 0) return db.rollback(() => res.status(404).json({ error: 'Buyer not found' }));

            if (status !== 'Sold') {
                return db.commit((err) => {
                    if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
                    res.json({ message: 'Buyer updated' });
                });
            }

            db.query('UPDATE units SET status="Sold" WHERE name=?', [unit], (err) => {
                if (err) return db.rollback(() => res.status(500).json({ error: err.message }));

                db.query(
                    'UPDATE buyers SET status="Cancelled" WHERE unit=? AND status="Pending" AND id<>?',
                    [unit, id],
                    (err) => {
                        if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
                        db.commit((err) => {
                            if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
                            res.json({ message: 'Buyer sold; unit marked; others cancelled' });
                        });
                    }
                );
            });
        });
    });
});

app.delete('/api/buyers/:id', (req, res) => {
    db.query('DELETE FROM buyers WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Buyer not found' });
        res.json({ message: 'Buyer deleted' });
    });
});


/* =========================================================
   ANNOUNCEMENTS
   ========================================================= */

app.get('/api/announcements', (req, res) => {
    const sql = 'SELECT id, text, created_at FROM announcements ORDER BY id';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results.map(r => sanitizeRow(r, ['text'])));
    });
});

app.post('/api/announcements', (req, res) => {
    const { text } = req.body;

    if (!isNonEmptyString(text)) return res.status(400).json({ error: 'Announcement text required' });
    if (text.length > 500) return res.status(400).json({ error: 'Announcement too long (max 500)' });

    const sql = 'INSERT INTO announcements (text) VALUES (?)';
    db.query(sql, [text.trim()], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        const readSql = 'SELECT id, text, created_at FROM announcements WHERE id = ?';
        db.query(readSql, [result.insertId], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json(sanitizeRow(rows[0], ['text']));
        });
    });
});

app.put('/api/announcements/:id', (req, res) => {
    const { text } = req.body;
    const id = req.params.id;

    if (!isNonEmptyString(text)) return res.status(400).json({ error: 'Announcement text required' });
    if (text.length > 500) return res.status(400).json({ error: 'Announcement too long (max 500)' });

    db.query('UPDATE announcements SET text=? WHERE id=?', [text.trim(), id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Announcement not found' });

        const readSql = 'SELECT id, text, created_at FROM announcements WHERE id = ?';
        db.query(readSql, [id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(sanitizeRow(rows[0], ['text']));
        });
    });
});

app.delete('/api/announcements/:id', (req, res) => {
    db.query('DELETE FROM announcements WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Announcement not found' });
        res.json({ message: 'Announcement deleted' });
    });
});


/* =========================================================
   APPOINTMENTS
   ========================================================= */

app.get('/api/appointments', (req, res) => {
    const sql = `
        SELECT a.id, a.buyer_id, a.unit_id, a.scheduled_at, a.status, a.notes,
               b.name AS buyer_name, u.name AS unit_name, u.location AS unit_location
        FROM appointments a
        JOIN buyers b ON b.id = a.buyer_id
        JOIN units u  ON u.id = a.unit_id
        ORDER BY a.scheduled_at DESC
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results.map(r => sanitizeRow(r, ['buyer_name', 'unit_name', 'unit_location', 'notes'])));
    });
});

app.post('/api/appointments', (req, res) => {
    const { buyer_id, unit_id, scheduled_at, status, notes } = req.body;

    if (!buyer_id || !Number.isInteger(Number(buyer_id))) {
        return res.status(400).json({ error: 'Valid buyer_id required' });
    }
    if (!unit_id || !Number.isInteger(Number(unit_id))) {
        return res.status(400).json({ error: 'Valid unit_id required' });
    }
    if (!isNonEmptyString(scheduled_at)) {
        return res.status(400).json({ error: 'scheduled_at required' });
    }
    if (status !== undefined && !isValidEnum(status, VALID_APPT_STATUSES)) {
        return res.status(400).json({ error: 'Invalid appointment status' });
    }

    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ error: err.message });

        db.query('SELECT id FROM buyers WHERE id = ?', [buyer_id], (err, buyerRows) => {
            if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
            if (buyerRows.length === 0) return db.rollback(() => res.status(400).json({ error: 'Buyer not found' }));

            db.query('SELECT id, status FROM units WHERE id = ?', [unit_id], (err, unitRows) => {
                if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
                if (unitRows.length === 0) return db.rollback(() => res.status(400).json({ error: 'Unit not found' }));
                if (unitRows[0].status === 'Sold') return db.rollback(() => res.status(400).json({ error: 'Unit already sold' }));

                const sql = 'INSERT INTO appointments (buyer_id, unit_id, scheduled_at, status, notes) VALUES (?, ?, ?, ?, ?)';
                db.query(sql, [buyer_id, unit_id, scheduled_at, status || 'Scheduled', notes || null], (err, result) => {
                    if (err) return db.rollback(() => res.status(500).json({ error: err.message }));

                    db.commit((err) => {
                        if (err) return db.rollback(() => res.status(500).json({ error: err.message }));
                        res.status(201).json({ id: result.insertId, message: 'Appointment created' });
                    });
                });
            });
        });
    });
});

app.put('/api/appointments/:id', (req, res) => {
    const { scheduled_at, status, notes } = req.body;

    if (!isNonEmptyString(scheduled_at)) {
        return res.status(400).json({ error: 'scheduled_at required' });
    }
    if (!isValidEnum(status, VALID_APPT_STATUSES)) {
        return res.status(400).json({ error: 'Invalid appointment status' });
    }

    const sql = 'UPDATE appointments SET scheduled_at=?, status=?, notes=? WHERE id=?';
    db.query(sql, [scheduled_at, status, notes || null, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Appointment not found' });
        res.json({ message: 'Appointment updated' });
    });
});

app.delete('/api/appointments/:id', (req, res) => {
    db.query('DELETE FROM appointments WHERE id = ?', [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Appointment not found' });
        res.json({ message: 'Appointment deleted' });
    });
});


/* =========================================================
   STATISTICS
   ========================================================= */

app.get('/api/stats', (req, res) => {
    const queries = {
        available: 'SELECT COUNT(*) as count FROM units WHERE status="Available"',
        sold: 'SELECT COUNT(*) as count FROM units WHERE status="Sold"',
        buyers: 'SELECT COUNT(*) as count FROM buyers',
        viewings: 'SELECT COUNT(*) as count FROM buyers WHERE viewing_date IS NOT NULL',
        appointments: 'SELECT COUNT(*) as count FROM appointments'
    };

    const results = {};
    let completed = 0;

    for (const [key, sql] of Object.entries(queries)) {
        db.query(sql, (err, rows) => {
            results[key] = err ? 0 : rows[0].count;
            completed++;
            if (completed === Object.keys(queries).length) {
                res.json(results);
            }
        });
    }
});


/* =========================================================
   EXTERNAL APIs (TASK 1)
   ========================================================= */

const apiCache = new Map();
const CACHE_TTL = 1000 * 60 * 10; // 10 minutes

async function cachedFetch(key, url, options = {}) {
    const now = Date.now();
    const hit = apiCache.get(key);
    if (hit && now - hit.time < CACHE_TTL) return hit.data;

    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`External API failed: ${res.status}`);
    const data = await res.json();
    apiCache.set(key, { time: now, data });
    return data;
}


/* --- API 1a: Single currency conversion (Frankfurter) --- */

app.get('/api/external/convert', async (req, res) => {
    const { amount, from = 'USD', to = 'MYR' } = req.query;
    const amt = parseFloat(amount);

    if (!amt || amt <= 0) {
        return res.status(400).json({ error: 'Valid amount required' });
    }
    if (from === to) {
        return res.json({
            amount: amt, from, to, converted: amt, rate: 1,
            date: new Date().toISOString().slice(0, 10)
        });
    }

    try {
        const data = await cachedFetch(
            `fx-${from}-${to}-${amt}`,
            `https://api.frankfurter.app/latest?amount=${amt}&from=${from}&to=${to}`
        );
        res.json({
            amount: amt,
            from,
            to,
            converted: data.rates[to],
            rate: data.rates[to] / amt,
            date: data.date
        });
    } catch (err) {
        res.status(502).json({ error: 'Currency service unavailable', detail: err.message });
    }
});


/* --- API 1b: Batch currency conversion (returns just the rate) --- */

app.get('/api/external/convert-batch', async (req, res) => {
    const { from = 'USD', to = 'MYR' } = req.query;

    if (!isValidEnum(from, VALID_CURRENCIES) || !isValidEnum(to, VALID_CURRENCIES)) {
        return res.status(400).json({ error: 'Invalid currency code' });
    }

    if (from === to) {
        return res.json({ from, to, rate: 1, date: new Date().toISOString().slice(0, 10) });
    }

    try {
        const data = await cachedFetch(
            `rate-${from}-${to}`,
            `https://api.frankfurter.app/latest?from=${from}&to=${to}`
        );
        const rate = data.rates[to];
        if (!rate) return res.status(502).json({ error: 'Rate unavailable' });

        res.json({ from, to, rate, date: data.date });
    } catch (err) {
        res.status(502).json({ error: 'Currency service unavailable', detail: err.message });
    }
});


/* --- API 2a: Current weather by location (Nominatim + Open-Meteo) --- */

async function geocode(locationName) {
    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${encodeURIComponent(locationName)}`;
    const res = await fetch(url, {
        headers: { 'User-Agent': 'QuestHousingSales/1.0 (student project)' }
    });
    const data = await res.json();
    if (!data || data.length === 0) return null;
    return { lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon) };
}

app.get('/api/external/weather', async (req, res) => {
    const { location } = req.query;
    if (!location) return res.status(400).json({ error: 'Location required' });

    try {
        const coords = await geocode(location);
        if (!coords) return res.status(404).json({ error: 'Location not found' });

        const data = await cachedFetch(
            `weather-${coords.lat.toFixed(2)}-${coords.lon.toFixed(2)}`,
            `https://api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}&current=temperature_2m,weather_code,wind_speed_10m`
        );

        res.json({
            location,
            coordinates: coords,
            temperature: data.current.temperature_2m,
            windspeed: data.current.wind_speed_10m,
            weathercode: data.current.weather_code,
            units: { temperature: '°C', windspeed: 'km/h' }
        });
    } catch (err) {
        res.status(502).json({ error: 'Weather service unavailable', detail: err.message });
    }
});


/* --- API 2b: Weather at a specific appointment datetime ---
   GET /api/external/weather-at?location=Kuala+Lumpur&date=2026-10-20&time=14:30
------------------------------------------------------------ */
app.get('/api/external/weather-at', async (req, res) => {
    const { location, date, time } = req.query;

    if (!location) return res.status(400).json({ error: 'Location required' });
    if (!date) return res.status(400).json({ error: 'Date required (YYYY-MM-DD)' });

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({ error: 'Date must be YYYY-MM-DD' });
    }

    const targetDate = new Date(date + 'T00:00:00');
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const daysAhead = Math.floor((targetDate - today) / (1000 * 60 * 60 * 24));

    if (daysAhead < 0) {
        return res.status(400).json({ error: 'Date is in the past' });
    }
    if (daysAhead > 16) {
        return res.status(400).json({
            error: 'Date too far ahead',
            detail: `Open-Meteo forecasts up to 16 days ahead. Requested date is ${daysAhead} days away.`
        });
    }

    try {
        const coords = await geocode(location);
        if (!coords) return res.status(404).json({ error: 'Location not found' });

        const data = await cachedFetch(
            `weather-at-${coords.lat.toFixed(2)}-${coords.lon.toFixed(2)}-${date}`,
            `https://api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}` +
            `&daily=temperature_2m_max,temperature_2m_min,precipitation_sum,precipitation_probability_max,` +
            `wind_speed_10m_max,weather_code` +
            `&start_date=${date}&end_date=${date}&timezone=auto`
        );

        if (!data.daily || !data.daily.time || data.daily.time.length === 0) {
            return res.status(404).json({ error: 'No forecast data available for that date' });
        }

        // If a time was provided, fetch hourly data and pick the matching hour
        let hourly = null;
        if (time && /^\d{2}:\d{2}$/.test(time)) {
            try {
                const hourlyData = await cachedFetch(
                    `weather-hourly-${coords.lat.toFixed(2)}-${coords.lon.toFixed(2)}-${date}`,
                    `https://api.open-meteo.com/v1/forecast?latitude=${coords.lat}&longitude=${coords.lon}` +
                    `&hourly=temperature_2m,precipitation_probability,wind_speed_10m,weather_code` +
                    `&start_date=${date}&end_date=${date}&timezone=auto`
                );
                if (hourlyData.hourly && hourlyData.hourly.time) {
                    const targetHour = parseInt(time.split(':')[0], 10);
                    const idx = hourlyData.hourly.time.findIndex(t => {
                        const h = new Date(t).getHours();
                        return h === targetHour;
                    });
                    if (idx !== -1) {
                        hourly = {
                            time: hourlyData.hourly.time[idx],
                            temperature: hourlyData.hourly.temperature_2m[idx],
                            precipitation_probability: hourlyData.hourly.precipitation_probability[idx],
                            wind_speed: hourlyData.hourly.wind_speed_10m[idx],
                            weather_code: hourlyData.hourly.weather_code[idx]
                        };
                    }
                }
            } catch (err) {
                console.warn('Hourly forecast fetch failed:', err.message);
            }
        }

        res.json({
            location,
            coordinates: coords,
            date,
            requested_time: time || null,
            daily: {
                temperature_max: data.daily.temperature_2m_max[0],
                temperature_min: data.daily.temperature_2m_min[0],
                precipitation_sum: data.daily.precipitation_sum[0],
                precipitation_probability: data.daily.precipitation_probability_max[0],
                wind_speed_max: data.daily.wind_speed_10m_max[0],
                weather_code: data.daily.weather_code[0]
            },
            hourly
        });
    } catch (err) {
        res.status(502).json({ error: 'Weather service unavailable', detail: err.message });
    }
});


/* --- API 3: State → Country Lookup (CountriesNow — verified) --- */
app.get('/api/external/state-to-country', async (req, res) => {
    const { state } = req.query;

    if (!state || state.trim().length < 2) {
        return res.status(400).json({ error: 'State name required (min 2 chars)' });
    }
    if (state.length > 60) {
        return res.status(400).json({ error: 'State name too long' });
    }

    const needle = state.trim().toLowerCase();
    console.log('🌍 State lookup for:', needle);

    try {
        // Fetch ALL countries with their states (cached for 10 min via cachedFetch)
        const json = await cachedFetch(
            'countriesnow-states',
            'https://countriesnow.space/api/v0.1/countries/states',
            {
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'QuestHousingSales/1.0 (student project)'
                }
            }
        );

        console.log('🌍 Countries loaded:', json.data?.length || 0);

        if (!json.data || !Array.isArray(json.data)) {
            console.error('🌍 Unexpected shape:', JSON.stringify(json).substring(0, 300));
            return res.status(502).json({ error: 'Invalid response from state service' });
        }

        // Search across all countries → find the state
        let match = null;
        for (const country of json.data) {
            const states = country.states || [];
            const found =
                states.find(s => s.name?.toLowerCase() === needle) ||
                states.find(s => s.name?.toLowerCase().includes(needle));
            if (found) {
                match = {
                    state: found.name,
                    stateCode: found.state_code || null,
                    country: country.name,
                    countryCode: country.iso2 || null,
                    countryCode3: country.iso3 || null
                };
                break;
            }
        }

        if (!match) {
            console.log('🌍 No match for:', needle);
            return res.status(404).json({ error: 'State not found' });
        }

        console.log('🌍 Match:', match.state, '→', match.country);
        res.json(match);

    } catch (err) {
        console.error('🌍 State lookup failed:', err.message);
        res.status(502).json({
            error: 'State lookup service unavailable',
            detail: err.message
        });
    }
});

/* =========================================================
   START SERVER
   ========================================================= */

app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});