const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

// --- Database Setup ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const app = express();
const port = process.env.PORT || 3000;

async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);
    console.log('Users table checked/created.');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        event_key TEXT NOT NULL,
        description TEXT NOT NULL,
        notes TEXT DEFAULT '',
        category TEXT DEFAULT 'General',
        recurrence_pattern TEXT DEFAULT 'none',
        number_of_repeats INTEGER DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      );
    `);
    console.log('Events table checked/created.');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS recurrence_exceptions (
        id SERIAL PRIMARY KEY,
        event_id INTEGER NOT NULL,
        exception_date_key TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        UNIQUE(event_id, exception_date_key),
        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      );
    `);
    console.log('Recurrence_exceptions table checked/created.');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS event_modifications (
        id SERIAL PRIMARY KEY,
        original_event_id INTEGER NOT NULL,
        modified_date_key TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        notes TEXT DEFAULT '',
        category TEXT DEFAULT 'General',
        UNIQUE(original_event_id, modified_date_key),
        FOREIGN KEY (original_event_id) REFERENCES events (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
      );
    `);
    console.log('Event_modifications table checked/created.');

  } catch (err) {
    console.error('Error initializing database:', err.stack);
  }
}

// --- Middleware ---
app.use(cors());
app.use(express.json());

app.use((err, req, res, next) => {
    console.error('Server error:', err.stack);
    res.status(500).json({ message: 'Internal server error' });
});

// --- API Routes ---
app.get('/', (req, res) => {
    res.send('Hello from Phase Calendar Backend!');
});

app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || username.length < 3 || !password || password.length < 6) {
        return res.status(400).json({ message: 'Invalid input provided.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'User registered successfully!', userId: newUser.rows[0].id, username: newUser.rows[0].username });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ message: 'Username already exists.' });
        }
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            res.status(200).json({ message: 'Login successful!', userId: user.id, username: user.username });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    } catch (err) {
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/events', async (req, res) => {
    const { userId, eventKey, description, notes, category, recurrencePattern, numberOfRepeats } = req.body;
    // (Input validation remains the same...)
    try {
        const result = await pool.query(
            'INSERT INTO events (user_id, event_key, description, notes, category, recurrence_pattern, number_of_repeats) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
            [userId, eventKey, description, notes, category, recurrencePattern, numberOfRepeats]
        );
        res.status(201).json({ message: 'Event added successfully!', eventId: result.rows[0].id });
    } catch (err) {
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/events', async (req, res) => {
    const { userId } = req.query;
    if (!userId) {
        return res.status(400).json({ message: 'Valid userId is required.' });
    }
    try {
        const masterEventsRes = await pool.query('SELECT * FROM events WHERE user_id = $1', [userId]);
        const exceptionsRes = await pool.query('SELECT event_id, exception_date_key FROM recurrence_exceptions WHERE user_id = $1', [userId]);
        const modificationsRes = await pool.query('SELECT * FROM event_modifications WHERE user_id = $1', [userId]);

        const exceptionMap = new Map();
        exceptionsRes.rows.forEach(ex => {
            if (!exceptionMap.has(ex.event_id)) exceptionMap.set(ex.event_id, new Set());
            exceptionMap.get(ex.event_id).add(ex.exception_date_key);
        });

        const modificationMap = new Map();
        modificationsRes.rows.forEach(mod => {
            if (!modificationMap.has(mod.original_event_id)) modificationMap.set(mod.original_event_id, new Map());
            modificationMap.get(mod.original_event_id).set(mod.modified_date_key, mod);
        });

        res.status(200).json({
            masterEvents: masterEventsRes.rows,
            exceptions: Array.from(exceptionMap.entries()).map(([id, keys]) => [id, Array.from(keys)]),
            modifications: Array.from(modificationMap.entries()).map(([id, mods]) => [id, Array.from(mods.entries())])
        });
    } catch (err) {
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/events/:id', async (req, res) => {
    const { id } = req.params;
    const { userId, description, notes, category, recurrencePattern, numberOfRepeats } = req.body;
    try {
        const result = await pool.query(
            'UPDATE events SET description = $1, notes = $2, category = $3, recurrence_pattern = $4, number_of_repeats = $5 WHERE id = $6 AND user_id = $7',
            [description, notes, category, recurrencePattern, numberOfRepeats, id, userId]
        );
        if (result.rowCount > 0) {
            res.status(200).json({ message: 'Master event updated successfully!' });
        } else {
            res.status(404).json({ message: 'Event not found or user not authorized.' });
        }
    } catch (err) {
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.put('/api/events/instance/:originalEventId/:eventKey', async (req, res) => {
    const { originalEventId, eventKey } = req.params;
    const { userId, description, notes, category } = req.body;
    try {
        const sql = `
            INSERT INTO event_modifications (original_event_id, modified_date_key, user_id, description, notes, category)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (original_event_id, modified_date_key)
            DO UPDATE SET description = $4, notes = $5, category = $6;
        `;
        await pool.query(sql, [originalEventId, eventKey, userId, description, notes, category]);
        res.status(200).json({ message: 'Event instance updated successfully!' });
    } catch (err) {
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/events/:id', async (req, res) => {
    const { id } = req.params;
    const { userId } = req.query;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // The ON DELETE CASCADE in the schema handles deleting related modifications and exceptions.
        const result = await client.query('DELETE FROM events WHERE id = $1 AND user_id = $2', [id, userId]);
        await client.query('COMMIT');
        if (result.rowCount > 0) {
            res.status(200).json({ message: 'Master event and all related data deleted successfully!' });
        } else {
            res.status(404).json({ message: 'Event not found or user not authorized.' });
        }
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    } finally {
        client.release();
    }
});

app.delete('/api/events/instance/:originalEventId/:eventKey', async (req, res) => {
    const { originalEventId, eventKey } = req.params;
    const { userId } = req.query;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // Add an exception to "delete" the instance
        await client.query(
            'INSERT INTO recurrence_exceptions (event_id, exception_date_key, user_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
            [originalEventId, eventKey, userId]
        );
        // Also remove any modification that might exist for this instance
        await client.query(
            'DELETE FROM event_modifications WHERE original_event_id = $1 AND modified_date_key = $2 AND user_id = $3',
            [originalEventId, eventKey, userId]
        );
        await client.query('COMMIT');
        res.status(200).json({ message: 'Event instance excluded successfully!' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err.stack);
        res.status(500).json({ message: 'Internal server error' });
    } finally {
        client.release();
    }
});

// --- Start the server ---
app.listen(port, () => {
  console.log(`Phase Calendar Backend listening on port ${port}`);
  initializeDatabase();
});