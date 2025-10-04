const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;

// --- Database Setup ---
const db = new sqlite3.Database('./phase_calendar.db', (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table checked/created.');
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        event_key TEXT NOT NULL, -- YYYY-DDD for the ORIGINAL occurrence
        description TEXT NOT NULL,
        notes TEXT DEFAULT '',
        category TEXT DEFAULT 'General',
        recurrence_pattern TEXT DEFAULT 'none',
        number_of_repeats INTEGER DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('Error creating events table:', err.message);
        } else {
            console.log('Events table checked/created.');
            // Add columns if they don't exist
            db.run(`ALTER TABLE events ADD COLUMN notes TEXT DEFAULT ''`, (alterErr) => {
                if (alterErr && !alterErr.message.includes('duplicate column name')) {
                    console.error('Error altering events table to add notes column:', alterErr.message);
                } else if (!alterErr) {
                    console.log('Events table altered to add notes column (if not already present).');
                }
            });
            db.run(`ALTER TABLE events ADD COLUMN category TEXT DEFAULT 'General'`, (alterErr) => {
                if (alterErr && !alterErr.message.includes('duplicate column name')) {
                    console.error('Error altering events table to add category column:', alterErr.message);
                } else if (!alterErr) {
                    console.log('Events table altered to add category column (if not already present).');
                }
            });
            db.run(`ALTER TABLE events ADD COLUMN recurrence_pattern TEXT DEFAULT 'none'`, (alterErr) => {
                if (alterErr && !alterErr.message.includes('duplicate column name')) {
                    console.error('Error altering events table to add recurrence_pattern column:', alterErr.message);
                } else if (!alterErr) {
                    console.log('Events table altered to add recurrence_pattern column (if not already present).');
                }
            });
            db.run(`ALTER TABLE events ADD COLUMN number_of_repeats INTEGER DEFAULT NULL`, (alterErr) => {
                if (alterErr && !alterErr.message.includes('duplicate column name')) {
                    console.error('Error altering events table to add number_of_repeats column:', alterErr.message);
                } else if (!alterErr) {
                    console.log('Events table altered to add number_of_repeats column (if not already present).');
                }
            });
        }
    });

    // NEW: Table to store specific dates where a recurring event instance should be skipped
    db.run(`CREATE TABLE IF NOT EXISTS recurrence_exceptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,          -- Refers to the original recurring event's ID
        exception_date_key TEXT NOT NULL,   -- YYYY-DDD of the skipped instance
        user_id INTEGER NOT NULL,           -- For security and partitioning
        UNIQUE(event_id, exception_date_key), -- Ensure no duplicate exceptions for same event+date
        FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('Error creating recurrence_exceptions table:', err.message);
        } else {
            console.log('Recurrence_exceptions table checked/created.');
        }
    });

    // NEW: Table to store modifications for specific occurrences of recurring events
    db.run(`CREATE TABLE IF NOT EXISTS event_modifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_event_id INTEGER NOT NULL, -- Refers to the original recurring event's ID
        modified_date_key TEXT NOT NULL,    -- YYYY-DDD of the modified instance
        user_id INTEGER NOT NULL,           -- For security and partitioning
        description TEXT NOT NULL,
        notes TEXT DEFAULT '',
        category TEXT DEFAULT 'General',
        UNIQUE(original_event_id, modified_date_key), -- Only one modification per instance
        FOREIGN KEY (original_event_id) REFERENCES events (id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
        if (err) {
            console.error('Error creating event_modifications table:', err.message);
        } else {
            console.log('Event_modifications table checked/created.');
        }
    });
}

// --- Middleware ---
app.use(cors());
app.use(express.json());

// Global error handler to ensure JSON responses
app.use((err, req, res, next) => {
    console.error('Server error:', {
        message: err.message,
        stack: err.stack,
        path: req.originalUrl,
        method: req.method
    });
    res.status(500).json({ message: 'Internal server error' });
});

// --- API Routes ---
app.get('/', (req, res) => {
    res.send('Hello from Phase Calendar Backend!');
});

app.get('/api/init-db', (req, res) => {
    initializeDatabase();
    res.json({ message: 'Database initialization attempted (tables checked/created).' });
});

// --- User Registration (Sign Up) API ---
app.post('/api/signup', async (req, res) => {
    const username = req.body.username ? req.body.username.trim() : '';
    const password = req.body.password ? req.body.password.trim() : '';

    if (!username || username.length < 3 || username.length > 50) {
        return res.status(400).json({ message: 'Username must be between 3 and 50 characters.' });
    }
    if (!password || password.length < 6 || password.length > 100) {
        return res.status(400).json({ message: 'Password must be between 6 and 100 characters.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('SQLITE_CONSTRAINT: UNIQUE')) {
                    return res.status(409).json({ message: 'Username already exists.' });
                }
                console.error('Error during user signup:', err.message);
                return res.status(500).json({ message: 'Internal server error during registration.' });
            }
            res.status(201).json({ message: 'User registered successfully!', userId: this.lastID, username: username });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

// --- User Login API ---
app.post('/api/login', (req, res) => {
    const username = req.body.username ? String(req.body.username).trim() : '';
    const password = req.body.password ? String(req.body.password).trim() : '';

    if (!username) {
        return res.status(400).json({ message: 'Username cannot be empty.' });
    }
    if (!password) {
        return res.status(400).json({ message: 'Password cannot be empty.' });
    }

    db.get('SELECT id, username, password FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Error during user login database query:', err.message);
            return res.status(500).json({ message: 'Internal server error during login.' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
            res.status(200).json({ message: 'Login successful!', userId: user.id, username: user.username });
        } else {
            res.status(401).json({ message: 'Invalid username or password.' });
        }
    });
});

// --- Add Event API ---
app.post('/api/events', (req, res) => {
    const { userId } = req.body;
    const eventKey = req.body.eventKey ? String(req.body.eventKey).trim() : '';
    const description = req.body.description ? String(req.body.description).trim() : '';
    const notes = req.body.notes ? String(req.body.notes).trim() : '';
    const category = req.body.category ? String(req.body.category).trim() : 'General';
    const recurrencePattern = req.body.recurrencePattern ? String(req.body.recurrencePattern).trim() : 'none';
    const numberOfRepeats = req.body.numberOfRepeats !== undefined && req.body.numberOfRepeats !== null ? parseInt(req.body.numberOfRepeats) : null;

    if (!userId || isNaN(parseInt(userId))) {
        return res.status(400).json({ message: 'Valid userId is required.' });
    }
    if (!eventKey || eventKey.length === 0) {
        return res.status(400).json({ message: 'Event key is required.' });
    }
    if (!description || description.length < 1 || description.length > 255) {
        return res.status(400).json({ message: 'Description must be between 1 and 255 characters.' });
    }
    if (notes.length > 1000) {
        return res.status(400).json({ message: 'Notes cannot exceed 1000 characters.' });
    }
    if (recurrencePattern !== 'none' && (isNaN(numberOfRepeats) || numberOfRepeats < 1)) {
        return res.status(400).json({ message: 'Number of repeats must be a positive number if recurrence is selected.' });
    }

    const finalCategory = (category === null || category === undefined || category === '') ? 'General' : category;
    const finalRecurrencePattern = (recurrencePattern === null || recurrencePattern === undefined || recurrencePattern === '') ? 'none' : recurrencePattern;

    db.get('SELECT id FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Error checking user ID for event:', err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        db.run('INSERT INTO events (user_id, event_key, description, notes, category, recurrence_pattern, number_of_repeats) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [userId, eventKey, description, notes, finalCategory, finalRecurrencePattern, numberOfRepeats],
          function(err) {
            if (err) {
              console.error('Error adding event:', err.message);
              return res.status(500).json({ message: 'Internal server error while adding event.' });
            }
            res.status(201).json({ message: 'Event added successfully!', eventId: this.lastID });
          }
        );
    });
});


// --- Get Events API (MODIFIED to fetch exceptions and modifications) ---
app.get('/api/events', async (req, res) => {
    const userId = req.query.userId;

    if (!userId || isNaN(parseInt(userId))) {
        return res.status(400).json({ message: 'Valid userId is required as a query parameter.' });
    }

    try {
        // Fetch master events
        const masterEvents = await new Promise((resolve, reject) => {
            db.all('SELECT id, event_key, description, notes, category, recurrence_pattern, number_of_repeats FROM events WHERE user_id = ? ORDER BY event_key', [userId], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });

        // Fetch recurrence exceptions
        const exceptions = await new Promise((resolve, reject) => {
            db.all('SELECT event_id, exception_date_key FROM recurrence_exceptions WHERE user_id = ?', [userId], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });
        const exceptionMap = new Map(); // Map original_event_id -> Set of exception_date_keys
        exceptions.forEach(ex => {
            if (!exceptionMap.has(ex.event_id)) {
                exceptionMap.set(ex.event_id, new Set());
            }
            exceptionMap.get(ex.event_id).add(ex.exception_date_key);
        });

        // Fetch event modifications
        const modifications = await new Promise((resolve, reject) => {
            db.all('SELECT original_event_id, modified_date_key, description, notes, category FROM event_modifications WHERE user_id = ?', [userId], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });
        const modificationMap = new Map(); // Map original_event_id -> Map of modified_date_key -> modification_details
        modifications.forEach(mod => {
            if (!modificationMap.has(mod.original_event_id)) {
                modificationMap.set(mod.original_event_id, new Map());
            }
            modificationMap.get(mod.original_event_id).set(mod.modified_date_key, {
                description: mod.description,
                notes: mod.notes,
                category: mod.category
            });
        });

        res.status(200).json({ masterEvents, exceptions: Array.from(exceptionMap), modifications: Array.from(modificationMap) });

    } catch (error) {
        console.error('Error fetching events with exceptions/modifications:', error.message);
        res.status(500).json({ message: 'Internal server error while fetching events.' });
    }
});

// --- Update Master Event API (MODIFIED to only update master event fields) ---
app.put('/api/events/:id', (req, res) => {
    const eventId = req.params.id;
    const userId = req.body.userId;
    const description = req.body.description ? String(req.body.description).trim() : '';
    const notes = req.body.notes ? String(req.body.notes).trim() : '';
    const category = req.body.category ? String(req.body.category).trim() : 'General';
    const recurrencePattern = req.body.recurrencePattern ? String(req.body.recurrencePattern).trim() : 'none';
    const numberOfRepeats = req.body.numberOfRepeats !== undefined && req.body.numberOfRepeats !== null ? parseInt(req.body.numberOfRepeats) : null;

    if (!eventId || isNaN(parseInt(eventId))) {
        return res.status(400).json({ message: 'Valid Event ID is required.' });
    }
    if (!userId || isNaN(parseInt(userId))) {
        return res.status(400).json({ message: 'Valid userId is required.' });
    }
    if (!description || description.length < 1 || description.length > 255) {
        return res.status(400).json({ message: 'Description must be between 1 and 255 characters.' });
    }
    if (notes.length > 1000) {
        return res.status(400).json({ message: 'Notes cannot exceed 1000 characters.' });
    }
    if (recurrencePattern !== 'none' && (isNaN(numberOfRepeats) || numberOfRepeats < 1)) {
        return res.status(400).json({ message: 'Number of repeats must be a positive number if recurrence is selected.' });
    }

    const finalCategory = (category === null || category === undefined || category === '') ? 'General' : category;
    const finalRecurrencePattern = (recurrencePattern === null || recurrencePattern === undefined || recurrencePattern === '') ? 'none' : recurrencePattern;


    // Update the master event directly
    db.run('UPDATE events SET description = ?, notes = ?, category = ?, recurrence_pattern = ?, number_of_repeats = ? WHERE id = ? AND user_id = ?',
        [description, notes, finalCategory, finalRecurrencePattern, numberOfRepeats, eventId, userId],
        function(err) {
            if (err) {
                console.error('Error updating master event:', err.message);
                return res.status(500).json({ message: 'Internal server error while updating master event.' });
            }
            if (this.changes > 0) {
                res.status(200).json({ message: 'Master event updated successfully!', eventId: eventId });
            } else {
                res.status(404).json({ message: 'Master event not found or not authorized to update.' });
            }
        }
    );
});


// --- NEW: Update specific recurring event instance API (PUT) ---
app.put('/api/events/instance/:originalEventId/:eventKey', (req, res) => {
    const originalEventId = parseInt(req.params.originalEventId);
    const eventKey = req.params.eventKey; // YYYY-DDD of the instance being modified
    const userId = req.body.userId;
    const description = req.body.description ? String(req.body.description).trim() : '';
    const notes = req.body.notes ? String(req.body.notes).trim() : '';
    const category = req.body.category ? String(req.body.category).trim() : 'General';

    if (isNaN(originalEventId) || !eventKey || !userId || isNaN(parseInt(userId))) {
        return res.status(400).json({ message: 'Valid originalEventId, eventKey, and userId are required.' });
    }
    if (!description || description.length < 1 || description.length > 255) {
        return res.status(400).json({ message: 'Description must be between 1 and 255 characters.' });
    }
    if (notes.length > 1000) {
        return res.status(400).json({ message: 'Notes cannot exceed 1000 characters.' });
    }

    // First, check if the original recurring event exists and belongs to the user
    db.get('SELECT id FROM events WHERE id = ? AND user_id = ?', [originalEventId, userId], (err, masterEvent) => {
        if (err) {
            console.error('Error checking master event for instance update:', err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (!masterEvent) {
            return res.status(404).json({ message: 'Original recurring event not found or not authorized.' });
        }

        // Upsert (INSERT or UPDATE) the modification
        db.run('INSERT INTO event_modifications (original_event_id, modified_date_key, user_id, description, notes, category) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(original_event_id, modified_date_key) DO UPDATE SET description = ?, notes = ?, category = ?',
            [originalEventId, eventKey, userId, description, notes, category, description, notes, category],
            function(err) {
                if (err) {
                    console.error('Error upserting event modification:', err.message);
                    return res.status(500).json({ message: 'Internal server error while updating event instance.' });
                }
                res.status(200).json({ message: 'Event instance updated successfully!', originalEventId: originalEventId, eventKey: eventKey });
            }
        );
    });
});


// --- Delete Master Event API (MODIFIED to also delete exceptions/modifications) ---
app.delete('/api/events/:id', (req, res) => {
    const eventId = req.params.id; // This is the master event ID
    const userId = req.query.userId;

    const parsedEventId = parseInt(eventId);
    const parsedUserId = parseInt(userId);
    if (isNaN(parsedEventId) || isNaN(parsedUserId)) {
        return res.status(400).json({ message: 'Event ID and userId must be valid numbers.' });
    }

    // Start a transaction to ensure atomicity
    db.serialize(() => {
        db.run('BEGIN TRANSACTION;', (beginErr) => {
            if (beginErr) {
                console.error('Error beginning transaction for master event deletion:', beginErr.message);
                return res.status(500).json({ message: 'Internal server error during deletion.' });
            }

            // Delete from master events table
            db.run('DELETE FROM events WHERE id = ? AND user_id = ?', [parsedEventId, parsedUserId], function(err) {
                if (err) {
                    console.error('Error deleting master event:', err.message);
                    db.run('ROLLBACK;');
                    return res.status(500).json({ message: 'Internal server error while deleting master event.' });
                }
                if (this.changes === 0) {
                    db.run('ROLLBACK;');
                    return res.status(404).json({ message: 'Master event not found or not authorized to delete.' });
                }

                // CASCADE DELETE will handle recurrence_exceptions and event_modifications due to FOREIGN KEY ON DELETE CASCADE
                // So explicit deletes here are technically not needed if FKs are set up correctly,
                // but adding for clarity / fallback if FKs were misconfigured or not supported
                db.run('DELETE FROM recurrence_exceptions WHERE event_id = ? AND user_id = ?', [parsedEventId, parsedUserId], (err) => {
                    if (err) {
                        console.error('Error deleting recurrence exceptions:', err.message);
                        db.run('ROLLBACK;');
                        return res.status(500).json({ message: 'Internal server error during deletion.' });
                    }
                    db.run('DELETE FROM event_modifications WHERE original_event_id = ? AND user_id = ?', [parsedEventId, parsedUserId], (err) => {
                        if (err) {
                            console.error('Error deleting event modifications:', err.message);
                            db.run('ROLLBACK;');
                            return res.status(500).json({ message: 'Internal server error during deletion.' });
                        }
                        db.run('COMMIT;', (commitErr) => {
                            if (commitErr) {
                                console.error('Error committing transaction for master event deletion:', commitErr.message);
                                return res.status(500).json({ message: 'Internal server error during deletion.' });
                            }
                            res.status(200).json({ message: 'Master event and all its occurrences/exceptions deleted successfully!', eventId: parsedEventId });
                        });
                    });
                });
            });
        });
    });
});


// --- NEW: Delete specific recurring event instance API (DELETE) ---
app.delete('/api/events/instance/:originalEventId/:eventKey', (req, res) => {
    const originalEventId = parseInt(req.params.originalEventId);
    const eventKey = req.params.eventKey; // YYYY-DDD of the instance to be skipped
    const userId = req.query.userId;

    if (isNaN(originalEventId) || !eventKey || !userId || isNaN(parseInt(userId))) {
        return res.status(400).json({ message: 'Valid originalEventId, eventKey, and userId are required.' });
    }

    // First, check if the original recurring event exists and belongs to the user
    db.get('SELECT id FROM events WHERE id = ? AND user_id = ?', [originalEventId, userId], (err, masterEvent) => {
        if (err) {
            console.error('Error checking master event for instance deletion:', err.message);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (!masterEvent) {
            return res.status(404).json({ message: 'Original recurring event not found or not authorized.' });
        }

        // Add an exception for this specific instance
        db.run('INSERT OR IGNORE INTO recurrence_exceptions (event_id, exception_date_key, user_id) VALUES (?, ?, ?)',
            [originalEventId, eventKey, userId],
            function(err) {
                if (err) {
                    console.error('Error adding recurrence exception:', err.message);
                    return res.status(500).json({ message: 'Internal server error while deleting event instance.' });
                }
                // Also remove any existing modification for this instance (if it was previously edited)
                db.run('DELETE FROM event_modifications WHERE original_event_id = ? AND modified_date_key = ? AND user_id = ?',
                    [originalEventId, eventKey, userId],
                    (deleteErr) => {
                        if (deleteErr) {
                            console.error('Error deleting existing modification for instance:', deleteErr.message);
                            // Log but don't fail, the primary goal (adding exception) was achieved
                        }
                        res.status(200).json({ message: 'Event instance excluded from recurrence successfully!', originalEventId: originalEventId, eventKey: eventKey });
                    }
                );
            }
        );
    });
});

// --- Start the server ---
app.listen(port, () => {
    console.log(`Phase Calendar Backend listening at http://localhost:${port}`);
    console.log('API Endpoints ready:');
    console.log(`  POST /api/signup`);
    console.log(`  POST /api/login`);
    console.log(`  POST /api/events (with userId, eventKey, description, optional notes, optional category, optional recurrence_pattern, optional number_of_repeats)`);
    console.log(`  GET /api/events?userId={id}`);
    console.log(`  PUT /api/events/:id (with userId, description, notes, category, recurrence_pattern, number_of_repeats in body)`);
    console.log(`  PUT /api/events/instance/:originalEventId/:eventKey (with userId, description, notes, category in body) [NEW]`);
    console.log(`  DELETE /api/events/:id?userId={id}`);
    console.log(`  DELETE /api/events/instance/:originalEventId/:eventKey?userId={id} [NEW]`);
});

// --- Close database on process exit ---
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        }
        console.log('Database connection closed.');
        process.exit(0);
    });
});