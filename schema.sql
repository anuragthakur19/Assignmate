DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS assignments;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS confirmations;
DROP TABLE IF EXISTS ratings;
DROP TABLE IF EXISTS notes;

-- USERS
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    profile_img TEXT,
    total_posted INTEGER DEFAULT 0,
    total_completed INTEGER DEFAULT 0,
    rating REAL DEFAULT 0
);

-- ASSIGNMENTS
CREATE TABLE assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    subject TEXT NOT NULL,
    deadline TEXT NOT NULL,
    pages INTEGER NOT NULL,
    price INTEGER NOT NULL,
    status TEXT DEFAULT 'open',
    poster_id INTEGER NOT NULL,
    selected_solver_id INTEGER,
    FOREIGN KEY (poster_id) REFERENCES users(id),
    FOREIGN KEY (selected_solver_id) REFERENCES users(id)
);

-- APPLICATIONS
CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    solver_id INTEGER NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id),
    FOREIGN KEY (solver_id) REFERENCES users(id)
);

-- MESSAGES (Chat system)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
);

-- CONFIRMATIONS (Payment + Delivery)
CREATE TABLE confirmations (
    assignment_id INTEGER PRIMARY KEY,
    poster_paid INTEGER DEFAULT 0,
    solver_received INTEGER DEFAULT 0,
    solver_delivered INTEGER DEFAULT 0,
    poster_completed INTEGER DEFAULT 0,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id)
);

-- RATINGS
CREATE TABLE ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user INTEGER NOT NULL,
    to_user INTEGER NOT NULL,
    assignment_id INTEGER NOT NULL,
    score INTEGER NOT NULL,
    comment TEXT,
    FOREIGN KEY (from_user) REFERENCES users(id),
    FOREIGN KEY (to_user) REFERENCES users(id),
    FOREIGN KEY (assignment_id) REFERENCES assignments(id)
);

-- PRIVATE NOTES (only visible to poster & solver)
CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
