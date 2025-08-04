-- Create database
CREATE DATABASE IF NOT EXISTS expense_tracker;
USE expense_tracker;

--  Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    gender ENUM('male', 'female', 'other') NOT NULL,
    dob DATE NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    totalExpenses DECIMAL(10, 2) DEFAULT 0,  -- Added totalExpenses column
    totalIncome DECIMAL(10, 2) DEFAULT 0      -- Added totalIncome column
);
ALTER TABLE users ADD COLUMN reset_token VARCHAR(64);

--  Expenses Table
CREATE TABLE IF NOT EXISTS expenses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    date DATE NOT NULL,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--  Income Table
CREATE TABLE IF NOT EXISTS income (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    source VARCHAR(100) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    date DATE NOT NULL,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--  Budgets Table
CREATE TABLE IF NOT EXISTS budgets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,  -- Each user can have only one budget entry
    budget DECIMAL(10, 2) NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

--  Insert an Admin User (Change password after first login)
INSERT INTO users (username, email, password, gender, dob, role) 
VALUES ('Admin', 'admin@example.com', '$2b$10$hashedpasswordhere', 'male', '1990-01-01', 'admin');

--  Set Default Budget for All Users
INSERT INTO budgets (user_id, budget)
SELECT id, 0 FROM users WHERE id NOT IN (SELECT user_id FROM budgets);

SET time_zone = '+00:00'; -- Set MySQL to UTC
UPDATE users
SET reset_token_expires = UTC_TIMESTAMP() + INTERVAL 1 HOUR
WHERE reset_token = 'your_token_here';

const updateQuery = "UPDATE users SET password = ? WHERE id = ?";
await db.query(updateQuery, [hashedPassword, userId]);
