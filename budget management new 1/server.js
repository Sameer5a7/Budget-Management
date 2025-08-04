// Import required modules
const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cors = require('cors');
const MySQLStore = require('express-mysql-session')(session);
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = 4000;

app.use(express.json()); // Enable JSON parsing

// Set Content Security Policy
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "connect-src 'self' http://localhost:4000 http://localhost:5500");
    next();
});

// Enable CORS with credentials
app.use(cors({
    origin: ['http://localhost:5500', 'http://localhost:4000'], // Add all necessary frontend URLs
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

// Database connection (Using connection pool)
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'expense_tracker'
});

function getTokenExpiration() {
    const expirationTime = 60 * 60 * 12000; // 1 hour in milliseconds
    return new Date(Date.now() + expirationTime); // Current time + expiration time
}

function generateResetToken() {
    return crypto.randomBytes(32).toString('hex'); // Generates a secure random token
}

// Configure MySQL session store
const sessionStore = new MySQLStore({
    expiration: 86400000,
    createDatabaseTable: true
}, db);



// Configure session middleware
app.use(session({
    secret: 'your-secret-key', // Use a strong secret
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        maxAge: 86400000,  // 1-day session
        httpOnly: true,
        secure: false, // Change to `true` in production (HTTPS required)
        sameSite: 'Lax'
    }
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// User Registration
app.post('/register', async (req, res) => {
    const { username, email, password, gender, dob } = req.body;

    // Validate input fields
    if (!username || !email || !password || !gender || !dob) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 5);
        
        // SQL query to insert user data
        const query = 'INSERT INTO users (username, email, password, gender, dob, role, budget, totalExpenses, totalIncome) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
        
        // Execute the query
        db.query(query, [username, email, hashedPassword, gender, dob, 'user', 0, 0, 0], (err) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.json({ message: 'User  registered successfully!' });
        });
    } catch (error) {
        res.status(500).json({ error: "Server error during registration." });
    }
});

// User Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    const query = 'SELECT * FROM users WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Database error. Try again later." });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid email or password." });
        }

        const match = await bcrypt.compare(password, results[0].password);
        if (!match) {
            return res.status(401).json({ error: "Invalid email or password." });
        }


        // Set session user data here
        req.session.user = {
            id: results[0].id,
            username: results[0].username,
            role: results[0].role,
            budget: results[0].budget,
            totalExpenses: results[0].totalExpenses,
            totalIncome: results[0].totalIncome
        };

        req.session.save(err => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).json({ error: "Session error. Try again." });
            }
            res.json({ message: "Login successful!", user: req.session.user });
        });
    });
});
// User-admin Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    const query = 'SELECT * FROM users WHERE email = ?';

    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Database error. Try again later." });
        }

        if (results.length === 0) {
            // Check for admin credentials
            if (email === "admin@gmail.com" && password === "admin123") {
                req.session.user = { username: "Admin", role: "admin" };
                return res.json({ message: "Login successful", user: req.session.user });
            }
            return res.status(401).json({ error: "Invalid email or password." });
        }

        const match = await bcrypt.compare(password, results[0].password);
        if (!match) {
            return res.status(401).json({ error: "Invalid email or password." });
        }

        req.session.user = {
            id: results[0].id,
            username: results[0].username,
            role: results[0].role,
            budget: results[0].budget,
            totalExpenses: results[0].totalExpenses,
            totalIncome: results[0].totalIncome
        };

        req.session.save(err => {
            if (err) {
                console.error("Session save error:", err);
                return res.status(500).json({ error: "Session error. Try again." });
            }
            res.json({ message: "Login successful!", user: req.session.user });
        });
    });
});

// Fetch user expenses
app.get('/expenses', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const query = 'SELECT * FROM expenses WHERE user_id = ?';
    db.query(query, [req.session.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        res.json(results);
    });
});

// Add Expense
app.post('/expenses', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const { name, amount, date, notes } = req.body;
    if (!name || !amount || !date) return res.status(400).json({ error: 'All fields are required.' });

    const query = 'INSERT INTO expenses (user_id, name, amount, date, notes) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [req.session.user.id, name, amount, date, notes], (err) => {
        if (err) {
            console.error("Error adding expense:", err);
            return res.status(500).json({ error: err.sqlMessage || "Failed to add expense." });
        }

        const updateQuery = 'UPDATE users SET totalExpenses = totalExpenses + ? WHERE id = ?';
        db.query(updateQuery, [amount, req.session.user.id], (err) => {
            if (err) {
                console.error("Error updating total expenses:", err);
                return res.status(500).json({ error: err.sqlMessage });
            }
            res.json({ message: 'Expense added successfully!' });
        });
    });
});

// Delete Expense
app.delete('/expenses/:id', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const expenseId = req.params.id;

    // First, fetch the expense to get the amount
    const fetchQuery = 'SELECT amount FROM expenses WHERE id = ? AND user_id = ?';
    db.query(fetchQuery, [expenseId, req.session.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        if (results.length === 0) return res.status(404).json({ error: 'Expense not found.' });

        const amount = results[0].amount;

        // Now delete the expense
        const deleteQuery = 'DELETE FROM expenses WHERE id = ? AND user_id = ?';
        db.query(deleteQuery, [expenseId, req.session.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });

            // Update total expenses in the users table
            const updateQuery = 'UPDATE users SET totalExpenses = totalExpenses - ? WHERE id = ?';
            db.query(updateQuery, [amount, req.session.user.id], (err) => {
                if (err) return res.status(500).json({ error: err.sqlMessage });
                res.json({ message: 'Expense deleted successfully!' });
            });
        });
    });
});

// Fetch user income
app.get('/income', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const query = 'SELECT * FROM income WHERE user_id = ?';
    db.query(query, [req.session.user.id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.sqlMessage });
        }
        res.json(results);
    });
});

// Add Income
app.post('/income', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const { source, amount, date, notes } = req.body;
    if (!source || !amount || !date) return res.status(400).json({ error: 'All fields are required.' });

    const query = 'INSERT INTO income (user_id, source, amount, date, notes) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [req.session.user.id, source, amount, date, notes], (err) => {
        if (err) {
            console.error("Error adding income:", err);
            return res.status(500).json({ error: err.sqlMessage || "Failed to add income." });
        }

        const updateQuery = 'UPDATE users SET totalIncome = totalIncome + ? WHERE id = ?';
        db.query(updateQuery, [amount, req.session.user.id], (err) => {
            if (err) {
                console.error("Error updating total income:", err);
                return res.status(500).json({ error: err.sqlMessage });
            }
            res.json({ message: 'Income added successfully!' });
        });
    });
});

// Reset Expenses
app.post('/reset-expenses', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const query = 'DELETE FROM expenses WHERE user_id = ?';
    db.query(query, [req.session.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        // Reset total expenses in the user table
        const updateQuery = 'UPDATE users SET totalExpenses = 0 WHERE id = ?';
        db.query(updateQuery, [req.session.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.json({ message: 'All expenses reset successfully!' });
        });
    });
});

// Reset Income
app.post('/reset-income', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const query = 'DELETE FROM income WHERE user_id = ?';
    db.query(query, [req.session.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        // Reset total income in the user table
        const updateQuery = 'UPDATE users SET totalIncome = 0 WHERE id = ?';
        db.query(updateQuery, [req.session.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            res.json({ message: 'All income reset successfully!' });
        });
    });
});

// Reset Budget
app.post('/reset-budget', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const query = 'UPDATE users SET budget = 0 WHERE id = ?';
    db.query(query, [req.session.user.id], (err) => {
        if (err) {
            console.error(err); // Log the error for debugging
            return res.status(500).json({ error: 'Database error occurred' });
        }
        res.json({ message: 'Budget reset successfully!' });
    });
});

// Fetch Budget
app.get('/budget', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const query = `SELECT budget, COALESCE(totalExpenses, 0) AS totalExpenses, COALESCE(totalIncome, 0) AS totalIncome FROM users WHERE id = ?`;

    db.query(query, [req.session.user.id], (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });

        if (results.length > 0) {
            res.json(results[0]);  // Send budget data to frontend
        } else {
            res.status(404).json({ error: 'Budget data not found.' });
        }
    });
});

// Update Budget
app.post('/set-budget', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const { budget } = req.body;
    if (!budget || isNaN(budget) || budget < 0) {
        return res.status(400).json({ error: 'Invalid budget amount.' });
    }

    const query = 'UPDATE users SET budget = ? WHERE id = ?';
    db.query(query, [budget, req.session.user.id], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: err.sqlMessage });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "User  not found or budget not updated." });
        }

        res.json({ message: 'Budget updated successfully!', budget });
    });
});


// Edit user details
app.put('/users/:id', (req, res) => {
    // Check if user is authorized
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id } = req.params;
    const { username, email } = req.body;

    // Log the incoming data to verify it
    console.log("Received Data - Username:", username);
    console.log("Received Data - Email:", email);

    // Check if both username and email are provided
    if (!username || !email) {
        return res.status(400).json({ error: "Username and email are required." });
    }

    // SQL query to update user details
    const query = 'UPDATE users SET username = ?, email = ? WHERE id = ?';
    db.query(query, [username, email, id], (err, result) => {
        if (err) {
            // Log the error for debugging purposes
            console.error("Database Error:", err.sqlMessage);
            return res.status(500).json({ error: err.sqlMessage });
        }

        // If the update was successful, send a success message
        res.json({ message: 'User updated successfully!' });
    });
});

// Delete user
app.delete('/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id } = req.params;
    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [id], (err) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        res.json({ message: 'User  deleted successfully!' });
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: "Logout failed." });
        res.json({ message: 'Logged out successfully' });
    });
});

// Check session status
app.get('/session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.status(401).json({ error: 'Session expired. Please log in again.' });
    }
});
//-------------

const fs = require('fs');
app.get('/download-report', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const doc = new PDFDocument({ margin: 50 });
    let filename = `Expense_Report_${req.session.user.username}.pdf`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/pdf');

    doc.pipe(res);

    // Title
    doc.font('Helvetica-Bold').fontSize(26).text('Expense Tracker Report', { align: 'center' });
    doc.moveDown(2);

    // User Details
    doc.font('Helvetica').fontSize(14)
       .text(`User: ${req.session.user.username}`, { align: 'left' });
    doc.moveDown(2);

    // Expenses Table
    doc.font('Helvetica-Bold').fontSize(18).text('Expenses', { underline: true });
    doc.moveDown();

    // Table Header
    doc.fontSize(12).fillColor('#000000')
       .text('Name', 50, doc.y, { width: 150, continued: true })
       .text('Amount', 200, doc.y, { width: 100, continued: true })
       .text('Date', 300, doc.y, { width: 100, continued: true })
       .text('Notes', 400, doc.y);
    doc.moveDown();
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.moveDown();

    const userId = req.session.user.id;
    db.query('SELECT * FROM expenses WHERE user_id = ?', [userId], (err, expenses) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ error: "Database error. Try again later." });
        }

        expenses.forEach(expense => {
            doc.text(expense.name, 50, doc.y, { width: 150, continued: true })
               .text(`₹${expense.amount.toFixed(2)}`, 200, doc.y, { width: 100, continued: true })
               .text(new Date(expense.date).toLocaleDateString(), 300, doc.y, { width: 100, continued: true })
               .text(expense.notes || '', 400, doc.y);
            doc.moveDown();
        });

        doc.moveDown(2);

        // Income Table
        doc.font('Helvetica-Bold').fontSize(18).text('Income', { underline: true });
        doc.moveDown();

        doc.fontSize(12).fillColor('#000000')
           .text('Source', 50, doc.y, { width: 150, continued: true })
           .text('Amount', 200, doc.y, { width: 100, continued: true })
           .text('Date', 300, doc.y, { width: 100, continued: true })
           .text('Notes', 400, doc.y);
        doc.moveDown();
        doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
        doc.moveDown();

        db.query('SELECT * FROM income WHERE user_id = ?', [userId], (err, income) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ error: "Database error. Try again later." });
            }

            income.forEach(incomeItem => {
                doc.text(incomeItem.source, 50, doc.y, { width: 150, continued: true })
                   .text(`₹${incomeItem.amount.toFixed(2)}`, 200, doc.y, { width: 100, continued: true })
                   .text(new Date(incomeItem.date).toLocaleDateString(), 300, doc.y, { width: 100, continued: true })
                   .text(incomeItem.notes || '', 400, doc.y);
                doc.moveDown();
            });

            doc.end();
        });
    });
});
//-------------
app.get('/users', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const query = "SELECT id, username, email FROM users";
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
    });
});

            
// Start Server
app.listen(port, () => {
    console.log(`🚀 Server running on http://localhost:${port}`);
});

// Import required modules for sending emails

// Configure nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use your email service
    auth: {
        user: 'sameerpasha8328@gmail.com', // Your email
        pass: 'dagk equz ioao zbrx' // Your email password
    }
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) return res.status(500).json({ error: err.sqlMessage });
        if (results.length === 0) return res.status(404).json({ error: 'User not found.' });

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');

        // Store token and expiration
        const updateQuery = `
            UPDATE users 
            SET reset_token = ?, reset_token_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) 
            WHERE email = ?`;

        db.query(updateQuery, [resetToken, email], (err, results) => {
            if (err) return res.status(500).json({ error: err.sqlMessage });
            console.log("Token updated:", results);

            const resetLink = `http://localhost:5500/reset-password.html?token=${resetToken}`;
            const mailOptions = {
                from: 'sameerpasha8328@gmail.com',
                to: email,
                subject: 'Password Reset',
                text: `Click the link to reset your password: ${resetLink}`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) return res.status(500).json({ error: 'Error sending email.' });
                res.json({ message: 'Reset link sent to your email.' });
            });
        });
    });
});

app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
        return res.status(400).json({ error: 'Token and new password are required.' });
    }

    const query = 'SELECT id FROM users WHERE reset_token = ? AND reset_token_expires > UTC_TIMESTAMP()';
    db.query(query, [token], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Database error: ' + err.sqlMessage });
        }
        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid or expired token.' });
        }

        const userId = results[0].id;
        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            const updateQuery = 'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?';
            db.query(updateQuery, [hashedPassword, userId], (updateErr) => {
                if (updateErr) {
                    return res.status(500).json({ error: 'Database error: ' + updateErr.sqlMessage });
                }
                res.json({ message: 'Password has been reset successfully.' });
            });
        } catch (hashError) {
            return res.status(500).json({ error: 'Error hashing password: ' + hashError.message });
        }
    });
});

