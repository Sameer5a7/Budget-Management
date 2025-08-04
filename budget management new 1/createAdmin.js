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


app.put('/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id } = req.params;
    const { username, email } = req.body;

    const query = 'UPDATE users SET username = ?, email = ? WHERE id = ?';
    db.query(query, [username, email, id], (err, result) => {
        if (err) {
            console.error("Database update error:", err); // Log the error for debugging
            return res.status(500).json({ error: err.sqlMessage });
        }
        res.json({ message: 'User  updated successfully!' });
    });
});