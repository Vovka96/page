const { body, validationResult } = require('express-validator');

app.post('register', [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    index.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
            console.error('Error inserting user into database:', err);
            res.status(500).send('Internal server error');
            return;
        }
        res.status(200).send('User registered successfully');
    });
});
