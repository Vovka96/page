const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const db = require('./index');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // 1 minute
}));

app.use(express.static(path.join(__dirname)));

// Реєстрація
app.post('/register', [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
            console.error('Error inserting user into database:', err);
            res.status(500).send('Internal server error');
            return;
        }
        res.status(200).send('User registered successfully');
    });
});

// Логін
app.post('/login', [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            res.status(500).send('Internal server error');
            return;
        }

        if (results.length === 0) {
            res.status(401).send('Invalid username or password');
            return;
        }

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);

        if (!passwordIsValid) {
            res.status(401).send('Invalid username or password');
            return;
        }

        req.session.userId = user.id;
        res.status(200).send('Login successful');
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});