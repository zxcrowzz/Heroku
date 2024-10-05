if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}

const express = require("express");
const app = express();
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const flash = require("express-flash");
const session = require("express-session");
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

const PendingUser = require('./models/PendingUser');
const cookieParser = require('cookie-parser');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.set('view engine', 'ejs');

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'pantsbro4@gmail.com',
        pass: 'xyz123zyx321'
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Initialize Passport
function initialize(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            const user = await User.findOne({ email: email });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
    passport.serializeUser((user, done) => {
        console.log("Serializing user:", user);
        done(null, user.id);
    });
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            console.log("Deserializing user:", user);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
}

initialize(passport);

mongoose.connect('mongodb+srv://kingcod163:Saggytits101@cluster0.rcyom.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    serverSelectionTimeoutMS: 30000
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/home');
    }
    next();
}

app.post("/register", [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const userzz = await User.findOne({ email: req.body.email });
        if (userzz) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const token = jwt.sign({ email: req.body.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const pendingUser = new PendingUser({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            token
        });

        await pendingUser.save();

        const url = `http://localhost:3000/confirmation/${token}`;
        await transporter.sendMail({
            to: pendingUser.email,
            subject: 'Confirm Email',
            html: `Click <a href="${url}">here</a> to confirm your email.`,
        });

        res.status(201).send('User registered. Please check your email to confirm.');

    } catch (e) {
        console.log(e);
        res.status(500).send('Server error');
    }
});

app.get('/confirmation/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const pendingUser = await PendingUser.findOne({ email: decoded.email, token });

        if (!pendingUser) {
            return res.status(400).send('Invalid token or user does not exist');
        }

        const newUser = new User({
            name: pendingUser.username,
            email: pendingUser.email,
            password: pendingUser.password,
            isConfirmed: true
        });

        await newUser.save();
        await PendingUser.deleteOne({ email: pendingUser.email });

        res.send('Email confirmed. You can now log in.');

    } catch (e) {
        console.log(e);
        res.status(500).send('Server error');
    }
});

function generateVerificationCode() {
    return crypto.randomBytes(3).toString('hex');
}

app.post("/login", (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        if (err) { return next(err); }
        if (!user) { return res.redirect('/login'); }

        req.logIn(user, async (err) => {
            if (err) {
                console.error("Login error:", err);
                return next(err);
            }

            const verificationCode = generateVerificationCode();
            await transporter.sendMail({
                to: user.email,
                subject: 'Your Verification Code',
                html: `Your verification code is: ${verificationCode}`
            });

            req.session.verificationCode = verificationCode;

            return res.render('verify', { message: 'Enter the verification code sent to your email.' });
        });
    })(req, res, next);
});

app.post("/verify", (req, res, next) => {
    const { verificationCode } = req.body;

    if (req.session.verificationCode === verificationCode) {
        console.log("User before logging in:", req.user);
        req.logIn(req.user, (err) => {
            if (err) {
                console.error("Login error:", err);
                return next(err);
            }
            delete req.session.verificationCode;
            return res.redirect('/home');
        });
    } else {
        return res.render('verify', { message: 'Invalid verification code. Please try again.' });
    }
});

app.post("/redirect", async (req, res) => {
    res.redirect("/register");
});

app.post("/redirect1", async (req, res) => {
    res.redirect("/login");
});

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs");
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render("login.ejs");
});

app.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        res.redirect('/home');
    } else {
        res.redirect('/login');
    }
});

app.get('/home', checkAuthenticated, (req, res) => {
    res.render("index.ejs");
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
