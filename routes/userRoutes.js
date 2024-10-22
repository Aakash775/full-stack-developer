const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const router = express.Router();
const User = require('../models/User');

// Multer Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname); // Correct Date.now()
    }
});
const upload = multer({
    storage: storage
});

// Register
router.post('/register', upload.single('userImage'), async (req, res) => {
    const { username, name, password, address, phone } = req.body;
    const userImage = req.file ? req.file.path : null;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({
            username, name, password: hashedPassword, userImage, address, phone
        });
        await newUser.save();
        res.json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Fix login route typo and error handling
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid Credentials' });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
module.exports = router;
