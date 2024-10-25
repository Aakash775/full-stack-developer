const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const router = express.Router();
const User = require('../models/User');
const Product = require('../models/Product');
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
    
    // Use JWT_SECRET from environment variables
    const JWT_SECRET = process.env.JWT_SECRET;

    if (!JWT_SECRET) {
        return res.status(500).json({ message: 'JWT_SECRET is not defined' });
    }

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

// Product Api

router.post('/upload-product', upload.single('productImage'),
async (req, res) => {
    const {
        name, description, price
    } = req.body;
    const productImage = req.file ? req.file.path : null;
    try {
        const newProduct = new 
        Product({
            name,
            description,
            price,
            productImage,
            user: req.user.id
        });
        await newProduct.save();
        res.json({message : 'Product Upload Successfully'});
    }catch  (err){
            res.status(500).json({error: err.message});
        
    };
});

//Middelware to verify token and attache user
const authMiddleware = (req, res, 
    next) => {
    const token = 
    req.header('x-auth-token');
    if (!token) return
    res.status(401).json({message: 'No token, authorization denied' });
    try{
        const decode = jwt.verify(token, JWT_SECRET);
        req.user = decode;
       // user Data attached
       next();
    }catch (err){
        res.status(401).json({message: 'Token is not valid'});
    }
};

// Protect Product upload route with auth middleware

router.post('/upload-product', authMiddleware, upload.single('productImage')),
async (req, res) =>{
    const {name, description, price} = req.body;
    const productImage = req.file ? req.file.path:null;

    try {
        const newProduct = new
        Product ({
            name,
            description,
            price,
            productImage,
            user: req.user.id
        });
        await newProduct.save();
        res.json ({message: 'Product uploaded successfully'});

    }catch (err) {
        res.status(500).json({error: err.message});
    }
};

module.exports = router;
