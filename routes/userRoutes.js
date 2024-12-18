const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const router = express.Router();
const User = require('../models/User');
const Product = require('../models/Product');

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('JWT_SECRET is not defined in environment variables.');
}

// Multer Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Middleware to verify token and attach user
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Register Route
router.post('/register', upload.single('userImage'), async (req, res) => {
    const { username, name, password, address, phone } = req.body;
    const userImage = req.file ? req.file.path : null;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const newUser = new User({ username, name, password: hashedPassword, userImage, address, phone });
        await newUser.save();
        res.json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Login Route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
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

// Product Upload Route (Protected)
router.post('/product', authMiddleware, upload.single('productImage'), async (req, res) => {
    const { name, description, price } = req.body;
    const productImage = req.file ? req.file.path : null;

    try {
        const newProduct = new Product({ name, description, price, productImage, user: req.user.id });
        await newProduct.save();
        res.json({ message: 'Product uploaded successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Product Details
router.get('/product', authMiddleware, async (req, res) => {
    try {
        // Check if user ID is available
        if (!req.user || !req.user.id) {
            return res.status(400).json({ message: 'User ID not found in request' });
        }

        // Fetch products associated with the authenticated user
        const products = await Product.find({ user: req.user.id });
        
        if (!products.length) {
            return res.status(404).json({ message: 'No products found for this user' });
        }
        
        res.json(products);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: err.message });
    }
});

// Delete product by ID

router.delete('/product/:id', authMiddleware, async(req, res) =>
   {
    try{
        const products = await 
        Product.findById(req.params.id);

        if (!products){
            return
            res.status(404).json({message: 'Product not found'});
        }
        if(products.user.toString() != req.user.id){
            return
            res.status(403).json({message: 'unAthorizeuser'});
        }

        await products.remove();

        res.json({message:'Product Deleted Succesfully'});


    } catch (err) {
        res.status(500).json({error: err.message});
    }
   });



module.exports = router;
