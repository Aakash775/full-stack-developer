require('dotenv').config(); // Load environment variables first
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const userRoutes = require('./routes/userRoutes');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use('/uploads', express.static('uploads'));
// Verify JWT_SECRET loading
if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is not set in the environment variables.');
    process.exit(1);
}

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log(err));

// Routes
app.use('/user', userRoutes);

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
