const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require ('cors');
const userRoutes = require('./routes/userRoutes');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

//DB Connection
mongoose.connect('mongodb://localhost:27017/userAuthDB' ,{
    useNewUrlParser:true,
    useUnifiedTopology: true
}).then(()=> console.log("MongoDB Connected"))
.catch(err=> console.log(err));

//user Routes

app.use('/user', userRoutes);
//console.log(user);
//Start Server

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));