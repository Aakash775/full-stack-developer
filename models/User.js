const mongoose = require('mongoose');
const userSchema = new 
mongoose.Schema({
    username: { type: String, required: true, unique: true},
    name: { type: String, required: true},
    password: { type: String, required:true },
    userImage: { type: String, },
    address: { type: String, },
    phone: { type: String, required:true },
})

module.exports = mongoose.model('User', userSchema);