const mongoose = require('mongoose');
//package validate email
const { isEmail } = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    // defined structure User document
    email: {
      type: String,
      required: [true, 'Please enter an email'],
      unique: true,
      lowercase: true,
      validate: [isEmail, 'Please enter a valid email']
    },
    password: {
      type: String,
      required: [true, 'Please enter a password'],
      minlength: [6, 'Minimum password length is 6 characters'],
    }
});

// https://mongoosejs.com/docs/middleware.html
// fire a function before doc saved to db
userSchema.pre('save', async function (next) {
  // 'this' refers to local instance of 'User'
  const salt = await bcrypt.genSalt();
  // hashing password
  // salt is a random string of character separate from the password (string before a password)
  // salt attach to the password before it hash
  // salt + password => hashing algorithm => random string/character
  // 'this' reference to 'User'
  this.password = await bcrypt.hash(this.password, salt);
  // if next() isn't fire, there'll be hanging and going anywhere
  next();
});

// static method to login user
userSchema.statics.login = async function(email, password) {
  // find email at db
  const user = await this.findOne({ email });
  // check: does this email exist?
  if (user) {
    // compare: does this password same?
    const auth = await bcrypt.compare(password, user.password);
    if (auth) {
      return user;
    }
    throw Error('incorrect password');
  }
  throw Error('incorrect email');
};

//model
const User = mongoose.model('user', userSchema);

module.exports = User;