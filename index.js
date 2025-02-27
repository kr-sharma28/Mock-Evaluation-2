//User Schema

let mongoose = require('mongoose');
let bcrypt = require('bcryptjs');

let userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobileNumber: { type: String, required: true },
  gender: { type: String, required: true },
  role: {
    type: String,
    enum: ['admin', 'customer'],
    default: 'customer',
  },
});

// Hash password before saving the user
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Compare password
userSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', userSchema);


//Ticket Schema

let mongoose = require('mongoose');

let ticketSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  dateOfTravel: { type: Date, required: true },
  modeOfTravel: { type: String, enum: ['rail', 'bus'], required: true },
  perHeadPrice: { type: Number, required: true },
  from: { type: String, required: true },
  to: { type: String, required: true },
  numberOfPassengers: { type: Number, required: true },
  totalPrice: {
    type: Number,
    required: true,
    default: function () {
      return this.perHeadPrice * this.numberOfPassengers;
    },
  },
});

module.exports = mongoose.model('Ticket', ticketSchema);


//Auth Middleware

let jwt = require('jsonwebtoken');

let authMiddleware = (roleRequired) => {
  return async (req, res, next) => {
    let token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        let decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;

      // Role-based access control
      if (roleRequired && req.user.role !== roleRequired) {
        return res.status(403).json({ message: 'Forbidden' });
      }

      next();
    } catch (error) {
      return res.status(400).json({ message: 'Invalid token.' });
    }
  };
};

module.exports = authMiddleware;

// Login Endpoint to Get JWT

let express = require('express');
let jwt = require('jsonwebtoken');
let bcrypt = require('bcryptjs');
let User = require('./models/User');

let router = express.Router();

// User login
router.post('/login', async (req, res) => {
    let { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    let isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    let token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;


//nodemailer

let nodemailer = require('nodemailer');

let sendEmail = async (to, subject, text) => {
    let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  let mailOptions = {
    from: process.env.EMAIL_USER,
    to: [to, 'venugopal.burli@masaischool.com'],
    subject: subject,
    text: text,
  };

  await transporter.sendMail(mailOptions);
};

//Middleware

let loggerMiddleware = (req, res, next) => {
    console.log(`${req.method} ${req.originalUrl} - ${new Date().toISOString()}`);
    next();
  };
  
  module.exports = loggerMiddleware;

//Test Example

let request = require('supertest');
let app = require('../app');

describe('POST /login', () => {
  it('should return a JWT token on successful login', async () => {
    let res = await request(app)
      .post('/login')
      .send({ email: 'test@example.com', password: 'password123' });
    
    expect(res.status).toBe(200);
    expect(res.body.token).toBeDefined();
  });
});

//Error Handling Middleware

let errorHandler = (err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: err.message });
  };
  
  module.exports = errorHandler;
  
  
  