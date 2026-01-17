require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// EJS Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Owner Schema
const ownerSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, default: null },
  status: { type: String, enum: ['pending', 'active'], default: 'pending' },
  invitationCode: { type: String, unique: true, sparse: true },
  clinicName: { type: String, default: '' },
  clinicEmail: { type: String, default: '' },
  clinicPhone: { type: String, default: '' },
  clinicAddress: { type: String, default: '' },
  websiteUrl: { type: String, default: '' },
  settings: {
    startHour: { type: Number, default: 9 },
    endHour: { type: Number, default: 17 },
    closedDays: { type: [Number], default: [0, 6] },
    slotsPerHour: { type: Number, default: 1 },
    services: { type: [String], default: ['Consultation'] }
  },
  createdAt: { type: Date, default: Date.now }
});

const Owner = mongoose.model('Owner', ownerSchema);

// Booking Schema (reference to existing bookings)
const bookingSchema = new mongoose.Schema({
  id: Number,
  date: String,
  time: String,
  service: String,
  name: String,
  email: String,
  phone: String,
  notes: String,
  cancelToken: String,
  status: { type: String, default: 'confirmed' },
  type: { type: String, enum: ['booking', 'blocked'], default: 'booking' },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Owner' },
  clinicName: String,
  clinicEmail: String,
  clinicPhone: String,
  clinicAddress: String,
  websiteUrl: String,
  createdAt: { type: Date, default: Date.now }
});

const Booking = mongoose.model('Booking', bookingSchema);

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.owner = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login');
  }
};

// Super Admin Middleware
const authenticateSuperAdmin = (req, res, next) => {
  const token = req.cookies.superToken;
  if (!token) return res.redirect('/super-admin/login');
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'super-admin') {
      return res.redirect('/super-admin/login');
    }
    req.superAdmin = decoded;
    next();
  } catch (err) {
    res.clearCookie('superToken');
    return res.redirect('/super-admin/login');
  }
};

// Generate Invitation Code
function generateInvitationCode() {
  return crypto.randomBytes(16).toString('hex');
}

// Send Invitation Email via Brevo
async function sendInvitationEmail(email, invitationCode, clinicName) {
  if (!process.env.BREVO_API_KEY) {
    console.log('Skipping email - BREVO_API_KEY not configured');
    return false;
  }

  const inviteUrl = `${process.env.DASHBOARD_URL}/register?code=${invitationCode}`;
  
  const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #e0e5ec;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #e0e5ec; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background: #e0e5ec; border-radius: 32px; box-shadow: 20px 20px 60px #a3b1c6, -20px -20px 60px #ffffff;">
          
          <tr>
            <td style="padding: 50px 40px; text-align: center;">
              <div style="width: 90px; height: 90px; background: #e0e5ec; border-radius: 50%; margin: 0 auto 24px; box-shadow: 8px 8px 16px #a3b1c6, -8px -8px 16px #ffffff; display: inline-block;">
                <table width="90" height="90"><tr><td align="center" valign="middle" style="font-size: 40px; color: #10b981;">&#10003;</td></tr></table>
              </div>
              <h1 style="color: #1e293b; margin: 0 0 12px; font-size: 32px; font-weight: 700;">Welcome to Booking Dashboard</h1>
              <p style="color: #64748b; margin: 0; font-size: 18px;">You've been invited to manage your bookings</p>
            </td>
          </tr>
          
          <tr>
            <td style="padding: 0 40px 32px;">
              <p style="color: #1e293b; font-size: 18px; margin: 0 0 20px; line-height: 1.6;">
                Hello,<br><br>
                You have been invited to create your Booking Dashboard account${clinicName ? ` for <strong>${clinicName}</strong>` : ''}.
              </p>
              <p style="color: #64748b; font-size: 16px; margin: 0 0 32px; line-height: 1.6;">
                Click the button below to set up your account and start managing your appointments.
              </p>
            </td>
          </tr>
          
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <a href="${inviteUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 18px 48px; border-radius: 16px; font-size: 18px; font-weight: 600; box-shadow: 6px 6px 12px #a3b1c6, -6px -6px 12px #ffffff;">Create My Account</a>
            </td>
          </tr>
          
          <tr>
            <td style="padding: 0 40px 40px;">
              <div style="background: #e0e5ec; border-radius: 16px; box-shadow: inset 4px 4px 8px #a3b1c6, inset -4px -4px 8px #ffffff; padding: 20px; text-align: center;">
                <p style="color: #64748b; font-size: 14px; margin: 0 0 8px;">Or copy this link:</p>
                <p style="color: #1e293b; font-size: 14px; margin: 0; word-break: break-all;">${inviteUrl}</p>
              </div>
            </td>
          </tr>
          
          <tr>
            <td style="padding: 24px 40px; text-align: center;">
              <p style="color: #94a3b8; font-size: 14px; margin: 0;">This invitation link will expire in 7 days.</p>
            </td>
          </tr>
          
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `;

  try {
    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': process.env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: {
          name: 'Booking Dashboard',
          email: process.env.BREVO_SENDER_EMAIL
        },
        to: [{ email }],
        subject: 'You\'re Invited to Booking Dashboard',
        htmlContent: emailHtml
      })
    });

    if (response.ok) {
      console.log(`Invitation email sent to ${email}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Email sending error:', error.message);
    return false;
  }
}

// ============================================
// SUPER ADMIN ROUTES
// ============================================

// Super Admin Login Page
app.get('/super-admin/login', (req, res) => {
  res.render('super-admin-login', { error: null });
});

// Super Admin Login
app.post('/super-admin/login', (req, res) => {
  const { email, password } = req.body;
  
  if (email === process.env.SUPER_ADMIN_EMAIL && password === process.env.SUPER_ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'super-admin', email }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('superToken', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    return res.redirect('/super-admin/dashboard');
  }
  
  res.render('super-admin-login', { error: 'Invalid credentials' });
});

// Super Admin Dashboard
app.get('/super-admin/dashboard', authenticateSuperAdmin, async (req, res) => {
  try {
    const owners = await Owner.find().sort({ createdAt: -1 });
    res.render('super-admin-dashboard', { owners, success: req.query.success });
  } catch (error) {
    res.render('super-admin-dashboard', { owners: [], error: error.message });
  }
});

// Create Invitation
app.post('/super-admin/invite', authenticateSuperAdmin, async (req, res) => {
  try {
    const { email, clinicName } = req.body;
    
    // Check if owner already exists
    const existing = await Owner.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.redirect('/super-admin/dashboard?error=Email already exists');
    }
    
    // Create invitation
    const invitationCode = generateInvitationCode();
    const owner = new Owner({
      email: email.toLowerCase(),
      clinicName: clinicName || '',
      invitationCode,
      status: 'pending'
    });
    
    await owner.save();
    
    // Send invitation email
    await sendInvitationEmail(email, invitationCode, clinicName);
    
    res.redirect('/super-admin/dashboard?success=Invitation sent to ' + email);
  } catch (error) {
    console.error('Invite error:', error);
    res.redirect('/super-admin/dashboard?error=' + error.message);
  }
});

// Super Admin Logout
app.get('/super-admin/logout', (req, res) => {
  res.clearCookie('superToken');
  res.redirect('/super-admin/login');
});

// ============================================
// OWNER REGISTRATION & AUTH ROUTES
// ============================================

// Register Page (with invitation code)
app.get('/register', async (req, res) => {
  const { code } = req.query;
  
  if (!code) {
    return res.render('register', { error: 'Invalid invitation link', owner: null });
  }
  
  try {
    const owner = await Owner.findOne({ invitationCode: code, status: 'pending' });
    if (!owner) {
      return res.render('register', { error: 'Invalid or expired invitation', owner: null });
    }
    
    res.render('register', { error: null, owner, code });
  } catch (error) {
    res.render('register', { error: 'Something went wrong', owner: null });
  }
});

// Register Submit
app.post('/register', async (req, res) => {
  const { code, password, confirmPassword, clinicName, clinicPhone, clinicAddress, websiteUrl } = req.body;
  
  try {
    const owner = await Owner.findOne({ invitationCode: code, status: 'pending' });
    if (!owner) {
      return res.render('register', { error: 'Invalid invitation', owner: null });
    }
    
    if (password !== confirmPassword) {
      return res.render('register', { error: 'Passwords do not match', owner, code });
    }
    
    if (password.length < 6) {
      return res.render('register', { error: 'Password must be at least 6 characters', owner, code });
    }
    
    // Hash password and activate account
    const hashedPassword = await bcrypt.hash(password, 10);
    owner.password = hashedPassword;
    owner.status = 'active';
    owner.invitationCode = null; // Clear invitation code
    owner.clinicName = clinicName || owner.clinicName;
    owner.clinicEmail = owner.email;
    owner.clinicPhone = clinicPhone || '';
    owner.clinicAddress = clinicAddress || '';
    owner.websiteUrl = websiteUrl || '';
    
    await owner.save();
    
    // Auto-login
    const token = jwt.sign({ id: owner._id, email: owner.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    
    res.redirect('/dashboard');
  } catch (error) {
    res.render('register', { error: error.message, owner: null });
  }
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login Submit
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const owner = await Owner.findOne({ email: email.toLowerCase(), status: 'active' });
    if (!owner) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    const validPassword = await bcrypt.compare(password, owner.password);
    if (!validPassword) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ id: owner._id, email: owner.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    
    res.redirect('/dashboard');
  } catch (error) {
    res.render('login', { error: 'Something went wrong' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// ============================================
// DASHBOARD ROUTES (Protected)
// ============================================

// Dashboard Home
app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookings = await Booking.find({ 
      ownerId: owner._id,
      status: { $ne: 'cancelled' }
    }).sort({ date: -1, time: -1 });
    
    res.render('dashboard', { owner, bookings, success: req.query.success });
  } catch (error) {
    res.render('dashboard', { owner: null, bookings: [], error: error.message });
  }
});

// Add Manual Booking Page
app.get('/dashboard/add-booking', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    res.render('add-booking', { owner, error: null });
  } catch (error) {
    res.redirect('/dashboard');
  }
});

// Add Manual Booking Submit
app.post('/dashboard/add-booking', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const { date, time, name, email, phone, service, notes, type } = req.body;
    
    const booking = new Booking({
      id: Date.now(),
      date,
      time,
      name: type === 'blocked' ? 'BLOCKED' : name,
      email: type === 'blocked' ? '' : email,
      phone: type === 'blocked' ? '' : phone,
      service: type === 'blocked' ? 'Blocked Slot' : service,
      notes: notes || '',
      type: type || 'booking',
      status: 'confirmed',
      cancelToken: crypto.randomBytes(16).toString('hex'),
      ownerId: owner._id,
      clinicName: owner.clinicName,
      clinicEmail: owner.clinicEmail,
      clinicPhone: owner.clinicPhone,
      clinicAddress: owner.clinicAddress,
      websiteUrl: owner.websiteUrl
    });
    
    await booking.save();
    res.redirect('/dashboard?success=Booking added successfully');
  } catch (error) {
    const owner = await Owner.findById(req.owner.id);
    res.render('add-booking', { owner, error: error.message });
  }
});

// Cancel Booking
app.post('/dashboard/cancel-booking/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    await Booking.deleteOne({ id: parseInt(req.params.id), ownerId: owner._id });
    res.redirect('/dashboard?success=Booking cancelled');
  } catch (error) {
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Settings Page
app.get('/dashboard/settings', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    res.render('settings', { owner, success: req.query.success });
  } catch (error) {
    res.redirect('/dashboard');
  }
});

// Update Settings
app.post('/dashboard/settings', authenticateToken, async (req, res) => {
  try {
    const { clinicName, clinicPhone, clinicAddress, websiteUrl, startHour, endHour, slotsPerHour, services } = req.body;
    
    await Owner.findByIdAndUpdate(req.owner.id, {
      clinicName,
      clinicPhone,
      clinicAddress,
      websiteUrl,
      'settings.startHour': parseInt(startHour) || 9,
      'settings.endHour': parseInt(endHour) || 17,
      'settings.slotsPerHour': parseInt(slotsPerHour) || 1,
      'settings.services': services ? services.split(',').map(s => s.trim()) : ['Consultation']
    });
    
    res.redirect('/dashboard/settings?success=Settings updated');
  } catch (error) {
    const owner = await Owner.findById(req.owner.id);
    res.render('settings', { owner, error: error.message });
  }
});

// ============================================
// HOME & HEALTH CHECK
// ============================================

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start Server
app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════╗
║     📊 BOOKING DASHBOARD v1.0                  ║
╠════════════════════════════════════════════════╣
║  Port: ${PORT}                                    ║
║  Status: Running                               ║
╚════════════════════════════════════════════════╝
  `);
});
