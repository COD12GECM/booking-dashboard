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
    workingDays: { type: [Number], default: [1, 2, 3, 4, 5] },
    slotsPerHour: { type: Number, default: 1 },
    services: { type: [String], default: ['Consultation'] }
  },
  emailSettings: {
    logoUrl: { type: String, default: '' },
    primaryColor: { type: String, default: '#10b981' },
    secondaryColor: { type: String, default: '#059669' },
    backgroundColor: { type: String, default: '#ffffff' },
    textColor: { type: String, default: '#374151' },
    businessName: { type: String, default: '' },
    emailFooter: { type: String, default: '' },
    // Confirmation email
    confirmationSubject: { type: String, default: 'Booking Confirmed' },
    confirmationMessage: { type: String, default: 'Your appointment has been confirmed. Here are the details:' },
    // Cancellation email
    cancellationSubject: { type: String, default: 'Booking Cancelled' },
    cancellationMessage: { type: String, default: 'Your appointment has been cancelled.' },
    // Reminder email
    reminderSubject: { type: String, default: 'Appointment Reminder' },
    reminderMessage: { type: String, default: 'This is a reminder for your upcoming appointment.' }
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

  // Use DASHBOARD_URL or fallback to the correct Render URL
  const baseUrl = process.env.DASHBOARD_URL || 'https://booking-dashboard-eco2.onrender.com';
  const inviteUrl = `${baseUrl}/register?code=${invitationCode}`;
  
  const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #ffffff;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 16px;">
          
          <!-- Header with gradient -->
          <tr>
            <td style="background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 48px 40px; text-align: center; border-radius: 16px 16px 0 0;">
              <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">Booking Dashboard</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 12px 0 0; font-size: 16px; font-weight: 400;">Professional Appointment Management</p>
            </td>
          </tr>
          
          <!-- Main Content -->
          <tr>
            <td style="padding: 48px 40px 32px;">
              <h2 style="color: #111827; margin: 0 0 20px; font-size: 24px; font-weight: 700;">You're Invited</h2>
              <p style="color: #374151; font-size: 17px; margin: 0 0 24px; line-height: 1.7;">
                You have been invited to create your Booking Dashboard account${clinicName ? ` for <strong style="color: #10b981;">${clinicName}</strong>` : ''}.
              </p>
              <p style="color: #6b7280; font-size: 16px; margin: 0 0 32px; line-height: 1.7;">
                Set up your account to start managing appointments, view your calendar, and keep your business organized.
              </p>
            </td>
          </tr>
          
          <!-- CTA Button -->
          <tr>
            <td style="padding: 0 40px 40px; text-align: center;">
              <a href="${inviteUrl}" style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 18px 56px; border-radius: 12px; font-size: 17px; font-weight: 600; letter-spacing: 0.3px; border: none;">Create My Account</a>
            </td>
          </tr>
          
          <!-- Link Box -->
          <tr>
            <td style="padding: 0 40px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 12px;">
                <tr>
                  <td style="padding: 20px; text-align: center;">
                    <p style="color: #6b7280; font-size: 13px; margin: 0 0 10px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Or copy this link</p>
                    <p style="color: #10b981; font-size: 14px; margin: 0; word-break: break-all; font-family: monospace;">${inviteUrl}</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="padding: 32px 40px; border-top: 1px solid #e5e7eb; text-align: center;">
              <p style="color: #9ca3af; font-size: 14px; margin: 0 0 8px;">This invitation expires in 7 days.</p>
              <p style="color: #d1d5db; font-size: 13px; margin: 0;">Booking Dashboard &bull; Professional Scheduling</p>
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

// Send Booking Confirmation Email to Client (uses owner's custom email settings)
async function sendBookingConfirmationEmail(booking, owner) {
  if (!process.env.BREVO_API_KEY || !booking.email) {
    console.log('Skipping confirmation email - no API key or client email');
    return false;
  }

  // Get custom email settings or defaults
  const emailSettings = owner.emailSettings || {};
  const primaryColor = emailSettings.primaryColor || '#10b981';
  const secondaryColor = emailSettings.secondaryColor || '#059669';
  const businessName = emailSettings.businessName || owner.clinicName || 'Your Business';
  const emailFooter = emailSettings.emailFooter || '';
  const confirmationSubject = emailSettings.confirmationSubject || 'Booking Confirmed';
  const confirmationMessage = emailSettings.confirmationMessage || 'Your appointment has been confirmed. Here are the details:';

  const dateObj = new Date(booking.date + 'T' + booking.time);
  const formattedDate = dateObj.toLocaleDateString('en-US', { 
    weekday: 'long', 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  });

  const emailHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #ffffff;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background: #ffffff; border: 1px solid #e5e7eb; border-radius: 16px;">
          
          <tr>
            <td style="background: linear-gradient(135deg, ${primaryColor} 0%, ${secondaryColor} 100%); padding: 48px 40px; text-align: center; border-radius: 16px 16px 0 0;">
              <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700;">${confirmationSubject}</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 12px 0 0; font-size: 16px;">${businessName}</p>
            </td>
          </tr>
          
          <tr>
            <td style="padding: 40px;">
              <p style="color: #374151; font-size: 17px; margin: 0 0 24px; line-height: 1.7;">
                Dear <strong>${booking.name}</strong>,
              </p>
              <p style="color: #6b7280; font-size: 16px; margin: 0 0 32px; line-height: 1.7;">
                ${confirmationMessage}
              </p>
              
              <table width="100%" cellpadding="0" cellspacing="0" style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 12px; margin-bottom: 32px;">
                <tr>
                  <td style="padding: 24px;">
                    <p style="margin: 0 0 12px;"><strong style="color: #374151;">Date:</strong> <span style="color: #6b7280;">${formattedDate}</span></p>
                    <p style="margin: 0 0 12px;"><strong style="color: #374151;">Time:</strong> <span style="color: #6b7280;">${booking.time}</span></p>
                    <p style="margin: 0 0 12px;"><strong style="color: #374151;">Service:</strong> <span style="color: #6b7280;">${booking.service}</span></p>
                    ${owner.clinicAddress ? `<p style="margin: 0;"><strong style="color: #374151;">Location:</strong> <span style="color: #6b7280;">${owner.clinicAddress}</span></p>` : ''}
                  </td>
                </tr>
              </table>
              
              ${owner.clinicPhone ? `<p style="color: #6b7280; font-size: 14px; margin: 0;">Questions? Contact us at ${owner.clinicPhone}</p>` : ''}
              ${emailFooter ? `<p style="color: #9ca3af; font-size: 13px; margin: 24px 0 0; padding-top: 16px; border-top: 1px solid #e5e7eb;">${emailFooter}</p>` : ''}
            </td>
          </tr>
          
          <tr>
            <td style="padding: 24px 40px; border-top: 1px solid #e5e7eb; text-align: center;">
              <p style="color: #9ca3af; font-size: 13px; margin: 0;">${businessName}</p>
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
          name: businessName,
          email: process.env.BREVO_SENDER_EMAIL
        },
        to: [{ email: booking.email, name: booking.name }],
        subject: `${confirmationSubject} - ${formattedDate} at ${booking.time}`,
        htmlContent: emailHtml
      })
    });

    if (response.ok) {
      console.log(`Confirmation email sent to ${booking.email}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Confirmation email error:', error.message);
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

// Delete Owner
app.post('/super-admin/delete/:id', authenticateSuperAdmin, async (req, res) => {
  try {
    await Owner.findByIdAndDelete(req.params.id);
    res.redirect('/super-admin/dashboard?success=Owner deleted successfully');
  } catch (error) {
    console.error('Delete error:', error);
    res.redirect('/super-admin/dashboard?error=' + error.message);
  }
});

// Resend Invitation
app.post('/super-admin/resend/:id', authenticateSuperAdmin, async (req, res) => {
  try {
    const owner = await Owner.findById(req.params.id);
    if (!owner) {
      return res.redirect('/super-admin/dashboard?error=Owner not found');
    }
    
    // Generate new invitation code
    const newCode = generateInvitationCode();
    owner.invitationCode = newCode;
    await owner.save();
    
    // Send new invitation email
    await sendInvitationEmail(owner.email, newCode, owner.clinicName);
    
    res.redirect('/super-admin/dashboard?success=Invitation resent to ' + owner.email);
  } catch (error) {
    console.error('Resend error:', error);
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

// Dashboard Home - Fetches bookings from booking-api's collection
app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    
    // Get bookings from the shared bookingdb collection (same as booking-api)
    // Filter by clinicEmail matching owner's email - include all statuses to show cancelled ones
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    const shopifyBookings = await BookingsCollection.find({ 
      clinicEmail: owner.email
    }).sort({ date: -1, time: -1 }).toArray();
    
    // Sort all bookings by date/time descending
    const allBookings = shopifyBookings.sort((a, b) => {
      const dateA = new Date(a.date + 'T' + a.time);
      const dateB = new Date(b.date + 'T' + b.time);
      return dateB - dateA;
    });
    
    res.render('dashboard', { owner, bookings: allBookings, success: req.query.success });
  } catch (error) {
    console.error('Dashboard error:', error);
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

// Add Manual Booking Submit - Saves to bookingdb for Shopify sync
app.post('/dashboard/add-booking', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const { date, time, name, email, phone, service, notes, type } = req.body;
    
    const bookingData = {
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
      clinicName: owner.clinicName,
      clinicEmail: owner.email, // Use owner's email for filtering
      clinicPhone: owner.clinicPhone,
      clinicAddress: owner.clinicAddress,
      websiteUrl: owner.websiteUrl,
      createdAt: new Date(),
      source: 'dashboard' // Mark as created from dashboard
    };
    
    // Save to bookingdb collection (same as booking-api) for Shopify sync
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    await BookingsCollection.insertOne(bookingData);
    
    // Send confirmation email to client (if not a blocked slot)
    if (type !== 'blocked' && email) {
      await sendBookingConfirmationEmail(bookingData, owner);
    }
    
    res.redirect('/dashboard?success=Booking added successfully');
  } catch (error) {
    console.error('Add booking error:', error);
    const owner = await Owner.findById(req.owner.id);
    res.render('add-booking', { owner, error: error.message });
  }
});

// Cancel Booking - Marks as cancelled (doesn't delete) and frees slot if 6+ hours before
app.post('/dashboard/cancel-booking/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    
    // Get the booking first
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    const booking = await BookingsCollection.findOne({ id: bookingId, clinicEmail: owner.email });
    
    if (!booking) {
      return res.redirect('/dashboard?error=Booking not found');
    }
    
    // Check if cancellation is 6+ hours before appointment
    const appointmentTime = new Date(booking.date + 'T' + booking.time);
    const now = new Date();
    const hoursUntilAppointment = (appointmentTime - now) / (1000 * 60 * 60);
    
    // Mark as cancelled (slot freed if 6+ hours before)
    const updateData = {
      status: 'cancelled',
      cancelledAt: new Date(),
      cancelledBy: 'owner',
      slotFreed: hoursUntilAppointment >= 6
    };
    
    await BookingsCollection.updateOne(
      { id: bookingId, clinicEmail: owner.email },
      { $set: updateData }
    );
    
    const message = hoursUntilAppointment >= 6 
      ? 'Booking cancelled and slot freed' 
      : 'Booking cancelled (slot not freed - less than 6 hours notice)';
    
    res.redirect('/dashboard?success=' + encodeURIComponent(message));
  } catch (error) {
    console.error('Cancel booking error:', error);
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Mark booking as no-show
app.post('/dashboard/no-show/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    await BookingsCollection.updateOne(
      { id: bookingId, clinicEmail: owner.email },
      { $set: { status: 'no-show', markedAt: new Date() } }
    );
    
    res.redirect('/dashboard?success=Marked as no-show');
  } catch (error) {
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Mark booking as completed
app.post('/dashboard/complete/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    await BookingsCollection.updateOne(
      { id: bookingId, clinicEmail: owner.email },
      { $set: { status: 'completed', completedAt: new Date() } }
    );
    
    res.redirect('/dashboard?success=Marked as completed');
  } catch (error) {
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Edit Booking Page
app.get('/dashboard/edit-booking/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    const booking = await BookingsCollection.findOne({ id: bookingId, clinicEmail: owner.email });
    
    if (!booking) {
      return res.redirect('/dashboard?error=Booking not found');
    }
    
    res.render('edit-booking', { owner, booking, error: req.query.error });
  } catch (error) {
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Update Booking
app.post('/dashboard/edit-booking/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    const { name, email, phone, service, date, time, notes } = req.body;
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    await BookingsCollection.updateOne(
      { id: bookingId, clinicEmail: owner.email },
      { $set: { name, email, phone, service, date, time, notes, updatedAt: new Date() } }
    );
    
    res.redirect('/dashboard?success=Booking updated successfully');
  } catch (error) {
    res.redirect('/dashboard/edit-booking/' + req.params.id + '?error=' + error.message);
  }
});

// AI Assistant Page
app.get('/dashboard/ai-assistant', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    const allBookings = await BookingsCollection.find({ clinicEmail: owner.email }).toArray();
    
    const today = new Date().toISOString().split('T')[0];
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    
    const confirmedBookings = allBookings.filter(b => b.type === 'booking' && b.status !== 'cancelled');
    const completedBookings = allBookings.filter(b => b.status === 'completed');
    const noShowBookings = allBookings.filter(b => b.status === 'no-show');
    const todayBookings = allBookings.filter(b => b.date === today && b.status !== 'cancelled');
    const weekBookings = allBookings.filter(b => b.date >= weekAgo && b.status !== 'cancelled');
    
    // Calculate busiest day
    const dayCount = {};
    confirmedBookings.forEach(b => {
      const day = new Date(b.date + 'T00:00:00').toLocaleDateString('en-US', { weekday: 'long' });
      dayCount[day] = (dayCount[day] || 0) + 1;
    });
    const busiestDay = Object.entries(dayCount).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A';
    
    // Calculate popular service
    const serviceCount = {};
    confirmedBookings.forEach(b => {
      if (b.service) serviceCount[b.service] = (serviceCount[b.service] || 0) + 1;
    });
    const popularService = Object.entries(serviceCount).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A';
    
    const totalFinished = completedBookings.length + noShowBookings.length;
    const completionRate = totalFinished > 0 ? Math.round((completedBookings.length / totalFinished) * 100) : 100;
    const noShowRate = totalFinished > 0 ? Math.round((noShowBookings.length / totalFinished) * 100) : 0;
    
    const stats = {
      totalBookings: confirmedBookings.length,
      todayBookings: todayBookings.length,
      weekBookings: weekBookings.length,
      completionRate,
      noShowRate,
      popularService,
      busiestDay
    };
    
    res.render('ai-assistant', { owner, stats });
  } catch (error) {
    console.error('AI Assistant error:', error);
    res.redirect('/dashboard');
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
    const { 
      clinicName, clinicPhone, clinicAddress, websiteUrl, 
      startHour, endHour, slotsPerHour, services, workingDays,
      logoUrl, emailBusinessName, primaryColor, secondaryColor, backgroundColor, textColor,
      confirmationSubject, confirmationMessage, 
      cancellationSubject, cancellationMessage,
      reminderSubject, reminderMessage, emailFooter 
    } = req.body;
    
    // Parse working days (checkboxes)
    const parsedWorkingDays = workingDays ? (Array.isArray(workingDays) ? workingDays.map(Number) : [Number(workingDays)]) : [1, 2, 3, 4, 5];
    
    await Owner.findByIdAndUpdate(req.owner.id, {
      clinicName,
      clinicPhone,
      clinicAddress,
      websiteUrl,
      'settings.startHour': parseInt(startHour) || 9,
      'settings.endHour': parseInt(endHour) || 17,
      'settings.slotsPerHour': parseInt(slotsPerHour) || 1,
      'settings.services': services ? services.split(',').map(s => s.trim()) : ['Consultation'],
      'settings.workingDays': parsedWorkingDays,
      'emailSettings.logoUrl': logoUrl || '',
      'emailSettings.businessName': emailBusinessName || clinicName || '',
      'emailSettings.primaryColor': primaryColor || '#10b981',
      'emailSettings.secondaryColor': secondaryColor || '#059669',
      'emailSettings.backgroundColor': backgroundColor || '#ffffff',
      'emailSettings.textColor': textColor || '#374151',
      'emailSettings.confirmationSubject': confirmationSubject || 'Booking Confirmed',
      'emailSettings.confirmationMessage': confirmationMessage || 'Your appointment has been confirmed. Here are the details:',
      'emailSettings.cancellationSubject': cancellationSubject || 'Booking Cancelled',
      'emailSettings.cancellationMessage': cancellationMessage || 'Your appointment has been cancelled.',
      'emailSettings.reminderSubject': reminderSubject || 'Appointment Reminder',
      'emailSettings.reminderMessage': reminderMessage || 'This is a reminder for your upcoming appointment.',
      'emailSettings.emailFooter': emailFooter || ''
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

// 404 Handler
app.use((req, res) => {
  console.log(`404 - Route not found: ${req.method} ${req.url}`);
  res.status(404).send(`Route not found: ${req.url}. Available routes: /login, /register, /dashboard, /super-admin/login`);
});

// Error Handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).send('Server error: ' + err.message);
});

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════╗
║     📊 BOOKING DASHBOARD v1.0                  ║
╠════════════════════════════════════════════════╣
║  Port: ${PORT}                                    ║
║  Host: 0.0.0.0                                 ║
║  Status: Running                               ║
╚════════════════════════════════════════════════╝
  `);
  console.log('Routes registered:');
  console.log('  GET  /');
  console.log('  GET  /login');
  console.log('  POST /login');
  console.log('  GET  /register');
  console.log('  POST /register');
  console.log('  GET  /dashboard');
  console.log('  GET  /super-admin/login');
  console.log('  POST /super-admin/login');
  console.log('  GET  /super-admin/dashboard');
  console.log('  GET  /health');
});
