require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

const app = express();
const PORT = process.env.PORT || 3000;

// ===========================================
// SECURITY MIDDLEWARE - Professional Grade
// ===========================================

// 1. Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// 2. Rate Limiting - Prevent brute force attacks
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 min per IP
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts per 15 min
  message: { error: 'Too many login attempts, please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 API requests per minute
  message: { error: 'API rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);

// 3. Body Parser with size limits
app.use(express.json({ limit: '10kb' })); // Limit body size to prevent DoS
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 4. Cookie Parser
app.use(cookieParser());

// 5. NoSQL Injection Prevention
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`[SECURITY] NoSQL injection attempt blocked: ${key}`);
  }
}));

// 6. HTTP Parameter Pollution Prevention
app.use(hpp());

// 7. XSS Protection (manual sanitization function)
const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

// 8. Security logging middleware
app.use((req, res, next) => {
  const suspiciousPatterns = [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i, // SQL injection
    /<script/i, // XSS
    /\$where/i, // MongoDB injection
    /\$gt|\$lt|\$ne|\$eq/i, // MongoDB operators
    /javascript:/i, // JS injection
    /on\w+\s*=/i // Event handlers
  ];
  
  const checkValue = (value) => {
    if (typeof value === 'string') {
      return suspiciousPatterns.some(pattern => pattern.test(value));
    }
    return false;
  };
  
  const isSuspicious = Object.values(req.query).some(checkValue) ||
                       Object.values(req.body || {}).some(checkValue);
  
  if (isSuspicious) {
    console.warn(`[SECURITY ALERT] Suspicious request from ${req.ip}: ${req.method} ${req.path}`);
  }
  
  next();
});

// 9. Remove X-Powered-By header
app.disable('x-powered-by');

// 10. Static files with security
app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'ignore',
  etag: true,
  maxAge: '1d'
}));

// EJS Setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Owner Schema
// Team Member Schema (embedded in Owner)
const teamMemberSchema = new mongoose.Schema({
  name: { type: String, required: true },
  role: { type: String, default: 'Specialist' },
  email: { type: String, default: '' },
  phone: { type: String, default: '' },
  color: { type: String, default: '#10b981' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

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
  teamMembers: [teamMemberSchema],
  settings: {
    startHour: { type: Number, default: 9 },
    endHour: { type: Number, default: 17 },
    closedDays: { type: [Number], default: [0, 6] },
    workingDays: { type: [Number], default: [1, 2, 3, 4, 5] },
    slotsPerHour: { type: Number, default: 1 },
    services: { type: [String], default: ['Consultation'] },
    requireTeamMember: { type: Boolean, default: false }
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
  teamMemberId: { type: mongoose.Schema.Types.ObjectId, default: null },
  teamMemberName: { type: String, default: '' },
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

// Send Booking Confirmation Email to Client - Premium Template (identical to booking-api)
async function sendBookingConfirmationEmail(booking, owner) {
  if (!process.env.BREVO_API_KEY || !booking.email) {
    console.log('Skipping confirmation email - no API key or client email');
    return false;
  }

  // Get custom email settings or defaults
  const emailSettings = owner.emailSettings || {};
  const primaryColor = emailSettings.primaryColor || '#059669';
  const secondaryColor = emailSettings.secondaryColor || '#10b981';
  const businessName = emailSettings.businessName || owner.clinicName || 'Your Business';
  const confirmationSubject = emailSettings.confirmationSubject || 'Booking Confirmed';
  const CLINIC_ADDRESS = owner.clinicAddress || '';
  const CLINIC_EMAIL = owner.email || '';
  const CLINIC_PHONE = owner.clinicPhone || '';

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
<body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e5e5e5;">
          
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, ${primaryColor} 0%, ${secondaryColor} 100%); padding: 50px 40px; text-align: center;">
              <table width="70" height="70" align="center" style="background: rgba(255,255,255,0.2); border-radius: 50%;"><tr><td align="center" valign="middle" style="font-size: 32px; color: #ffffff; font-weight: bold;">&#10003;</td></tr></table>
              <h1 style="color: #ffffff; margin: 24px 0 8px; font-size: 32px; font-weight: 600;">Booking Confirmed</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 18px;">Your appointment has been scheduled</p>
            </td>
          </tr>
          
          <!-- Greeting -->
          <tr>
            <td style="padding: 40px 40px 24px;">
              <p style="color: #1a1a1a; font-size: 20px; margin: 0; line-height: 1.5;">
                Dear <strong>${booking.name}</strong>,
              </p>
              <p style="color: #666666; font-size: 18px; margin: 16px 0 0; line-height: 1.6;">
                Thank you for choosing ${businessName}. We look forward to seeing you.
              </p>
            </td>
          </tr>
          
          <!-- Appointment Details -->
          <tr>
            <td style="padding: 0 40px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background: #f8f9fa; border-radius: 12px; border: 1px solid #e9ecef;">
                <tr>
                  <td style="padding: 28px;">
                    <p style="color: #6c757d; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 24px; border-bottom: 2px solid #e9ecef; padding-bottom: 12px;">Appointment Details</p>
                    
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding: 16px 0; border-bottom: 1px solid #e9ecef;">
                          <p style="color: #6c757d; font-size: 14px; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 1px;">Date</p>
                          <p style="color: #1a1a1a; font-size: 20px; font-weight: 600; margin: 0;">${formattedDate}</p>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding: 16px 0; border-bottom: 1px solid #e9ecef;">
                          <p style="color: #6c757d; font-size: 14px; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 1px;">Time</p>
                          <p style="color: #1a1a1a; font-size: 20px; font-weight: 600; margin: 0;">${booking.time}</p>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding: 16px 0;${CLINIC_ADDRESS ? ' border-bottom: 1px solid #e9ecef;' : ''}">
                          <p style="color: #6c757d; font-size: 14px; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 1px;">Service</p>
                          <p style="color: #1a1a1a; font-size: 20px; font-weight: 600; margin: 0;">${booking.service}</p>
                        </td>
                      </tr>
                      ${CLINIC_ADDRESS ? `<tr>
                        <td style="padding: 16px 0;">
                          <p style="color: #6c757d; font-size: 14px; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 1px;">Location</p>
                          <p style="color: #1a1a1a; font-size: 20px; font-weight: 600; margin: 0;">${CLINIC_ADDRESS}</p>
                        </td>
                      </tr>` : ''}
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Reference Number -->
          <tr>
            <td style="padding: 0 40px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background: linear-gradient(135deg, ${primaryColor} 0%, ${secondaryColor} 100%); border-radius: 12px;">
                <tr>
                  <td style="padding: 28px; text-align: center;">
                    <p style="color: rgba(255,255,255,0.9); font-size: 14px; margin: 0 0 8px; text-transform: uppercase; letter-spacing: 2px; font-weight: 600;">Booking Reference</p>
                    <p style="color: #ffffff; font-size: 28px; font-weight: 700; margin: 0; letter-spacing: 1px;">#${booking.id}</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          
          <!-- Cancel Section -->
          ${owner.websiteUrl ? `<tr>
            <td style="padding: 0 40px 32px; text-align: center;">
              <p style="color: #666666; font-size: 16px; margin: 0 0 20px; line-height: 1.6;">Need to reschedule? Cancel up to 6 hours before your appointment.</p>
              <a href="${owner.websiteUrl}/pages/cancel-booking?token=${booking.cancelToken}&id=${booking.id}" style="display: inline-block; background: #ffffff; color: #dc2626; text-decoration: none; padding: 16px 36px; border-radius: 8px; font-size: 16px; font-weight: 600; border: 2px solid #dc2626;">Cancel Booking</a>
            </td>
          </tr>` : ''}
          
          <!-- Contact -->
          <tr>
            <td style="padding: 28px 40px; background: #f8f9fa; border-top: 1px solid #e9ecef;">
              <p style="color: #6c757d; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 16px;">Contact Us</p>
              ${CLINIC_EMAIL ? `<p style="color: #1a1a1a; font-size: 16px; margin: 0 0 8px;">
                <a href="mailto:${CLINIC_EMAIL}" style="color: #059669; text-decoration: none;">${CLINIC_EMAIL}</a>
              </p>` : ''}
              ${CLINIC_PHONE ? `<p style="color: #1a1a1a; font-size: 16px; margin: 0;">
                <a href="tel:${CLINIC_PHONE}" style="color: #059669; text-decoration: none;">${CLINIC_PHONE}</a>
              </p>` : ''}
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; text-align: center; background: #f8f9fa;">
              <p style="color: #999999; font-size: 14px; margin: 0;">${new Date().getFullYear()} ${businessName}. All rights reserved.</p>
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

// Send Cancellation Email to Client (when owner cancels from dashboard)
async function sendCancellationEmailToClient(booking, owner) {
  if (!process.env.BREVO_API_KEY || !booking.email) {
    console.log('Skipping cancellation email - no API key or client email');
    return false;
  }

  const emailSettings = owner.emailSettings || {};
  const primaryColor = emailSettings.primaryColor || '#10b981';
  const businessName = emailSettings.businessName || owner.clinicName || 'Your Business';
  const cancellationSubject = emailSettings.cancellationSubject || 'Appointment Cancelled';
  const cancellationMessage = emailSettings.cancellationMessage || 'We regret to inform you that your appointment has been cancelled.';

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
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e5e5e5;">
          <tr>
            <td style="background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%); padding: 50px 40px; text-align: center;">
              <h1 style="color: #ffffff; margin: 0; font-size: 32px; font-weight: 700;">${cancellationSubject}</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 12px 0 0; font-size: 18px;">${businessName}</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 40px;">
              <p style="color: #374151; font-size: 20px; margin: 0 0 24px;">Dear <strong>${booking.name}</strong>,</p>
              <p style="color: #6b7280; font-size: 18px; margin: 0 0 32px; line-height: 1.7;">${cancellationMessage}</p>
              <table width="100%" cellpadding="0" cellspacing="0" style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 12px; margin-bottom: 32px;">
                <tr>
                  <td style="padding: 28px;">
                    <p style="margin: 0 0 14px;"><strong style="color: #991b1b; font-size: 16px;">Date:</strong> <span style="color: #7f1d1d; font-size: 20px; font-weight: 600;">${formattedDate}</span></p>
                    <p style="margin: 0 0 14px;"><strong style="color: #991b1b; font-size: 16px;">Time:</strong> <span style="color: #7f1d1d; font-size: 20px; font-weight: 600;">${booking.time}</span></p>
                    <p style="margin: 0;"><strong style="color: #991b1b; font-size: 16px;">Service:</strong> <span style="color: #7f1d1d; font-size: 20px; font-weight: 600;">${booking.service}</span></p>
                  </td>
                </tr>
              </table>
              <p style="color: #6b7280; font-size: 18px; margin: 0 0 24px; line-height: 1.7;">We apologize for any inconvenience. Please contact us to reschedule your appointment.</p>
              ${owner.websiteUrl ? `<p style="text-align: center;"><a href="${owner.websiteUrl}" style="display: inline-block; background: linear-gradient(135deg, ${primaryColor} 0%, #059669 100%); color: #ffffff; text-decoration: none; padding: 18px 44px; border-radius: 10px; font-size: 18px; font-weight: 600;">Book New Appointment</a></p>` : ''}
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
        sender: { name: businessName, email: process.env.BREVO_SENDER_EMAIL },
        to: [{ email: booking.email, name: booking.name }],
        subject: `${cancellationSubject} - ${formattedDate}`,
        htmlContent: emailHtml
      })
    });

    if (response.ok) {
      console.log(`Cancellation email sent to ${booking.email}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Cancellation email error:', error.message);
    return false;
  }
}

// Send Reminder Email to Client
async function sendReminderEmail(booking, owner) {
  if (!process.env.BREVO_API_KEY || !booking.email) {
    console.log('Skipping reminder email - no API key or client email');
    return false;
  }

  const emailSettings = owner.emailSettings || {};
  const primaryColor = emailSettings.primaryColor || '#10b981';
  const secondaryColor = emailSettings.secondaryColor || '#059669';
  const businessName = emailSettings.businessName || owner.clinicName || 'Your Business';
  const reminderSubject = emailSettings.reminderSubject || 'Appointment Reminder';
  const reminderMessage = emailSettings.reminderMessage || 'This is a friendly reminder about your upcoming appointment.';

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
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background: #ffffff; border-radius: 16px; overflow: hidden; border: 1px solid #e5e5e5;">
          <tr>
            <td style="background: linear-gradient(135deg, ${primaryColor} 0%, ${secondaryColor} 100%); padding: 50px 40px; text-align: center;">
              <h1 style="color: #ffffff; margin: 0 0 12px; font-size: 32px; font-weight: 700;">${reminderSubject}</h1>
              <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 18px;">${businessName}</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 40px;">
              <p style="color: #374151; font-size: 20px; margin: 0 0 24px;">Dear <strong>${booking.name}</strong>,</p>
              <p style="color: #6b7280; font-size: 18px; margin: 0 0 32px; line-height: 1.7;">${reminderMessage}</p>
              <table width="100%" cellpadding="0" cellspacing="0" style="background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%); border: 1px solid #a7f3d0; border-radius: 12px; margin-bottom: 32px;">
                <tr>
                  <td style="padding: 28px;">
                    <p style="color: #047857; font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 20px; border-bottom: 2px solid #a7f3d0; padding-bottom: 12px;">Appointment Details</p>
                    <p style="margin: 0 0 14px;"><strong style="color: #047857; font-size: 16px;">Date:</strong> <span style="color: #065f46; font-size: 20px; font-weight: 600;">${formattedDate}</span></p>
                    <p style="margin: 0 0 14px;"><strong style="color: #047857; font-size: 16px;">Time:</strong> <span style="color: #065f46; font-size: 20px; font-weight: 600;">${booking.time}</span></p>
                    <p style="margin: 0 0 14px;"><strong style="color: #047857; font-size: 16px;">Service:</strong> <span style="color: #065f46; font-size: 20px; font-weight: 600;">${booking.service}</span></p>
                    ${owner.clinicAddress ? `<p style="margin: 0;"><strong style="color: #047857; font-size: 16px;">Location:</strong> <span style="color: #065f46; font-size: 18px;">${owner.clinicAddress}</span></p>` : ''}
                  </td>
                </tr>
              </table>
              <p style="color: #6b7280; font-size: 18px; margin: 0; text-align: center;">We look forward to seeing you!</p>
              ${owner.clinicPhone ? `<p style="color: #9ca3af; font-size: 16px; margin: 16px 0 0; text-align: center;">Questions? Contact us at ${owner.clinicPhone}</p>` : ''}
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
        sender: { name: businessName, email: process.env.BREVO_SENDER_EMAIL },
        to: [{ email: booking.email, name: booking.name }],
        subject: `${reminderSubject} - ${formattedDate} at ${booking.time}`,
        htmlContent: emailHtml
      })
    });

    if (response.ok) {
      console.log(`Reminder email sent to ${booking.email}`);
      return true;
    }
    return false;
  } catch (error) {
    console.error('Reminder email error:', error.message);
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

// Super Admin Login (with rate limiting)
app.post('/super-admin/login', authLimiter, (req, res) => {
  const { email, password } = req.body;
  
  // Sanitize inputs
  const sanitizedEmail = sanitizeInput(email);
  
  if (sanitizedEmail === process.env.SUPER_ADMIN_EMAIL && password === process.env.SUPER_ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'super-admin', email: sanitizedEmail }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.cookie('superToken', token, { 
      httpOnly: true, 
      secure: true,
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    return res.redirect('/super-admin/dashboard');
  }
  
  // Log failed login attempt
  console.warn(`[SECURITY] Failed super-admin login attempt from ${req.ip} for email: ${sanitizedEmail}`);
  res.render('super-admin-login', { error: 'Invalid credentials' });
});

// Super Admin Dashboard
app.get('/super-admin/dashboard', authenticateSuperAdmin, async (req, res) => {
  try {
    const owners = await Owner.find().sort({ createdAt: -1 });
    
    // Get booking stats for each owner
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    const ownerStats = await Promise.all(owners.map(async (owner) => {
      const totalBookings = await BookingsCollection.countDocuments({ clinicEmail: owner.email });
      const thisMonthStart = new Date();
      thisMonthStart.setDate(1);
      thisMonthStart.setHours(0, 0, 0, 0);
      const monthlyBookings = await BookingsCollection.countDocuments({ 
        clinicEmail: owner.email,
        createdAt: { $gte: thisMonthStart }
      });
      return {
        ...owner.toObject(),
        totalBookings,
        monthlyBookings
      };
    }));
    
    // Global stats
    const totalBookingsAll = await BookingsCollection.countDocuments();
    const activeOwners = owners.filter(o => o.status === 'active').length;
    const pendingOwners = owners.filter(o => o.status === 'pending').length;
    
    res.render('super-admin-dashboard', { 
      owners: ownerStats, 
      stats: {
        totalOwners: owners.length,
        activeOwners,
        pendingOwners,
        totalBookings: totalBookingsAll
      },
      success: req.query.success,
      error: req.query.error
    });
  } catch (error) {
    console.error('Super admin dashboard error:', error);
    res.render('super-admin-dashboard', { owners: [], stats: {}, error: error.message });
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

// Ghost Mode - View dashboard as owner
app.get('/super-admin/ghost/:id', authenticateSuperAdmin, async (req, res) => {
  try {
    const owner = await Owner.findById(req.params.id);
    if (!owner || owner.status !== 'active') {
      return res.redirect('/super-admin/dashboard?error=Owner not found or not active');
    }
    
    // Create a temporary token for ghost mode
    const ghostToken = jwt.sign(
      { id: owner._id, email: owner.email, ghost: true },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1h' }
    );
    
    res.cookie('token', ghostToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    res.redirect('/dashboard?ghost=true&owner=' + encodeURIComponent(owner.clinicName || owner.email));
  } catch (error) {
    console.error('Ghost mode error:', error);
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

// Register Submit (with security)
app.post('/register', authLimiter, async (req, res) => {
  const { code, password, confirmPassword, clinicName, clinicPhone, clinicAddress, websiteUrl } = req.body;
  
  // Input validation
  if (!code || !password || !confirmPassword) {
    return res.render('register', { error: 'All fields are required', owner: null });
  }
  
  try {
    const owner = await Owner.findOne({ invitationCode: code, status: 'pending' });
    if (!owner) {
      console.warn(`[SECURITY] Invalid registration attempt with code from ${req.ip}`);
      return res.render('register', { error: 'Invalid invitation', owner: null });
    }
    
    if (password !== confirmPassword) {
      return res.render('register', { error: 'Passwords do not match', owner, code });
    }
    
    // Strong password validation
    if (password.length < 8) {
      return res.render('register', { error: 'Password must be at least 8 characters', owner, code });
    }
    
    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
      return res.render('register', { error: 'Password must contain uppercase, lowercase, and numbers', owner, code });
    }
    
    // Hash password with higher cost factor
    const hashedPassword = await bcrypt.hash(password, 12);
    owner.password = hashedPassword;
    owner.status = 'active';
    owner.invitationCode = null;
    owner.clinicName = sanitizeInput(clinicName) || owner.clinicName;
    owner.clinicEmail = owner.email;
    owner.clinicPhone = sanitizeInput(clinicPhone) || '';
    owner.clinicAddress = sanitizeInput(clinicAddress) || '';
    owner.websiteUrl = sanitizeInput(websiteUrl) || '';
    
    await owner.save();
    
    // Auto-login with secure cookie
    const token = jwt.sign({ id: owner._id, email: owner.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { 
      httpOnly: true, 
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    console.log(`[AUTH] New owner registered: ${owner.email} from ${req.ip}`);
    res.redirect('/dashboard');
  } catch (error) {
    console.error(`[ERROR] Registration error: ${error.message}`);
    res.render('register', { error: error.message, owner: null });
  }
});

// Login Page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// Login Submit (with rate limiting and security)
app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  
  // Input validation
  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required' });
  }
  
  // Sanitize email
  const sanitizedEmail = email.toLowerCase().trim();
  
  try {
    const owner = await Owner.findOne({ email: sanitizedEmail, status: 'active' });
    if (!owner) {
      console.warn(`[SECURITY] Failed login attempt from ${req.ip} for email: ${sanitizedEmail}`);
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    const validPassword = await bcrypt.compare(password, owner.password);
    if (!validPassword) {
      console.warn(`[SECURITY] Failed login attempt from ${req.ip} for email: ${sanitizedEmail}`);
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    const token = jwt.sign({ id: owner._id, email: owner.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { 
      httpOnly: true, 
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    console.log(`[AUTH] Successful login for ${sanitizedEmail} from ${req.ip}`);
    res.redirect('/dashboard');
  } catch (error) {
    console.error(`[ERROR] Login error: ${error.message}`);
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
    
    // Get bookingdb collection
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    // Check for double-booking (slot already taken)
    const slotsPerHour = owner.settings?.slotsPerHour || 1;
    const existingBookings = await BookingsCollection.countDocuments({
      date,
      time,
      clinicEmail: owner.email,
      status: { $nin: ['cancelled', 'no-show'] }
    });
    
    if (existingBookings >= slotsPerHour) {
      return res.render('add-booking', { 
        owner, 
        error: `This time slot is already fully booked (${existingBookings}/${slotsPerHour} slots taken). Please choose another time.` 
      });
    }
    
    // Get team member info if selected
    const teamMemberId = req.body.teamMemberId || null;
    let teamMemberName = '';
    if (teamMemberId && owner.teamMembers) {
      const member = owner.teamMembers.find(m => m._id.toString() === teamMemberId);
      if (member) teamMemberName = member.name;
    }
    
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
      clinicEmail: owner.email,
      clinicPhone: owner.clinicPhone,
      clinicAddress: owner.clinicAddress,
      websiteUrl: owner.websiteUrl,
      teamMemberId: teamMemberId,
      teamMemberName: teamMemberName,
      createdAt: new Date(),
      source: 'dashboard'
    };
    
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
    
    // Send cancellation email to client
    if (booking.email) {
      await sendCancellationEmailToClient(booking, owner);
    }
    
    const message = hoursUntilAppointment >= 6 
      ? 'Booking cancelled and slot freed' 
      : 'Booking cancelled (slot not freed - less than 6 hours notice)';
    
    res.redirect('/dashboard?success=' + encodeURIComponent(message));
  } catch (error) {
    console.error('Cancel booking error:', error);
    res.redirect('/dashboard?error=' + error.message);
  }
});

// Send Reminder Email to Client
app.post('/dashboard/send-reminder/:id', authenticateToken, async (req, res) => {
  try {
    const owner = await Owner.findById(req.owner.id);
    const bookingId = parseInt(req.params.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    const booking = await BookingsCollection.findOne({ id: bookingId, clinicEmail: owner.email });
    
    if (!booking) {
      return res.redirect('/dashboard?error=Booking not found');
    }
    
    if (!booking.email) {
      return res.redirect('/dashboard?error=No email address for this booking');
    }
    
    await sendReminderEmail(booking, owner);
    
    // Mark that reminder was sent
    await BookingsCollection.updateOne(
      { id: bookingId },
      { $set: { reminderSent: true, reminderSentAt: new Date() } }
    );
    
    res.redirect('/dashboard?success=Reminder email sent to ' + booking.email);
  } catch (error) {
    console.error('Send reminder error:', error);
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
      startHour, endHour, slotsPerHour, services,
      logoUrl, emailBusinessName, primaryColor, secondaryColor, backgroundColor, textColor,
      confirmationSubject, confirmationMessage, 
      cancellationSubject, cancellationMessage,
      reminderSubject, reminderMessage, emailFooter 
    } = req.body;
    
    // Parse working days from JSON string
    let parsedWorkingDays = [1, 2, 3, 4, 5]; // default Mon-Fri
    const workingDaysData = req.body.workingDaysData;
    if (workingDaysData) {
      try {
        parsedWorkingDays = JSON.parse(workingDaysData);
        if (!Array.isArray(parsedWorkingDays)) {
          parsedWorkingDays = [1, 2, 3, 4, 5];
        }
      } catch (e) {
        console.log('[SETTINGS] Failed to parse workingDaysData:', e.message);
      }
    }
    console.log('[SETTINGS] Working days saved:', parsedWorkingDays);
    
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
// TEAM MEMBERS MANAGEMENT
// ============================================

// Add Team Member
app.post('/dashboard/team/add', authenticateToken, async (req, res) => {
  try {
    const { name, role, email, phone, color } = req.body;
    console.log('[TEAM] Adding team member:', { name, role, email, phone, color, ownerId: req.owner.id });
    
    if (!name || name.trim() === '') {
      return res.redirect('/dashboard/settings?error=Team member name is required');
    }
    
    const result = await Owner.findByIdAndUpdate(
      req.owner.id, 
      {
        $push: {
          teamMembers: {
            name: name.trim(),
            role: role || 'Specialist',
            email: email || '',
            phone: phone || '',
            color: color || '#10b981',
            isActive: true
          }
        }
      },
      { new: true }
    );
    
    console.log('[TEAM] Team members after add:', result?.teamMembers);
    res.redirect('/dashboard/settings?success=Team member added');
  } catch (error) {
    console.error('Add team member error:', error);
    res.redirect('/dashboard/settings?error=Failed to add team member');
  }
});

// Update Team Member
app.post('/dashboard/team/update/:memberId', authenticateToken, async (req, res) => {
  try {
    const { memberId } = req.params;
    const { name, role, email, phone, color, isActive } = req.body;
    
    await Owner.findOneAndUpdate(
      { _id: req.owner.id, 'teamMembers._id': memberId },
      {
        $set: {
          'teamMembers.$.name': name,
          'teamMembers.$.role': role || 'Specialist',
          'teamMembers.$.email': email || '',
          'teamMembers.$.phone': phone || '',
          'teamMembers.$.color': color || '#10b981',
          'teamMembers.$.isActive': isActive === 'true' || isActive === true
        }
      }
    );
    
    res.redirect('/dashboard/settings?success=Team member updated');
  } catch (error) {
    console.error('Update team member error:', error);
    res.redirect('/dashboard/settings?error=Failed to update team member');
  }
});

// Delete Team Member
app.post('/dashboard/team/delete/:memberId', authenticateToken, async (req, res) => {
  try {
    const { memberId } = req.params;
    
    await Owner.findByIdAndUpdate(req.owner.id, {
      $pull: { teamMembers: { _id: memberId } }
    });
    
    res.redirect('/dashboard/settings?success=Team member removed');
  } catch (error) {
    console.error('Delete team member error:', error);
    res.redirect('/dashboard/settings?error=Failed to remove team member');
  }
});

// ============================================
// QUICK DAY-OFF (Block entire day or time range)
// ============================================

app.post('/dashboard/day-off', authenticateToken, async (req, res) => {
  try {
    const { date, startTime, endTime, reason, teamMemberId } = req.body;
    const owner = await Owner.findById(req.owner.id);
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingCollection = bookingDb.collection('bookings');
    
    // Generate time slots to block
    const start = parseInt(startTime?.split(':')[0]) || owner.settings.startHour;
    const end = parseInt(endTime?.split(':')[0]) || owner.settings.endHour;
    const slotsPerHour = owner.settings.slotsPerHour || 1;
    
    const blockedSlots = [];
    for (let hour = start; hour < end; hour++) {
      for (let slot = 0; slot < slotsPerHour; slot++) {
        const minutes = Math.floor((60 / slotsPerHour) * slot);
        const time = `${hour.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
        
        blockedSlots.push({
          id: Date.now() + Math.random(),
          date: date,
          time: time,
          type: 'blocked',
          status: 'blocked',
          name: reason || 'Day Off',
          notes: reason || 'Blocked by owner',
          clinicEmail: owner.email,
          clinicName: owner.clinicName,
          teamMemberId: teamMemberId || null,
          teamMemberName: teamMemberId ? owner.teamMembers.find(m => m._id.toString() === teamMemberId)?.name : '',
          createdAt: new Date()
        });
      }
    }
    
    if (blockedSlots.length > 0) {
      await BookingCollection.insertMany(blockedSlots);
    }
    
    res.redirect('/dashboard?success=Day off scheduled');
  } catch (error) {
    console.error('Day off error:', error);
    res.redirect('/dashboard?error=Failed to schedule day off');
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

// 404 Handler (don't expose route info)
app.use((req, res) => {
  console.warn(`[SECURITY] 404 - ${req.method} ${req.url} from ${req.ip}`);
  res.status(404).render('error', { 
    title: 'Page Not Found',
    message: 'The page you are looking for does not exist.',
    code: 404
  });
});

// Error Handler (don't expose stack traces)
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${err.message} - ${req.method} ${req.url} from ${req.ip}`);
  res.status(500).render('error', {
    title: 'Server Error',
    message: 'Something went wrong. Please try again later.',
    code: 500
  });
});

// ============================================
// AUTOMATIC REMINDER SYSTEM (runs every hour)
// ============================================
async function sendAutomaticReminders() {
  try {
    console.log('[REMINDER] Checking for appointments tomorrow...');
    
    // Get tomorrow's date
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];
    
    const bookingDb = mongoose.connection.useDb('bookingdb');
    const BookingsCollection = bookingDb.collection('bookings');
    
    // Find all confirmed bookings for tomorrow that haven't received a reminder
    const bookingsForTomorrow = await BookingsCollection.find({
      date: tomorrowStr,
      status: { $nin: ['cancelled', 'no-show', 'completed'] },
      reminderSent: { $ne: true },
      email: { $exists: true, $ne: '' }
    }).toArray();
    
    console.log(`[REMINDER] Found ${bookingsForTomorrow.length} bookings for tomorrow (${tomorrowStr})`);
    
    for (const booking of bookingsForTomorrow) {
      try {
        // Get the owner for this booking
        const owner = await Owner.findOne({ email: booking.clinicEmail });
        if (!owner) {
          console.log(`[REMINDER] No owner found for ${booking.clinicEmail}`);
          continue;
        }
        
        // Send reminder email
        const sent = await sendReminderEmail(booking, owner);
        
        if (sent) {
          // Mark reminder as sent
          await BookingsCollection.updateOne(
            { id: booking.id },
            { $set: { reminderSent: true, reminderSentAt: new Date(), reminderType: 'automatic' } }
          );
          console.log(`[REMINDER] Sent automatic reminder to ${booking.email} for ${booking.date} ${booking.time}`);
        }
      } catch (err) {
        console.error(`[REMINDER] Error sending reminder for booking ${booking.id}:`, err.message);
      }
    }
    
    console.log('[REMINDER] Automatic reminder check completed');
  } catch (error) {
    console.error('[REMINDER] Error in automatic reminder system:', error.message);
  }
}

// Run reminder check every hour
setInterval(sendAutomaticReminders, 60 * 60 * 1000); // Every hour

// Health check endpoint (for monitoring and keep-alive)
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
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
║  Auto-Reminders: Active (hourly)               ║
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
  
  // Run reminder check on startup (after 30 seconds to allow DB connection)
  setTimeout(sendAutomaticReminders, 30000);
  console.log('  GET  /super-admin/dashboard');
  console.log('  GET  /health');
});
