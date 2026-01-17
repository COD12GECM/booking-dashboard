# 📅 Complete Booking System Documentation

## Overview

This is a **professional, full-featured booking management system** built for businesses that need to manage appointments, bookings, and client relationships. The system consists of two main components that work together seamlessly:

1. **Booking API** (for Shopify/Website integration)
2. **Owner Dashboard** (for business management)

---

## 🏗️ System Architecture

### Technology Stack

- **Backend:** Node.js + Express.js
- **Database:** MongoDB (shared database for real-time sync)
- **Authentication:** JWT (JSON Web Tokens) with secure HTTP-only cookies
- **Email Service:** Brevo API (formerly Sendinblue)
- **Hosting:** Render.com (with auto-deploy from GitHub)
- **Frontend:** EJS templates with modern neumorphism design

### Database Structure

```
MongoDB Database: bookingdb
├── owners (collection)
│   ├── email, password, status
│   ├── clinicName, clinicPhone, clinicAddress
│   ├── settings (hours, services, working days)
│   └── emailSettings (templates, colors, logo)
│
└── bookings (collection)
    ├── id, date, time, service
    ├── name, email, phone
    ├── status (confirmed, cancelled, completed, no-show)
    ├── type (booking, blocked)
    └── clinicEmail (links to owner)
```

---

## ✨ Key Features

### For Business Owners

#### 📊 Dashboard Management
- **Real-time booking overview** with day/week/month/all views
- **Smart statistics** showing active bookings, completed, blocked slots, and today's count
- **Card-based booking display** grouped by date for easy scanning
- **Quick actions:** Mark as Done, No-Show, Cancel, or Edit any booking

#### 📝 Booking Management
- **Add manual bookings** directly from dashboard
- **Edit existing bookings** - change name, email, phone, service, date, time
- **Block time slots** for personal time or maintenance
- **Status tracking:** Confirmed → Completed/No-Show/Cancelled

#### ⚙️ Comprehensive Settings
**Business Tab:**
- Business/Clinic name
- Phone number
- Website URL
- Address
- Services offered (comma-separated)

**Schedule Tab:**
- Opening and closing hours
- Slots per hour
- Working days selection (Mon-Sun checkboxes)

**Email Templates Tab:**
- Logo URL with live preview
- Primary & Secondary colors (color pickers)
- Background & Text colors
- **Confirmation email** - subject + message
- **Cancellation email** - subject + message
- **Reminder email** - subject + message
- Email footer (appears on all emails)

#### 🤖 AI Business Assistant
- **Business insights** based on your booking data
- **Quick actions:** Busiest days, reduce no-shows tips, growth strategies
- **Weekly summaries** with key metrics
- **Personalized recommendations** based on your stats

### For Clients (via Shopify/Website)

- **Easy online booking** with available time slots
- **Service selection** from owner's configured services
- **Automatic confirmation emails** with booking details
- **Cancellation capability** (with 6-hour rule for slot release)

### For Super Admins

- **Owner management** - invite, resend invitations, delete owners
- **System overview** - all registered businesses
- **Secure authentication** with separate login

---

## 🔐 Security Features

- **JWT Authentication** with HTTP-only cookies
- **Password hashing** using bcrypt
- **Invitation-based registration** - owners can only register via email invitation
- **Unique invitation codes** that expire after use
- **Session management** with secure logout

---

## 📧 Email System

### Customizable Templates

All emails use the owner's custom branding:
- Logo displayed at top
- Custom colors (gradient header)
- Personalized messages
- Business contact information
- Custom footer

### Email Types

1. **Booking Confirmation** - Sent when booking is created
2. **Cancellation Notice** - Sent when booking is cancelled
3. **Appointment Reminder** - For upcoming appointments

### Email Design

- Modern, clean design
- Mobile-responsive
- Neumorphism-inspired styling
- Clear booking details display
- Contact information included

---

## 📱 Responsive Design

The entire system is fully responsive:
- **Desktop:** Full-featured dashboard with side-by-side layouts
- **Tablet:** Adapted grid layouts
- **Mobile:** Stacked layouts, touch-friendly buttons, collapsible navigation

---

## 🔄 Shopify Integration

The booking API integrates seamlessly with Shopify stores:

1. **Shared Database:** Both Shopify widget and dashboard use the same MongoDB
2. **Real-time Sync:** Bookings appear instantly in dashboard
3. **Unified Stats:** All bookings counted regardless of source
4. **Consistent Experience:** Same services, hours, and availability

---

## 📈 Statistics & Analytics

### Dashboard Stats
- **Active Bookings:** Confirmed appointments (not cancelled)
- **Completed:** Successfully finished appointments
- **Blocked Slots:** Time blocked by owner
- **Today:** Appointments for current day

### AI Assistant Analytics
- **Total Bookings:** All-time count
- **Weekly Bookings:** Last 7 days
- **Completion Rate:** % of appointments completed vs no-show
- **No-Show Rate:** % of missed appointments
- **Busiest Day:** Day with most bookings
- **Popular Service:** Most booked service

---

## 🛠️ Technical Details

### API Endpoints

**Authentication:**
- `GET /login` - Login page
- `POST /login` - Process login
- `GET /register/:code` - Registration with invitation
- `POST /register/:code` - Process registration
- `GET /logout` - Logout

**Dashboard:**
- `GET /dashboard` - Main dashboard
- `GET /dashboard/add-booking` - Add booking form
- `POST /dashboard/add-booking` - Create booking
- `GET /dashboard/edit-booking/:id` - Edit booking form
- `POST /dashboard/edit-booking/:id` - Update booking
- `POST /dashboard/cancel-booking/:id` - Cancel booking
- `POST /dashboard/complete/:id` - Mark as completed
- `POST /dashboard/no-show/:id` - Mark as no-show

**Settings:**
- `GET /dashboard/settings` - Settings page
- `POST /dashboard/settings` - Update settings

**AI Assistant:**
- `GET /dashboard/ai-assistant` - AI chat interface

**Super Admin:**
- `GET /super-admin/login` - Admin login
- `POST /super-admin/login` - Process admin login
- `GET /super-admin/dashboard` - Admin dashboard
- `POST /super-admin/invite` - Send owner invitation
- `POST /super-admin/resend/:id` - Resend invitation
- `POST /super-admin/delete/:id` - Delete owner

### Environment Variables

```env
PORT=3000
MONGODB_URI=mongodb+srv://...
JWT_SECRET=your-secret-key
SUPER_ADMIN_EMAIL=admin@example.com
SUPER_ADMIN_PASSWORD=secure-password
BREVO_API_KEY=your-brevo-api-key
BREVO_SENDER_EMAIL=noreply@yourdomain.com
DASHBOARD_URL=https://your-dashboard.onrender.com
```

---

## 🚀 Deployment

### Render.com Setup

1. Connect GitHub repository
2. Set environment variables
3. Deploy automatically on push
4. Custom domain (optional)

### Keep-Alive

Services include health check endpoints to prevent cold starts:
- `GET /health` - Returns `{ status: 'ok', timestamp: '...' }`

---

## 💡 Benefits

### For Business Owners

1. **Save Time:** Automated booking management
2. **Reduce No-Shows:** Email reminders and easy rescheduling
3. **Professional Image:** Branded emails and modern interface
4. **Data Insights:** AI-powered analytics and recommendations
5. **Flexibility:** Customize everything - hours, services, emails
6. **Mobile Access:** Manage bookings from any device

### For Clients

1. **24/7 Booking:** Book anytime, anywhere
2. **Instant Confirmation:** Email with all details
3. **Easy Management:** View and cancel bookings
4. **Clear Information:** Service, time, location details

### For Business Growth

1. **Increased Bookings:** Easy online scheduling
2. **Better Retention:** Professional communication
3. **Reduced Admin:** Automated processes
4. **Scalability:** Handle unlimited bookings

---

## 📋 Quick Start Guide

### For New Owners

1. Receive invitation email from super admin
2. Click registration link
3. Set password and business details
4. Configure settings (hours, services, working days)
5. Customize email templates
6. Start accepting bookings!

### For Super Admins

1. Login at `/super-admin/login`
2. Enter admin credentials
3. Invite new owners via email
4. Monitor registered businesses
5. Manage owner accounts

---

## 🔮 Future Enhancements

Potential additions:
- SMS notifications
- Calendar integrations (Google, Outlook)
- Payment processing
- Multi-location support
- Staff management
- Advanced reporting
- Client portal
- Recurring appointments

---

## 📞 Support

For technical support or feature requests, contact the system administrator.

---

**Version:** 2.0  
**Last Updated:** January 2026  
**Built with:** Node.js, Express, MongoDB, EJS, Brevo API
