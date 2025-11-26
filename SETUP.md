# MinihaAI Backend - Setup Guide

## 🎉 New Features Added

1. **Stripe Payment Gateway** - Real payment processing
2. **Email Verification** - Verify user emails before login
3. **Password Reset** - Forgot password functionality

---

## 📋 Required Environment Variables

Add these to your **Railway** environment variables:

### Database
```
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/minihaai?retryWrites=true&w=majority
```

### Google OAuth
```
GOOGLE_CLIENT_ID=your_google_client_id_here
```

### Stripe (Required for Payments)
```
STRIPE_SECRET_KEY=sk_test_... (or sk_live_... for production)
STRIPE_WEBHOOK_SECRET=whsec_... (for production webhooks)
```

### Email Service (Required for Email Verification & Password Reset)

**Option 1: Gmail SMTP**
```
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password  # Use App Password, not regular password
```

**Option 2: Other SMTP (SendGrid, Mailgun, etc.)**
```
EMAIL_SERVICE=smtp
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey
EMAIL_PASSWORD=your-api-key
```

### Frontend URL (For email links)
```
FRONTEND_URL=https://minihaai.vercel.app
```

---

## 🔧 Setup Instructions

### 1. Stripe Setup

1. Go to [stripe.com](https://stripe.com) and create an account
2. Get your **Secret Key** from Dashboard → Developers → API keys
3. Add to Railway: `STRIPE_SECRET_KEY=sk_test_...`
4. For production webhooks:
   - Go to Developers → Webhooks
   - Add endpoint: `https://your-railway-url.up.railway.app/api/payment/webhook`
   - Copy webhook secret to Railway: `STRIPE_WEBHOOK_SECRET=whsec_...`

### 2. Email Setup (Gmail)

1. Enable 2-Factor Authentication on your Gmail account
2. Go to [Google Account Settings](https://myaccount.google.com/apppasswords)
3. Generate an **App Password** for "Mail"
4. Add to Railway:
   ```
   EMAIL_SERVICE=gmail
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASSWORD=your-16-char-app-password
   ```

### 3. Frontend URL

Add to Railway:
```
FRONTEND_URL=https://minihaai.vercel.app
```

---

## 🧪 Testing

### Test Stripe (Use Test Cards)
- Card: `4242 4242 4242 4242`
- Expiry: Any future date
- CVC: Any 3 digits
- ZIP: Any 5 digits

### Test Email
- Check Railway logs for email sending status
- Emails will be sent to the user's email address

---

## 📝 API Endpoints

### Payment
- `POST /api/payment/create-session` - Create Stripe checkout session
- `POST /api/payment/verify` - Verify payment after redirect
- `POST /api/payment/webhook` - Stripe webhook handler

### Email Verification
- `GET /api/auth/verify-email?token=...&email=...` - Verify email
- `POST /api/auth/resend-verification` - Resend verification email

### Password Reset
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

---

## ⚠️ Important Notes

1. **Email Verification**: Users must verify email before login (can be disabled in code)
2. **Stripe**: Use test keys for development, live keys for production
3. **Email**: Gmail App Passwords expire - regenerate if emails stop working
4. **Webhooks**: Only needed for production automatic payment processing

---

## 🚀 Deployment Checklist

- [ ] MongoDB URI set in Railway
- [ ] Google Client ID set in Railway
- [ ] Stripe Secret Key set in Railway
- [ ] Email credentials set in Railway
- [ ] Frontend URL set in Railway
- [ ] Stripe webhook configured (production only)
- [ ] Test payment flow
- [ ] Test email verification
- [ ] Test password reset

