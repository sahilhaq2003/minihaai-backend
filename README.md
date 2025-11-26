# MinihaAI Backend API

Backend server for MinihaAI - AI Text Humanizer application.

## Tech Stack

- **Node.js** + **Express**
- **MongoDB Atlas** (Cloud Database)
- **Mongoose** (ODM)
- **bcryptjs** (Password Hashing)
- **Google OAuth** (Authentication)
- **Stripe** (Payment Processing)
- **Nodemailer** (Email Service)

## Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Configure Environment Variables**
   - See `SETUP.md` for complete list
   - Required: `MONGODB_URI`, `GOOGLE_CLIENT_ID`, `STRIPE_SECRET_KEY`, `EMAIL_USER`, `EMAIL_PASSWORD`, `FRONTEND_URL`

3. **Run Server**
   ```bash
   npm start
   ```

## API Endpoints

### Authentication
- `POST /api/auth/signup` - User registration (sends verification email)
- `POST /api/auth/login` - User login
- `POST /api/auth/google` - Google OAuth
- `GET /api/auth/verify-email` - Verify email address
- `POST /api/auth/resend-verification` - Resend verification email
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### User
- `GET /api/user/:userId` - Get user by ID
- `GET /api/user/:userId/transactions` - Get billing history

### Payments (Stripe)
- `POST /api/payment/create-session` - Create Stripe checkout session
- `POST /api/payment/verify` - Verify payment after redirect
- `POST /api/payment/webhook` - Stripe webhook handler

### Health
- `GET /` - Health check
- `GET /api/health` - Database status
- `GET /api/diagnose` - Detailed diagnostics

## Deployment

Deploy to Railway, Render, or any Node.js hosting platform.

Set environment variables (see `SETUP.md` for details):
- `MONGODB_URI` - MongoDB Atlas connection string
- `GOOGLE_CLIENT_ID` - Google OAuth client ID
- `STRIPE_SECRET_KEY` - Stripe secret key
- `EMAIL_USER` - Email address for sending emails
- `EMAIL_PASSWORD` - Email password/app password
- `FRONTEND_URL` - Frontend URL for email links
- `PORT` (optional, defaults to 3001)

