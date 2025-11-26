# MinihaAI Backend API

Backend server for MinihaAI - AI Text Humanizer application.

## Tech Stack

- **Node.js** + **Express**
- **MongoDB Atlas** (Cloud Database)
- **Mongoose** (ODM)
- **bcryptjs** (Password Hashing)
- **Google OAuth** (Authentication)

## Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Configure Environment Variables**
   - Copy `.env.example` to `.env`
   - Add your MongoDB Atlas connection string
   - Add your Google OAuth Client ID

3. **Run Server**
   ```bash
   npm start
   ```

## API Endpoints

- `GET /` - Health check
- `GET /api/health` - Database status
- `POST /api/auth/signup` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/google` - Google OAuth
- `GET /api/user/:userId` - Get user by ID
- `GET /api/user/:userId/transactions` - Get billing history
- `POST /api/payment/create` - Process payment

## Deployment

Deploy to Railway, Render, or any Node.js hosting platform.

Set environment variables:
- `MONGODB_URI`
- `GOOGLE_CLIENT_ID`
- `PORT` (optional, defaults to 3001)

