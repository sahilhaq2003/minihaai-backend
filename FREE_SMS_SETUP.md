# Free SMS Setup Guide for OTP Verification (WORKS GLOBALLY - All Countries)

This guide shows you how to set up **FREE** SMS services for sending OTP codes for password reset. **Both services work in ALL countries worldwide!**

## Option 1: Twilio Verify API (RECOMMENDED - Best for OTP) ⭐⭐⭐

Twilio Verify API is **specifically designed for OTP verification** and offers:
- ✅ **Automatic OTP generation** (no need to store OTPs manually)
- ✅ **Built-in security** (rate limiting, fraud protection)
- ✅ **Free trial**: $15.50 credit (~1,000 verifications)
- ✅ **Works globally** in all countries

### Setup Steps:

1. **Sign Up for Twilio**
   - Go to https://www.twilio.com/try-twilio
   - Sign up (requires phone verification, no credit card for trial)
   - You'll get $15.50 free credit

2. **Get Your Credentials**
   - Go to Twilio Console → Account → API Keys & Tokens
   - Copy your **Account SID** (starts with `AC...`)
   - Copy your **Auth Token** (secret token)

3. **Create a Verify Service**
   - Go to Twilio Console → Verify → Services → Create new Service
   - Name it: "MinihaAI Password Reset" (or any name)
   - Copy the **Service SID** (starts with `VA...`)

4. **Add Environment Variables**
   Add these to your `.env` file:
   ```env
   TWILIO_ACCOUNT_SID=your_account_sid_here
   TWILIO_AUTH_TOKEN=your_auth_token_here
   TWILIO_VERIFY_SERVICE_SID=your_verify_service_sid_here
   ```

   ⚠️ **IMPORTANT**: Replace with your actual credentials from Twilio Console!
   - Account SID starts with `AC...`
   - Auth Token is your secret token
   - Verify Service SID starts with `VA...`

5. **Install Dependencies**
   ```bash
   npm install twilio
   ```

### How Twilio Verify Works:

1. **Send OTP**: Twilio automatically generates and sends OTP
2. **Verify OTP**: Twilio verifies the code (no manual storage needed)
3. **Security**: Built-in rate limiting and fraud protection

### Cost:
- ✅ **FREE**: $15.50 trial credit (~1,000 verifications)
- 💰 After: ~$0.05 per verification (varies by country)
- 🌍 **Works in ALL countries worldwide**

---

## Option 2: Twilio Regular SMS (Alternative)

If you prefer to use regular SMS instead of Verify API:

1. **Get a Phone Number**
   - Go to Twilio Console → Phone Numbers → Buy a Number
   - Choose a number (free trial includes one free number)

2. **Add Environment Variables**
   ```env
   TWILIO_ACCOUNT_SID=your_account_sid
   TWILIO_AUTH_TOKEN=your_auth_token
   TWILIO_PHONE_NUMBER=+1234567890
   ```

### Cost:
- ✅ **FREE**: $15.50 trial credit (~1,000 SMS)
- 💰 After: ~$0.0079 per SMS (varies by country)
- 🌍 **Works in ALL countries worldwide**

---

## Option 2: AWS SNS (100 Free SMS/month - US/Canada Only) ⭐

AWS SNS offers **100 free SMS messages per month** to US/Canada numbers. **International SMS requires paid account** but works globally.

### Setup Steps:

1. **Create AWS Account** (if you don't have one)
   - Go to https://aws.amazon.com/
   - Sign up (requires credit card, but won't charge for free tier)

2. **Create IAM User for SNS**
   - Go to AWS Console → IAM → Users → Create User
   - User name: `minihaai-sns-user`
   - Enable "Programmatic access"
   - Attach policy: `AmazonSNSFullAccess` (or create custom policy with SNS permissions)
   - Save the **Access Key ID** and **Secret Access Key**

3. **Set Up SNS**
   - Go to AWS Console → SNS → Text messaging (SMS)
   - Set your default region (e.g., `us-east-1`)
   - For production, you may need to request SMS spending limits

4. **Add Environment Variables**
   Add these to your `.env` file:
   ```env
   AWS_ACCESS_KEY_ID=your_access_key_here
   AWS_SECRET_ACCESS_KEY=your_secret_key_here
   AWS_REGION=us-east-1
   ```

5. **Install Dependencies**
   ```bash
   npm install aws-sdk
   ```

### Cost:
- ✅ **FREE**: First 100 SMS/month (US/Canada only)
- 💰 International SMS: Varies by country (~$0.00645 - $0.10 per SMS)
- 🌍 **Works globally** (free tier limited to US/Canada)

---

## Option 3: smsmode (20 Free Test Credits)

1. Sign up at https://www.smsmode.com/
2. Get 20 free test credits
3. Follow their API documentation for integration

---

## How It Works

The code automatically tries:
1. **Twilio** first (if configured) - BEST for international
2. **AWS SNS** if Twilio fails or isn't configured
3. **Console log** if neither is configured (development mode)

### Mobile Number Format (REQUIRED - All Countries)

**IMPORTANT**: Users must include country code with `+` prefix:
- ✅ **Correct**: `+1234567890` (US), `+919876543210` (India), `+447911123456` (UK)
- ❌ **Wrong**: `1234567890` (missing country code)

**Examples by Country:**
- 🇺🇸 US/Canada: `+1234567890`
- 🇮🇳 India: `+919876543210`
- 🇬🇧 UK: `+447911123456`
- 🇦🇺 Australia: `+61412345678`
- 🇩🇪 Germany: `+4915123456789`
- 🇫🇷 France: `+33612345678`
- 🇯🇵 Japan: `+81901234567`
- 🇨🇳 China: `+8613812345678`

The system validates that numbers start with `+` to ensure international compatibility.

---

## Testing

1. **Development Mode** (No SMS service configured):
   - OTP will be logged to console
   - Check server logs for the OTP code

2. **With SMS Service**:
   - OTP will be sent via SMS
   - User receives OTP on their mobile number
   - OTP expires in 10 minutes

---

## Environment Variables Summary

Add to your `.env` file (choose one or both):

```env
# AWS SNS (Recommended for free tier)
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1

# OR

# Twilio (Free trial)
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=+1234567890
```

---

## Recommendation

- **For ALL Countries (International)**: Use **Twilio** ⭐
  - Works globally in all countries
  - Free trial: $15.50 credit (~1,000 SMS)
  - Easy setup and excellent documentation
  - Best international coverage

- **For US/Canada Only**: Use AWS SNS
  - 100 free SMS/month (US/Canada only)
  - Good if already using AWS infrastructure

- **For Development/Testing**: Use Twilio free trial
  - No credit card required for trial
  - Works for testing international numbers

**Both services work globally, but Twilio is recommended for international support and ease of use.**

