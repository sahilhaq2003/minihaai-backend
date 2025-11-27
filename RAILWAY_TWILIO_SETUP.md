# 🚂 Railway Twilio Setup Guide

## ✅ Add Twilio Credentials to Railway

### Step 1: Go to Railway Dashboard

1. Go to https://railway.app/
2. Sign in to your account
3. Select your **`minihaai-backend`** project/service

### Step 2: Add Environment Variables

1. Click on your backend service
2. Go to the **"Variables"** tab
3. Click **"+ New Variable"** for each variable below

### Step 3: Add These 3 Variables

Add each variable one by one:

#### Variable 1: `TWILIO_ACCOUNT_SID`
```
your_account_sid_here
```
**Replace with your actual Account SID from Twilio Console (starts with `AC...`)**

#### Variable 2: `TWILIO_AUTH_TOKEN`
```
your_auth_token_here
```
**Replace with your actual Auth Token from Twilio Console**

#### Variable 3: `TWILIO_VERIFY_SERVICE_SID`
```
your_verify_service_sid_here
```
**Replace with your actual Verify Service SID from Twilio Console (starts with `VA...`)**

---

## 📋 Complete Railway Variables List

After adding Twilio variables, your Railway Variables should include:

| Variable Name | Example Value | Status |
|--------------|---------------|--------|
| `MONGODB_URI` | `mongodb+srv://...` | ✅ Already set |
| `GEMINI_API_KEY` | `AIzaSy...` | ⚠️ Add if using AI |
| `TWILIO_ACCOUNT_SID` | `your_account_sid_here` | ⚠️ **ADD THIS** |
| `TWILIO_AUTH_TOKEN` | `your_auth_token_here` | ⚠️ **ADD THIS** |
| `TWILIO_VERIFY_SERVICE_SID` | `your_verify_service_sid_here` | ⚠️ **ADD THIS** |
| `EMAIL_SERVICE` | `gmail` | ⚠️ Add if using email |
| `EMAIL_USER` | `your-email@gmail.com` | ⚠️ Add if using email |
| `EMAIL_PASSWORD` | `your-app-password` | ⚠️ Add if using email |
| `FRONTEND_URL` | `https://minihaai.vercel.app` | ⚠️ Add if using email |

---

## 🔄 After Adding Variables

1. **Railway will automatically redeploy** your service
2. Wait for deployment to complete (usually 1-2 minutes)
3. Your password reset with OTP will now work! ✅

---

## 🧪 Testing

After Railway redeploys:

1. Go to your app: `https://minihaai.vercel.app`
2. Click "Forgot Password"
3. Enter email and mobile number (with country code, e.g., `+94767589002`)
4. You should receive OTP via SMS
5. Enter OTP to verify
6. Set new password

---

## ⚠️ Important Notes

1. **Never commit credentials to Git** - Always use Railway Variables
2. **Keep credentials secure** - Don't share them publicly
3. **Railway automatically restarts** - After adding variables, your service will redeploy
4. **Check deployment logs** - If something fails, check Railway logs

---

## ✅ Success Indicators

After setup, you should see in Railway logs:
```
✅ OTP sent via Twilio Verify to +94767589002 (International)
```

If you see errors, check:
- Variables are spelled correctly
- No extra spaces in variable values
- Twilio account is active
- Verify Service SID is correct

