const express = require('express');
const dns = require('dns');
dns.setDefaultResultOrder('ipv4first');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

dotenv.config();

const app = express();


app.use(cors());
app.use(express.json());

const getLocationLink = (location = {}) => {
  const lat = location.lat || location.latitude;
  const lng = location.lng || location.longitude;

  if (!lat || !lng) {
    return 'Location unavailable';
  }

  return `https://maps.google.com/?q=${lat},${lng}`;
};

const normalizePhoneNumber = (phone = '') => {
  const cleaned = String(phone).replace(/[^\d+]/g, '');

  if (cleaned.startsWith('+')) {
    return cleaned;
  }

  if (/^\d{10}$/.test(cleaned)) {
    return `+91${cleaned}`;
  }

  return cleaned;
};

const isConfigured = (...values) => values.every((value) => value && !String(value).startsWith('your_'));

let cachedFirebaseAccessToken = null;
let firebaseAccessTokenExpiresAt = 0;

const buildFormattedDateTime = () => {
  return new Date().toLocaleString('en-US', {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
};

const buildSOSMessage = ({ userId, reason, message, location }) => {
  const locationLink = getLocationLink(location);
  const timestamp = buildFormattedDateTime();
  const header = '🚨 EMERGENCY ALERT 🚨';
  const bodyLines = [
    header,
    '',
    'I need assistance.',
    '',
    '📍 My Live Location:',
    locationLink,
    '',
    '🕒 Time:',
    timestamp,
    '',
    'Please contact me immediately.',
  ];

  if (message) {
    bodyLines.push('', `Additional details: ${message}`);
  }

  if (reason && reason !== 'Manual SOS Button Pressed' && !message) {
    bodyLines.push('', `Reason: ${reason}`);
  }

  return bodyLines.join('\n');
};

const sendTwilioSMS = async ({ to, body }) => {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER } = process.env;

  if (!isConfigured(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER)) {
    return { provider: 'twilio', status: 'skipped', reason: 'Twilio credentials missing' };
  }

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        From: TWILIO_PHONE_NUMBER,
        To: to,
        Body: body,
      }),
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || 'Twilio SMS failed');
  }

  return { provider: 'twilio', status: 'sent', messageId: data.sid };
};

const sendMSG91SMS = async ({ to, body }) => {
  const { MSG91_AUTH_KEY, MSG91_TEMPLATE_ID, MSG91_SENDER_ID = 'SOSALT' } = process.env;

  if (!isConfigured(MSG91_AUTH_KEY, MSG91_TEMPLATE_ID)) {
    return { provider: 'msg91', status: 'skipped', reason: 'MSG91 credentials missing' };
  }

  const mobile = normalizePhoneNumber(to).replace(/^\+/, '');
  const response = await fetch('https://control.msg91.com/api/v5/sms', {
    method: 'POST',
    headers: {
      authkey: MSG91_AUTH_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      template_id: MSG91_TEMPLATE_ID,
      sender: MSG91_SENDER_ID,
      short_url: '0',
      mobiles: mobile,
      VAR1: body,
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.type === 'error') {
    throw new Error(data.message || 'MSG91 SMS failed');
  }

  return { provider: 'msg91', status: 'sent', messageId: data.request_id };
};

const sendTwilioWhatsApp = async ({ to, body }) => {
  const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER } = process.env;

  if (!isConfigured(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_NUMBER)) {
    return {
      provider: 'twilio-whatsapp',
      status: 'skipped',
      reason: 'Twilio WhatsApp credentials missing',
    };
  }

  const response = await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        From: `whatsapp:${TWILIO_WHATSAPP_NUMBER}`,
        To: `whatsapp:${to}`,
        Body: body,
      }),
    }
  );

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || 'Twilio WhatsApp failed');
  }

  return { provider: 'twilio-whatsapp', status: 'sent', messageId: data.sid };
};

const getFirebaseAccessToken = async () => {
  if (cachedFirebaseAccessToken && Date.now() < firebaseAccessTokenExpiresAt - 60000) {
    return cachedFirebaseAccessToken;
  }

  const { FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY } = process.env;

  if (!isConfigured(FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY)) {
    throw new Error('Firebase service account credentials missing');
  }

  const now = Math.floor(Date.now() / 1000);
  const encodedHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify({
    iss: FIREBASE_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })).toString('base64url');
  const unsignedToken = `${encodedHeader}.${encodedPayload}`;
  const privateKey = FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
  const signature = crypto
    .createSign('RSA-SHA256')
    .update(unsignedToken)
    .sign(privateKey, 'base64url');

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsignedToken}.${signature}`,
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error_description || data.error || 'Firebase access token failed');
  }

  cachedFirebaseAccessToken = data.access_token;
  firebaseAccessTokenExpiresAt = Date.now() + ((data.expires_in || 3600) * 1000);
  return cachedFirebaseAccessToken;
};

const sendFCMV1Notification = async ({ token, title, body, locationLink }) => {
  const { FIREBASE_PROJECT_ID } = process.env;

  if (!isConfigured(FIREBASE_PROJECT_ID)) {
    return { provider: 'fcm-v1', status: 'skipped', reason: 'Firebase project id missing' };
  }

  const accessToken = await getFirebaseAccessToken();
  const response = await fetch(`https://fcm.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/messages:send`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      message: {
        token,
        notification: {
          title,
          body,
        },
        webpush: {
          fcmOptions: {
            link: locationLink.startsWith('http') ? locationLink : '/',
          },
        },
        data: {
          type: 'sos',
          locationLink,
        },
      },
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error?.message || 'FCM HTTP v1 notification failed');
  }

  return { provider: 'fcm-v1', status: 'sent', messageId: data.name };
};

const sendLegacyFCMNotification = async ({ token, title, body, locationLink }) => {
  const { FCM_SERVER_KEY } = process.env;

  if (!isConfigured(FCM_SERVER_KEY)) {
    return { provider: 'fcm-legacy', status: 'skipped', reason: 'Legacy FCM server key missing' };
  }

  const response = await fetch('https://fcm.googleapis.com/fcm/send', {
    method: 'POST',
    headers: {
      Authorization: `key=${FCM_SERVER_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      to: token,
      notification: {
        title,
        body,
      },
      data: {
        type: 'sos',
        locationLink,
      },
      priority: 'high',
    }),
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.failure > 0) {
    throw new Error(data.results?.[0]?.error || 'Legacy FCM notification failed');
  }

  return { provider: 'fcm-legacy', status: 'sent', messageId: data.message_id || data.results?.[0]?.message_id };
};

const sendFCMNotification = async ({ token, title, body, locationLink }) => {
  if (!token) {
    return { provider: 'fcm', status: 'skipped', reason: 'Contact FCM token missing' };
  }

  try {
    const result = await sendFCMV1Notification({ token, title, body, locationLink });
    if (result.status === 'sent') return result;

    const legacyResult = await sendLegacyFCMNotification({ token, title, body, locationLink });
    return legacyResult.status === 'sent' ? legacyResult : result;
  } catch (error) {
    const legacyResult = await sendLegacyFCMNotification({ token, title, body, locationLink });
    if (legacyResult.status === 'sent') return legacyResult;
    throw error;
  }
};

const notifyEmergencyContact = async ({ contact, userId, reason, message, location }) => {
  const phone = normalizePhoneNumber(contact.phone);
  const locationLink = getLocationLink(location);
  const body = buildSOSMessage({ userId, reason, message, location });
  const providerResults = [];
  const wantWhatsApp = isConfigured(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN,
    process.env.TWILIO_WHATSAPP_NUMBER
  );

  if (phone) {
    const smsProvider = String(process.env.SMS_PROVIDER || 'twilio').toLowerCase();
    const smsSenders = smsProvider === 'msg91' ? [sendMSG91SMS, sendTwilioSMS] : [sendTwilioSMS, sendMSG91SMS];

    for (const sendSMS of smsSenders) {
      try {
        const result = await sendSMS({ to: phone, body });
        providerResults.push(result);
        if (result.status === 'sent') break;
      } catch (error) {
        providerResults.push({
          provider: sendSMS === sendTwilioSMS ? 'twilio' : 'msg91',
          status: 'failed',
          reason: error.message,
        });
      }
    }

    if (wantWhatsApp) {
      try {
        const whatsappResult = await sendTwilioWhatsApp({ to: phone, body });
        providerResults.push(whatsappResult);
      } catch (error) {
        providerResults.push({
          provider: 'twilio-whatsapp',
          status: 'failed',
          reason: error.message,
        });
      }
    } else {
      providerResults.push({
        provider: 'twilio-whatsapp',
        status: 'skipped',
        reason: 'Twilio WhatsApp not configured',
      });
    }
  }

  try {
    providerResults.push(await sendFCMNotification({
      token: contact.fcmToken || contact.pushToken,
      title: 'Emergency SOS Alert',
      body,
      locationLink,
    }));
  } catch (error) {
    providerResults.push({ provider: 'fcm', status: 'failed', reason: error.message });
  }

  return {
    id: contact.id,
    name: contact.name,
    phone,
    fcmToken: contact.fcmToken || contact.pushToken || '',
    locationLink,
    status: providerResults.some((result) => result.status === 'sent') ? 'sent' : 'not_sent',
    providers: providerResults,
  };
};

// MongoDB Connection


console.log("Connecting to MongoDB...");
console.log("MONGO URI RAW:");
console.log(JSON.stringify(process.env.MONGO_URI));

mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 30000,
})
.then(() => console.log("MongoDB connected successfully"))
.catch(err => console.error("MongoDB connection error:", err));

// User Model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Safety Event Model
const safetyEventSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  feature: { type: String, required: true },
  message: { type: String, required: true },
  severity: { type: String, required: true }
}, { timestamps: true });

const SafetyEvent = mongoose.model('SafetyEvent', safetyEventSchema);

// Auth Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log("Register body:", req.body);

    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      name,
      email,
      password: hashedPassword
    });

    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(201).json({ token, user: newUser });

  } catch (error) {
    console.error("Register Error:", error);
    res.status(500).json({
      message: "Server error",
      error: error.message
    });
  }
});

// app.post('/api/auth/register', async (req, res) => {
//   try {
//     const { name, email, password } = req.body;

//     const existingUser = await User.findOne({ email });
//     if (existingUser) {
//       return res.status(400).json({ message: 'User already exists' });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const newUser = new User({
//       name,
//       email,
//       password: hashedPassword
//     });

//     await newUser.save();

//     const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET || 'secret123', { expiresIn: '1d' });

//     res.status(201).json({
//       token,
//       user: {
//         id: newUser._id,
//         name: newUser.name,
//         email: newUser.email
//       }
//     });
//   } catch (error) {
//     res.status(500).json({ message: 'Server error' });
//   }
// });

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret123', { expiresIn: '1d' });

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Safety Events Route
app.post('/api/safety-events', async (req, res) => {
  try {
    const { userId, feature, message, severity } = req.body;
    
    const newEvent = new SafetyEvent({
      userId,
      feature,
      message,
      severity
    });
    
    await newEvent.save();
    res.status(201).json({ message: 'Safety event logged successfully', event: newEvent });
  } catch (error) {
    console.error('Error saving safety event:', error);
    res.status(500).json({ message: 'Server error saving event' });
  }
});

// GET Safety Events Route
app.get('/api/safety-events', async (req, res) => {
  try {
    const { userId } = req.query;
    const query = userId ? { userId } : {};
    const events = await SafetyEvent.find(query).sort({ createdAt: -1 }).limit(20);
    res.json(events);
  } catch (error) {
    console.error('Error fetching safety events:', error);
    res.status(500).json({ message: 'Server error fetching events' });
  }
});

// SOS Emergency Model
const sosEventSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  location: { type: Object, default: {} },
  source: { type: String, default: 'manual' }, // voice, shake, manual
  reason: { type: String, default: '' },
  message: { type: String, default: '' },
  contactsNotified: { type: Array, default: [] },
  status: { type: String, default: 'active' }
}, { timestamps: true });

const SOSEvent = mongoose.model('SOSEvent', sosEventSchema);

// Emergency SOS Trigger Route
// Emergency SOS Trigger Route
app.post('/api/sos/trigger', async (req, res) => {
  try {
    const { userId, location, source, reason, message, contacts = [] } = req.body;

    // -------- EMAIL ALERT --------
    const nodemailer = require('nodemailer');

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: "g7892712433@gmail.com",
        pass: "zcpb yswa zcap cqfu"
      }
    });

    const locationLink =
      location?.lat && location?.lng
        ? `https://maps.google.com/?q=${location.lat},${location.lng}`
        : 'Location unavailable';

    try {
      await transporter.sendMail({
        from: "g7892712433@gmail.com",
        to: "gurusirsi25@gmail.com",
        subject: "🚨 Emergency SOS Alert",
        text: `
🚨 Emergency Triggered!

User: ${userId}
Source: ${source}
Reason: ${reason}
Location: ${locationLink}

Message:
${message || "No additional message"}
        `
      });

      console.log("Emergency email sent successfully");
    } catch (emailError) {
      console.error("Email sending failed:", emailError);
    }

    // -------- SMS / CONTACT ALERT --------
    const fallbackPhone = process.env.SOS_NOTIFICATION_PHONE
      ? [
          {
            id: 'fallback',
            name: 'Fallback SOS Receiver',
            phone: process.env.SOS_NOTIFICATION_PHONE
          }
        ]
      : [];

    const contactsToNotify = contacts.length ? contacts : fallbackPhone;

    const deliveryResults = await Promise.all(
      contactsToNotify.map((contact) =>
        notifyEmergencyContact({
          contact,
          userId,
          reason,
          message,
          location: location || {}
        })
      )
    );

    // -------- SAVE TO DB --------
    const newSOS = new SOSEvent({
      userId,
      location: location || {},
      source: source || 'manual',
      reason: reason || '',
      message: message || '',
      contactsNotified: deliveryResults,
      status: 'active'
    });

    await newSOS.save();

    console.log(`🚨 EMERGENCY SOS TRIGGERED BY ${userId} via ${source} 🚨`);

    res.status(201).json({
      success: true,
      message: 'Emergency SOS saved and notifications sent successfully.',
      eventId: newSOS._id,
      contactsNotified: deliveryResults
    });

  } catch (error) {
    console.error('SOS trigger error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error triggering SOS'
    });
  }
});


// GET SOS Events Route
app.get('/api/sos/events', async (req, res) => {
  try {
    const { userId } = req.query;
    const query = userId ? { userId } : {};
    const events = await SOSEvent.find(query).sort({ createdAt: -1 }).limit(20);
    res.json(events);
  } catch (error) {
    console.error('Error fetching SOS events:', error);
    res.status(500).json({ message: 'Server error fetching SOS events' });
  }
});



const nodemailer = require('nodemailer');
app.post('/send-sos', async (req, res) => {
    try {
        const { reason, message } = req.body;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "g7892712433@gmail.com",
                pass: "zcpb yswa zcap cqfu",
            }
        });

        await transporter.sendMail({
            from: "g7892712433@gmail.com",
            to: "gurusirsi25@gmail.com",
            subject: "🚨 Emergency SOS Alert",
            text: message
        });

        res.json({ success: true });
    } catch (error) {
        console.log(error);
        res.status(500).json({ success: false });
    }
});



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
