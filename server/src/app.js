import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';
import { requireAuth } from './middleware/auth.js';
import { doubleCsrfProtection, issueCsrfToken } from './middleware/csrf.js';

const app = express();

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Anti-CSRF (see middleware/csrf.js). The token endpoint is a safe GET and is
// mounted before the guard; the guard then covers every state-changing request
// (POST/PATCH/DELETE) on every route below, except the pre-auth login/register
// routes which it skips by path. GET/HEAD/OPTIONS are never checked.
app.get('/api/csrf-token', requireAuth, issueCsrfToken);
app.use(doubleCsrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  // Missing / invalid / mismatched CSRF token: the request did not provably come
  // from our own app. Refuse it without touching any state.
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' });
  }
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || 'Server Error' });
});

export default app;
