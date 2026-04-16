require('dotenv').config();

const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const morgan = require('morgan');
const compression = require('compression');
const mongoSanitize = require('express-mongo-sanitize');
const xssClean = require('xss-clean');
const hpp = require('hpp');
const Joi = require('joi');
const winston = require('winston');

const app = express();

const PORT = process.env.PORT || 10000;
const HOST = '0.0.0.0';
const API_PREFIX = '/api';

// trust proxy
app.set('trust proxy', true);

// logging
const logTransports = [];
if (process.env.LOG_TO_FILE === '1') {
  if (!fs.existsSync('logs')) fs.mkdirSync('logs');
  logTransports.push(
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  );
}
logTransports.push(new winston.transports.Console({ format: winston.format.simple() }));

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: logTransports
});

app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// ✅ CLEAN SECURITY (FIXED)
app.use(helmet());

// ✅ SIMPLE CORS (FIXED)
app.use(cors());

// rate limit
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT || 60),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' }
});
app.use(`${API_PREFIX}/`, apiLimiter);

// body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xssClean());
app.use(hpp());
app.use(compression());

// static frontend
const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));

app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// helper
function safeError(res, err, code = 500) {
  logger.error(err.stack || err.toString());
  return res.status(code).json({
    error: code === 500 ? 'Internal server error' : err.message || 'Error'
  });
}

// validation
const analyzeSchema = Joi.object({
  text: Joi.string().max(10000).required()
});

const checkLinkSchema = Joi.object({
  url: Joi.string().uri().required()
});

// scan logic
function buildRegExp(token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (/^[a-zA-Z]+$/.test(token) && token.length <= 4) {
    return new RegExp(`\\b${escaped}\\b`, 'gi');
  }
  return new RegExp(escaped, 'gi');
}

const KEYWORDS = {
  trust: ['trust', 'trusted'],
  deception: ['click here', 'login'],
  urgency: ['urgent', 'immediately'],
  lures: ['gift card']
};

function scanTextDetailed(text) {
  const s = (text || '').toLowerCase();
  const hitsByCat = {};

  Object.keys(KEYWORDS).forEach(cat => {
    hitsByCat[cat] = 0;
    for (const phrase of KEYWORDS[cat]) {
      const re = buildRegExp(phrase.toLowerCase());
      const matches = s.match(re);
      if (matches) hitsByCat[cat] += matches.length;
    }
  });

  const axes = ['trust','reciprocity','authority','consensus','intimidation','deception','urgency','scarcity'];
  const scaled = {};
  const axisValues = axes.map(a => hitsByCat[a] || 0);
  const maxHits = Math.max(1, ...axisValues);

  axes.forEach(a => {
    scaled[a] = Math.round(((hitsByCat[a] || 0) / maxHits) * 100);
  });

  const riskScore = Math.min(
    100,
    (hitsByCat.deception || 0) * 10 +
    (hitsByCat.urgency || 0) * 8 +
    (hitsByCat.lures || 0) * 5
  );

  const summary = Object.entries(hitsByCat)
    .filter(([, c]) => c > 0)
    .map(([k]) => k)
    .slice(0, 3);

  return {
    scaled,
    matchesByCat: {},
    hitsByCat,
    riskScore,
    summary: summary.length
      ? summary.join(', ')
      : 'No strong manipulation signals detected.'
  };
}

// routes
app.get('/healthz', (req, res) => {
  res.json({ status: 'ok' });
});

app.post(`${API_PREFIX}/check-link`, (req, res) => {
  try {
    const { error, value } = checkLinkSchema.validate(req.body);
    if (error)
      return res.status(400).json({
        error: error.details.map(d => d.message).join('; ')
      });

    const { url } = value;

    let verdict = 'Safe';
    let score = 0;
    let note = 'Link appears safe.';

    if (url.includes('secure-bank.com')) {
      verdict = 'Malicious';
      score = 100;
      note = 'Simulated phishing link.';
    }

    return res.json({ verdict, score, note });
  } catch (err) {
    return safeError(res, err);
  }
});

app.post(`${API_PREFIX}/analyze`, (req, res) => {
  try {
    const { error, value } = analyzeSchema.validate(req.body);
    if (error)
      return res.status(400).json({
        error: error.details.map(d => d.message).join('; ')
      });

    const result = scanTextDetailed(value.text);
    return res.json(result);
  } catch (err) {
    return safeError(res, err);
  }
});

// error handling
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, next) => {
  logger.error(err.stack || err.toString());
  res.status(500).json({ error: 'Unexpected error' });
});

// start
app.listen(PORT, HOST, () => {
  logger.info(`🚀 Server running on http://${HOST}:${PORT}`);
});
