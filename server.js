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

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3';

// -----------------------------------------------------------------------------
// Trust proxy
// -----------------------------------------------------------------------------

app.set('trust proxy', false);

// -----------------------------------------------------------------------------
// Logging
// -----------------------------------------------------------------------------

const logTransports = [];

if (process.env.LOG_TO_FILE === '1') {
  if (!fs.existsSync('logs')) {
    fs.mkdirSync('logs');
  }

  logTransports.push(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error'
    }),
    new winston.transports.File({
      filename: 'logs/combined.log'
    })
  );
}

logTransports.push(
  new winston.transports.Console({
    format: winston.format.simple()
  })
);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: logTransports
});

app.use(
  morgan('combined', {
    stream: {
      write: msg => logger.info(msg.trim())
    }
  })
);

// -----------------------------------------------------------------------------
// Security middleware
// -----------------------------------------------------------------------------

app.use(helmet({
    contentSecurityPolicy: false
}));

app.use(cors());

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT || 60),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests, slow down.'
  }
});

app.use(`${API_PREFIX}/`, apiLimiter);

app.use(
  express.json({
    limit: '10kb'
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '10kb'
  })
);

app.use(mongoSanitize());
app.use(xssClean());
app.use(hpp());
app.use(compression());

// -----------------------------------------------------------------------------
// Static frontend
// -----------------------------------------------------------------------------

const publicDir = path.join(__dirname, 'public');

app.use(express.static(publicDir));

app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// -----------------------------------------------------------------------------
// Error helper
// -----------------------------------------------------------------------------

function safeError(res, err, code = 500) {
  logger.error(err.stack || err.toString());

  return res.status(code).json({
    error:
      code === 500
        ? 'Internal server error'
        : err.message || 'Error'
  });
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

const analyzeSchema = Joi.object({
  text: Joi.string().max(10000).required()
});

const checkLinkSchema = Joi.object({
  url: Joi.string().uri({
    scheme: ['http', 'https']
  }).required()
});

// -----------------------------------------------------------------------------
// Existing psychological scan logic
// -----------------------------------------------------------------------------

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

      if (matches) {
        hitsByCat[cat] += matches.length;
      }
    }
  });

  const axes = [
    'trust',
    'reciprocity',
    'authority',
    'consensus',
    'intimidation',
    'deception',
    'urgency',
    'scarcity'
  ];

  const scaled = {};
  const axisValues = axes.map(a => hitsByCat[a] || 0);
  const maxHits = Math.max(1, ...axisValues);

  axes.forEach(a => {
    scaled[a] = Math.round(
      ((hitsByCat[a] || 0) / maxHits) * 100
    );
  });

  const riskScore = Math.min(
    100,
    (hitsByCat.deception || 0) * 10 +
      (hitsByCat.urgency || 0) * 8 +
      (hitsByCat.lures || 0) * 5
  );

  const summary = Object.entries(hitsByCat)
    .filter(([, count]) => count > 0)
    .map(([key]) => key)
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

// -----------------------------------------------------------------------------
// VirusTotal helpers
// -----------------------------------------------------------------------------

function ensureVirusTotalConfigured() {
  if (!VIRUSTOTAL_API_KEY) {
    const error = new Error(
      'VirusTotal API key is not configured.'
    );

    error.code = 'VIRUSTOTAL_NOT_CONFIGURED';

    throw error;
  }
}

function virusTotalHeaders() {
  return {
    accept: 'application/json',
    'x-apikey': VIRUSTOTAL_API_KEY
  };
}

function encodeUrlForVirusTotal(url) {
  return Buffer.from(url)
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

async function virusTotalRequest(url, options = {}) {
  ensureVirusTotalConfigured();

  const response = await fetch(url, {
    ...options,
    headers: {
      ...virusTotalHeaders(),
      ...(options.headers || {})
    }
  });

  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    const error = new Error(
      body?.error?.message ||
        `VirusTotal request failed with status ${response.status}.`
    );

    error.status = response.status;
    error.virusTotalBody = body;

    throw error;
  }

  return body;
}

// -----------------------------------------------------------------------------
// Get an existing VirusTotal URL report
// -----------------------------------------------------------------------------

async function getVirusTotalUrlReport(url) {
  const urlId = encodeUrlForVirusTotal(url);

  const endpoint =
    `${VIRUSTOTAL_BASE_URL}/urls/${urlId}`;

  const response = await fetch(endpoint, {
    method: 'GET',
    headers: virusTotalHeaders()
  });

  if (response.status === 404) {
    return null;
  }

  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    const error = new Error(
      body?.error?.message ||
        `VirusTotal URL lookup failed with status ${response.status}.`
    );

    error.status = response.status;
    error.virusTotalBody = body;

    throw error;
  }

  return body;
}

// -----------------------------------------------------------------------------
// Submit a new URL to VirusTotal
// -----------------------------------------------------------------------------

async function submitVirusTotalUrl(url) {
  const form = new URLSearchParams();
  form.append('url', url);

  return virusTotalRequest(
    `${VIRUSTOTAL_BASE_URL}/urls`,
    {
      method: 'POST',
      headers: {
        'content-type':
          'application/x-www-form-urlencoded'
      },
      body: form.toString()
    }
  );
}

// -----------------------------------------------------------------------------
// Retrieve VirusTotal analysis
// -----------------------------------------------------------------------------

async function getVirusTotalAnalysis(analysisId) {
  return virusTotalRequest(
    `${VIRUSTOTAL_BASE_URL}/analyses/${encodeURIComponent(
      analysisId
    )}`,
    {
      method: 'GET'
    }
  );
}

// -----------------------------------------------------------------------------
// Normalize VirusTotal URL evidence
// -----------------------------------------------------------------------------

function normalizeVirusTotalReport(report) {
  const attributes = report?.data?.attributes || {};
  const stats = attributes.last_analysis_stats || {};

  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  const undetected = Number(stats.undetected || 0);
  const timeout = Number(stats.timeout || 0);

  const reputation =
    typeof attributes.reputation === 'number'
      ? attributes.reputation
      : null;

  const evidence = [];

  if (malicious > 0) {
    evidence.push({
      source: 'VirusTotal',
      type: 'vendor_detection',
      value: malicious,
      description:
        `${malicious} security vendor(s) classified the URL as malicious.`
    });
  }

  if (suspicious > 0) {
    evidence.push({
      source: 'VirusTotal',
      type: 'vendor_suspicion',
      value: suspicious,
      description:
        `${suspicious} security vendor(s) classified the URL as suspicious.`
    });
  }

  if (
    malicious === 0 &&
    suspicious === 0
  ) {
    evidence.push({
      source: 'VirusTotal',
      type: 'vendor_detection',
      value: 0,
      description:
        'No malicious or suspicious vendor detections were returned.'
    });
  }

  if (reputation !== null) {
    evidence.push({
      source: 'VirusTotal',
      type: 'reputation',
      value: reputation,
      description:
        'VirusTotal community reputation score.'
    });
  }

  if (attributes.title) {
    evidence.push({
      source: 'VirusTotal',
      type: 'page_title',
      value: attributes.title,
      description:
        'Page title observed by VirusTotal.'
    });
  }

  if (attributes.main_brand) {
    evidence.push({
      source: 'VirusTotal',
      type: 'main_brand',
      value: attributes.main_brand,
      description:
        'Primary brand identity reported by VirusTotal.'
    });
  }

  return {
    status: 'completed',

    malicious,
    suspicious,
    harmless,
    undetected,
    timeout,

    reputation,

    firstSubmissionDate:
      attributes.first_submission_date || null,

    lastAnalysisDate:
      attributes.last_analysis_date || null,

    timesSubmitted:
      typeof attributes.times_submitted === 'number'
        ? attributes.times_submitted
        : null,

    title:
      attributes.title || null,

    categories:
      attributes.categories || {},

    evidence
  };
}

// -----------------------------------------------------------------------------
// Normalize VirusTotal analysis object
// -----------------------------------------------------------------------------

function normalizeVirusTotalAnalysis(analysis) {
  const attributes = analysis?.data?.attributes || {};
  const stats = attributes.stats || {};

  return {
    status: attributes.status || 'unknown',

    malicious: Number(stats.malicious || 0),
    suspicious: Number(stats.suspicious || 0),
    harmless: Number(stats.harmless || 0),
    undetected: Number(stats.undetected || 0),
    timeout: Number(stats.timeout || 0),

    evidence: []
  };
}

// -----------------------------------------------------------------------------
// Health
// -----------------------------------------------------------------------------

app.get('/healthz', (req, res) => {
  res.json({
    status: 'ok'
  });
});

// -----------------------------------------------------------------------------
// Phase 1 — VirusTotal URL intelligence
// -----------------------------------------------------------------------------

app.post(`${API_PREFIX}/check-link`, async (req, res) => {
  try {
    const { error, value } =
      checkLinkSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        error: error.details
          .map(d => d.message)
          .join('; ')
      });
    }

    ensureVirusTotalConfigured();

    const { url } = value;

    logger.info(
      'VirusTotal URL intelligence requested.'
    );

    // -------------------------------------------------------------------------
    // First try to retrieve an existing VirusTotal report.
    // This avoids unnecessarily rescanning URLs.
    // -------------------------------------------------------------------------

    const existingReport =
      await getVirusTotalUrlReport(url);

    if (existingReport) {
      const technical =
        normalizeVirusTotalReport(existingReport);

      return res.json({
        success: true,

        observable: {
          type: 'url',
          value: url
        },

        provider: {
          name: 'VirusTotal',
          apiVersion: 'v3'
        },

        technical,

        evidence: technical.evidence,

        assessment: {
          status: 'technical_evidence_available'
        }
      });
    }

    // -------------------------------------------------------------------------
    // No existing report — submit URL for analysis.
    // -------------------------------------------------------------------------

    const submission =
      await submitVirusTotalUrl(url);

    const analysisId =
      submission?.data?.id || null;

    if (!analysisId) {
      throw new Error(
        'VirusTotal did not return an analysis ID.'
      );
    }

    // -------------------------------------------------------------------------
    // Give VirusTotal a short amount of time to process.
    // We intentionally do NOT hammer the API.
    // -------------------------------------------------------------------------

    await new Promise(resolve =>
      setTimeout(resolve, 5000)
    );

    const analysis =
      await getVirusTotalAnalysis(analysisId);

    const technical =
      normalizeVirusTotalAnalysis(analysis);

    const isCompleted =
      technical.status === 'completed';

    return res.json({
      success: true,

      observable: {
        type: 'url',
        value: url
      },

      provider: {
        name: 'VirusTotal',
        apiVersion: 'v3'
      },

      technical,

      evidence: technical.evidence,

      assessment: {
        status: isCompleted
          ? 'technical_evidence_available'
          : 'analysis_in_progress'
      },

      analysis: {
        id: analysisId,
        status: technical.status
      }
    });

  } catch (err) {
    logger.error(
      `VirusTotal integration error: ${
        err.stack || err.toString()
      }`
    );

    if (
      err.code === 'VIRUSTOTAL_NOT_CONFIGURED'
    ) {
      return res.status(503).json({
        success: false,
        error: {
          code: 'VIRUSTOTAL_NOT_CONFIGURED',
          message:
            'VirusTotal integration is not configured.'
        }
      });
    }

    if (err.status === 401 || err.status === 403) {
      return res.status(502).json({
        success: false,
        error: {
          code: 'VIRUSTOTAL_AUTHENTICATION_FAILED',
          message:
            'VirusTotal authentication failed.'
        }
      });
    }

    if (err.status === 429) {
      return res.status(503).json({
        success: false,
        error: {
          code: 'VIRUSTOTAL_RATE_LIMITED',
          message:
            'VirusTotal rate limit reached. Please try again later.'
        }
      });
    }

    if (err.status >= 400 && err.status < 500) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VIRUSTOTAL_REQUEST_REJECTED',
          message:
            err.message ||
            'VirusTotal rejected the request.'
        }
      });
    }

    return res.status(502).json({
      success: false,
      error: {
        code: 'VIRUSTOTAL_UNAVAILABLE',
        message:
          'Technical intelligence provider is temporarily unavailable.'
      }
    });
  }
});

// -----------------------------------------------------------------------------
// Existing text analysis endpoint
// -----------------------------------------------------------------------------

app.post(`${API_PREFIX}/analyze`, (req, res) => {
  try {
    const { error, value } =
      analyzeSchema.validate(req.body);

    if (error) {
      return res.status(400).json({
        error: error.details
          .map(d => d.message)
          .join('; ')
      });
    }

    const result =
      scanTextDetailed(value.text);

    return res.json(result);

  } catch (err) {
    return safeError(res, err);
  }
});

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({
    error: 'Not found'
  });
});

app.use((err, req, res, next) => {
  logger.error(
    err.stack || err.toString()
  );

  res.status(500).json({
    error: 'Unexpected error'
  });
});

// -----------------------------------------------------------------------------
// Start
// -----------------------------------------------------------------------------

app.listen(PORT, HOST, () => {
  logger.info(
    `🚀 Server running on http://${HOST}:${PORT}`
  );
});
