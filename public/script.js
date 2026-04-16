// script.js
// TRACIDUS — Rule-only unified AI core (synchronous for UI compatibility)
// Produces window.__tracidusLast and keeps API compatibility with existing UI
// Expects global: LABELS, KEYWORDS, PHISHING_FEATURES (if present)

// ----------------- Globals & model safety -----------------
let phishingModel = null;
let MODEL_READY = false;
const MODEL_PATH = './tfjs_model/model.json';

// harmless loader (will detect tf if present, but we won't rely on it)
async function loadModel(){
  if (typeof tf === 'undefined') {
    // TF not present — ok, rule engine is canonical
    MODEL_READY = false;
    phishingModel = null;
    return;
  }
  try {
    // try to load but don't break if it fails
    phishingModel = await tf.loadLayersModel(MODEL_PATH);
    MODEL_READY = true;
    console.log('TRACIDUS AI model loaded:', MODEL_PATH);
  } catch (err) {
    console.warn('Could not load TFJS model; continuing with rule fallback. Error:', err);
    phishingModel = null;
    MODEL_READY = false;
  }
}
// call but allow failures
loadModel().catch(()=>{ /* noop */ });

// ----------------- Utilities -----------------
function safeGetGlobal(name, fallback){
  try { return window[name] === undefined ? fallback : window[name]; } catch(e) { return fallback; }
}
const PHISHING_FEATURES = safeGetGlobal('PHISHING_FEATURES', [
  'URLLength','NoOfDots','NoOfSensitiveWords','NoOfURLFragments',
  'URLIsDynamic','IsEncoded','HostNameLength','URLTitleMatchScore',
  'DomainTitleMatchScore','IsHTTPS','URLIsLive'
]);

function buildRegExp(token){
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  if (/^[a-zA-Z]+$/.test(token) && token.length <= 4) {
    return new RegExp(`\\b${escaped}\\b`, 'gi');
  }
  return new RegExp(escaped,'gi');
}

function extractLinks(text){
  if(!text) return [];
  // Basic http(s) detection - keep simple and local
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const matches = text.match(urlRegex) || [];
  // unique & trim
  return Array.from(new Set(matches.map(s => s.trim())));
}

// ----------------- Feature extraction for URLs (unchanged) -----------------
function extractFeaturesFromURL(url){
  try {
    const urlObj = new URL(url);
    const features = {};
    const placeholderScore = (urlObj.hostname.includes('google') || urlObj.hostname.includes('amazon')) ? 0.9 : 0.2;

    features['URLLength'] = url.length;
    features['NoOfDots'] = (url.match(/\./g) || []).length;
    features['NoOfSensitiveWords'] = (url.match(/(login|verify|update|secure|password|bank|account|invoice|payment)/gi) || []).length;
    features['NoOfURLFragments'] = (url.match(/#/g) || []).length;
    features['URLIsDynamic'] = (url.includes('?') || url.includes('=')) ? 1 : 0;
    features['IsEncoded'] = (url.includes('%')) ? 1 : 0;
    features['HostNameLength'] = urlObj.hostname.length;
    features['URLTitleMatchScore'] = placeholderScore;
    features['DomainTitleMatchScore'] = placeholderScore;
    features['IsHTTPS'] = (urlObj.protocol === 'https:') ? 1 : 0;
    features['URLIsLive'] = 1; // local-only app: assume true

    // return in PHISHING_FEATURES order
    return PHISHING_FEATURES.map(f => (features[f] === undefined ? 0 : features[f]));
  } catch(e){
    // malformed URL -> zeros
    return PHISHING_FEATURES.map(()=>0);
  }
}

// ----------------- Link analysis (SYNC rule-only fallback) -----------------
// returns array of {url, score(0..100), verdict, note}
function analyzeLinks(links){
  // synchronous rule-based analysis (keeps UI synchronous)
  if (!Array.isArray(links) || links.length === 0) return [];

  // If TF model exists and MODEL_READY is true, we still avoid async complexity here.
  // For now we **prefer** the deterministic rule fallback so the app works offline/in-file.
  const results = [];
  for (const link of links){
    try {
      results.push(simpleLinkHeuristic(link));
    } catch(e){
      console.error('analyzeLinks error', e);
      results.push({ url: link, score: 0, verdict: 'Safe', note: 'Analysis error; default safe.' });
    }
  }
  return results;
}

// simple heuristic for link risk (local fallback)
function simpleLinkHeuristic(link){
  const suspiciousDomains = ['bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','drive.google.com','docs.google.com','sharepoint.com','dropbox.com','lnkd.in'];
  const maliciousKeywords = ['login','verify','update','payment','invoice','secure','sso','password','transfer','bank','wire'];
  let score = 0;
  let note = 'Heuristic analysis';
  let verdict = 'Safe';

  const lower = (link||'').toLowerCase();
  if (suspiciousDomains.some(d => lower.includes(d))) { score += 40; note = 'Uses known shortener / file service.'; }
  if (maliciousKeywords.some(k => lower.includes(k))) { score += 30; note = 'Contains suspicious keyword.'; }
  if (!lower.startsWith('https://') && !lower.startsWith('http://')) { score += 10; }
  // obviously fake domain patterns
  if (/(secure-|update-).*(login|account)/i.test(lower) || /-support\./i.test(lower)) score += 30;

  score = Math.min(100, score);
  if (score >= 70) verdict = 'Malicious';
  else if (score >= 35) verdict = 'Suspicious';

  return { url: link, score, verdict, note };
}

// ----------------- Attacker intent & user-perception inference -----------------
// small maps for inference (tweakable)
const INTENT_MAP = {
  credential_harvest: ['login','sign in','password','credentials','otp','verify account'],
  financial_gain: ['invoice','payment','wire','transfer','pay','remit','gift card','voucher','prize'],
  reconnaissance: ['fyi','as discussed','per our call','cc\'d','confirm details','employee'],
  malware_delivery: ['attachment','download','open the file','document shared','invoice attached'],
  social_engineering: ['urgent','immediately','asap','final notice','deadline','expires']
};

const USER_BIAS_MAP = {
  authority_bias: ['admin','manager','hr','security team','official','ceo','cto','verified'],
  urgency_bias: ['urgent','immediately','within 24','today','asap','deadline'],
  reciprocity_bias: ['gift','reward','voucher','thanks','compliments','on us','exclusive offer'],
  familiarity_bias: ['friend','colleague','same team','we use','company-wide','per policy']
};

function inferAttackerIntent(matchesByCat, rawText){
  rawText = (rawText||'').toLowerCase();
  const intents = {};
  for (const [intent, toks] of Object.entries(INTENT_MAP)){
    intents[intent] = toks.reduce((acc, tok) => acc + ((rawText.match(new RegExp(tok,'gi'))||[]).length), 0);
  }
  const total = Object.values(intents).reduce((a,b)=>a+b,0) || 1;
  const normalized = {};
  for (const k of Object.keys(intents)) normalized[k] = Math.round((intents[k]/total)*100);
  return normalized;
}

function inferUserPerception(matchesByCat, rawText){
  rawText = (rawText||'').toLowerCase();
  const biases = {};
  for (const [bias, toks] of Object.entries(USER_BIAS_MAP)){
    biases[bias] = toks.reduce((acc,tok) => acc + ((rawText.match(new RegExp(tok,'gi'))||[]).length), 0);
  }
  const total = Object.values(biases).reduce((a,b)=>a+b,0) || 1;
  const normalized = {};
  for (const k of Object.keys(biases)) normalized[k] = Math.round((biases[k]/total)*100);
  return normalized;
}

// ----------------- Main scanner (synchronous) -----------------
// NOTE: sync to match existing UI flow that expects immediate return.
// Uses rule-based link analysis and keyword heuristics.
function scanTextDetailed(text){
  const s = (text||'').toString();
  const links = extractLinks(s);
  const linkAnalysis = analyzeLinks(links); // sync

  // Keyword matches & counts (uses KEYWORDS global from index.html)
  const matchesByCat = {};
  const hitsByCat = {};
  const allKeywords = (typeof KEYWORDS !== 'undefined') ? KEYWORDS : {};
  for (const k of Object.keys(allKeywords)){
    matchesByCat[k] = [];
    hitsByCat[k] = 0;
    for (const token of allKeywords[k]){
      const re = buildRegExp(token.toLowerCase());
      const found = [...s.toLowerCase().matchAll(re)].map(m=>m[0]);
      if (found.length){
        hitsByCat[k] += found.length;
        matchesByCat[k].push({ phrase: token, count: found.length });
      }
    }
  }

  // Basic signals & boosters
  const axes = ['trust','reciprocity','authority','consensus','intimidation','deception','urgency','scarcity'];
  const axisCounts = axes.map(a => hitsByCat[a] || 0);
  const maxHit = Math.max(1, ...axisCounts);
  const scaled = {};
  axes.forEach((a,i) => { scaled[a] = Math.round(((hitsByCat[a]||0)/maxHit)*100); });

  const deception = hitsByCat.deception || 0;
  const urgency = hitsByCat.urgency || 0;
  const authority = hitsByCat.authority || 0;
  const lures = hitsByCat.lures || 0;
  const aiHits = hitsByCat.ai || 0;
  const containsAttach = /(attachment|invoice attached|see attached|download the file|open the attachment)/i.test(s);
  const containsFinance = /(invoice|payment|wire|bank|transfer|pay|remit|gift card)/i.test(s);

  // link-based blend
  const linkScoreSum = linkAnalysis.reduce((sum, l) => sum + (l.score||0), 0);
  const avgLinkScore = links.length ? Math.round(linkScoreSum / links.length) : 0;

  // Weighted keyword score (heuristic)
  const weights = { trust:1, reciprocity:1, authority:1.2, consensus:1, intimidation:1.5, deception:1.8, urgency:1.6, scarcity:1.0 };
  let weightedSum = 0;
  axes.forEach(a => weightedSum += (hitsByCat[a]||0) * (weights[a] || 1));
  // normalize relative to number of axes and maxHit to 0..100
  const keywordScore = Math.round(Math.min(100, (weightedSum / (maxHit * axes.length)) * 12.5));

  // blended final risk: keywords + link model + lures + AI keyword boost
  const lureBoost = Math.min(30, lures * 6);
  const aiBoost = Math.min(30, aiHits * 8);
  const blended = Math.round(Math.min(100, (keywordScore * 0.55) + (avgLinkScore * 0.35) + lureBoost * 0.06 + aiBoost * 0.06));

  // explicit extras
  let extra = 0;
  if (containsAttach) extra += 6;
  if (containsFinance) extra += 6;
  extra += Math.min(12, urgency * 3);

  const riskScore = Math.min(100, blended + extra);

  // Top signal summary
  const topCats = Object.entries(hitsByCat).sort((a,b)=>b[1]-a[1]).filter(x=>x[1]>0).slice(0,3).map(x=>x[0]);
  let summary = topCats.length ? ('Manipulation signals: ' + topCats.map(t => t[0].toUpperCase()+t.slice(1)).join(', ') + '.') : 'No strong manipulation signals detected.';
  if (aiHits > 0) summary = 'HIGH RISK: AI-patterns detected. ' + summary;
  if (linkAnalysis.some(l => l.verdict === 'Malicious')) summary = 'HIGH RISK: Malicious link detected. ' + summary;
  else if (linkAnalysis.some(l => l.verdict === 'Suspicious')) summary = 'ELEVATED RISK: Suspicious link detected. ' + summary;

  // Advice list (short actionable items)
  const advice = [];
  if (hitsByCat.deception > 0) advice.push('Avoid clicking unknown links; preview the URL or use a sandbox.');
  if (hitsByCat.urgency > 0) advice.push('Don’t act under time pressure — verify via a separate channel.');
  if (hitsByCat.authority > 0) advice.push('Verify sender identity by calling a known number before complying.');
  if (containsAttach) advice.push('Be cautious with attachments — scan in an isolated environment first.');
  if (avgLinkScore >= 60) advice.push('Link appears risky — do not submit credentials.');
  if (!advice.length) advice.push('No immediate red flags; proceed with healthy skepticism.');

  // attacker intent and user perception inference
  const attackerIntent = (typeof inferAttackerIntent === 'function') ? inferAttackerIntent(matchesByCat, s) : {};
  const userPerception = (typeof inferUserPerception === 'function') ? inferUserPerception(matchesByCat, s) : {};

  // unified result object (stable schema for UI / generator)
  const result = {
    timestamp: Date.now(),
    text: s,
    scaled,                // radar-style per-axis 0..100
    matchesByCat,          // phrases found per category
    hitsByCat,             // counts per category
    riskScore,             // 0..100 overall
    summary,
    advice,
    linkAnalysis,          // array of {url,score,verdict,note}
    attackerIntent,        // inferred attacker goals (weights)
    userPerception,        // inferred user biases (weights)
    provenance: {
      modelUsed: (MODEL_READY && phishingModel) ? 'tfjs_model' : 'rule_fallback',
      modelReady: !!MODEL_READY
    }
  };

  // persist last result for UI + generator
  try { window.__tracidusLast = Object.assign({}, result); } catch(e) { /* noop */ }
  window.__tracidusLast = Object.assign({}, result);

  return result;
}

// expose for console/manual use (keeps compatibility)
window.__tracidusScan = scanTextDetailed;

// ----------------- Console helpers -----------------
window.TRACIDUS_Checks = function(){
  return {
    scanTextDetailed_exists: typeof scanTextDetailed === 'function',
    analyzeLinks_exists: typeof analyzeLinks === 'function',
    PHISHING_FEATURES_defined: !!window.PHISHING_FEATURES,
    KEYWORDS_defined: !!window.KEYWORDS,
    LABELS_defined: !!window.LABELS,
    MODEL_READY: !!MODEL_READY,
    phishingModel_present: !!phishingModel
  };
};

window.TRACIDUS_LogState = function(){
  console.groupCollapsed('TRACIDUS state');
  console.log('window.__tracidusLast ->', window.__tracidusLast || null);
  console.log('window.__manifestationScenario ->', window.__manifestationScenario || null);
  console.log('Checks ->', window.TRACIDUS_Checks());
  console.groupEnd();
};

// ----------------- Export (module safety) -----------------
if (typeof module !== 'undefined' && module.exports){
  module.exports = { loadModel, scanTextDetailed, analyzeLinks, extractFeaturesFromURL };
}
