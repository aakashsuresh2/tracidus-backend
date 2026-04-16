// phishing_features.js
// Defines the feature order the TFJS model expects.
// Must match the model's training feature order exactly.
window.PHISHING_FEATURES = [
  'URLLength',
  'NoOfDots',
  'NoOfSensitiveWords',
  'NoOfURLFragments',
  'URLIsDynamic',
  'IsEncoded',
  'HostNameLength',
  'URLTitleMatchScore',
  'DomainTitleMatchScore',
  'IsHTTPS',
  'URLIsLive'
];
console.log('PHISHING_FEATURES loaded:', !!window.PHISHING_FEATURES);
