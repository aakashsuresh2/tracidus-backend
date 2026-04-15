// link_ai_module.js

// ================= FEATURE EXTRACTION =================
function extractFeatures(url){
    try {
        const urlObj = new URL(url);

        const letters = (url.match(/[a-zA-Z]/g) || []).length;
        const digits = (url.match(/[0-9]/g) || []).length;
        const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;

        return [
            url.length,
            urlObj.hostname.length,
            /^[0-9.]+$/.test(urlObj.hostname) ? 1 : 0,
            urlObj.hostname.split('.').length - 1,
            letters,
            letters / url.length || 0,
            digits,
            digits / url.length || 0,
            (url.match(/=/g) || []).length,
            (url.match(/\?/g) || []).length,
            (url.match(/&/g) || []).length,
            specialChars,
            specialChars / url.length || 0,
            url.startsWith("https") ? 1 : 0
        ];

    } catch (e){
        return Array(14).fill(0);
    }
}


// ================= HELPER DETECTIONS =================

// fake domain inside params
function hasFakeDomainPattern(url){
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;

        const suspiciousPart = url.split(/[?=]/).slice(1).join(" ");

        const domainMatch = suspiciousPart.match(/\b([a-z0-9-]+\.(com|net|org|io|co))\b/i);

        if (domainMatch) {
            const embedded = domainMatch[1];
            if (!hostname.includes(embedded)) return true;
        }

        return false;
    } catch { return false; }
}


// random garbage path
function hasRandomPath(url){
    try {
        const path = new URL(url).pathname.replace(/\//g, "");
        if (path.length < 10) return false;

        return /[A-Z0-9]{10,}/.test(path);
    } catch { return false; }
}


// suspicious subdomain depth
function hasSuspiciousSubdomain(url){
    try {
        const host = new URL(url).hostname;
        const parts = host.split(".");
        return parts.length > 3;
    } catch { return false; }
}


// brand impersonation
function hasBrandImpersonation(url){
    const brands = ["paypal","bank","google","apple","amazon","microsoft"];
    const lower = url.toLowerCase();

    for (const b of brands){
        if (lower.includes(b)) return true;
    }
    return false;
}


// keyword detection
function getKeywordScore(url){
    const keywords = [
        "login","verify","update","account",
        "secure","password","payment","confirm"
    ];

    let score = 0;
    const lower = url.toLowerCase();

    keywords.forEach(k=>{
        if (lower.includes(k)) score += 1;
    });

    return score;
}


// ================= AI =================
async function analyzeLinkAI(url){
    const features = extractFeatures(url);

    try {
        const res = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ features })
        });

        return await res.json();
    } catch {
        return { prediction: 0, confidence: 0 };
    }
}


// ================= MAIN PIPELINE =================
async function analyzeLinksAI(links){
    const results = [];

    for (const link of links){

        const lower = link.toLowerCase();

        let score = 0;
        let reasons = [];

        // ===== STRONG RULES =====

        if (lower.includes("bit.ly") || lower.includes("tinyurl") || lower.includes("goo.gl")){
            score += 40;
            reasons.push("Shortened URL");
        }

        if (hasFakeDomainPattern(link)){
            score += 50;
            reasons.push("Fake domain in URL");
        }

        if (hasRandomPath(link)){
            score += 40;
            reasons.push("Randomized path");
        }

        if (hasSuspiciousSubdomain(link)){
            score += 30;
            reasons.push("Deep subdomain");
        }

        if (hasBrandImpersonation(link)){
            score += 30;
            reasons.push("Brand impersonation");
        }

        const keywordScore = getKeywordScore(link);
        if (keywordScore > 0){
            score += keywordScore * 10;
            reasons.push("Phishing keywords");
        }

        // length + structure
        if (link.length > 100){
            score += 20;
            reasons.push("Long URL");
        }

        if ((link.match(/-/g)||[]).length > 4){
            score += 15;
            reasons.push("Too many hyphens");
        }

        // ===== AI SUPPORT =====
        const ai = await analyzeLinkAI(link);
        const aiScore = Math.round(ai.confidence * 100);

        if (ai.prediction === 1){
            score += 30;
            reasons.push("AI flagged");
        }

        // ===== FINAL DECISION =====
        let verdict = "Safe";

        if (score >= 80){
            verdict = "Malicious";
        } else if (score >= 40){
            verdict = "Suspicious";
        }

        score = Math.max(0, Math.min(100, score));

        results.push({
            url: link,
            score,
            verdict,
            note: reasons.join(", ") || "No strong indicators"
        });
    }

    return results;
}


// ================= EXPORT =================
window.analyzeLinks = analyzeLinksAI;