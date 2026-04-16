/* treeGenerator.js — TRACIDUS Manifestation Tree Generator (FIXED)
   - Preserves original complexity & heuristics
   - Enforces strict model-line compatibility
   - Guarantees renderer traversal
*/

(function(){

  // ---------- Knowledge bases ----------
  const SHORTENERS = ['bit.ly','tinyurl.com','t.co','ow.ly','goo.gl','buff.ly','lnkd.in'];
  const FINANCE_WORDS = ['invoice','payment','wire','bank','transfer','pay','remit','bill','fee','charge'];
  const ATTACH_HINTS = ['attachment','invoice attached','see attached','open the attachment','download the file'];
  const SUSPICIOUS_WORDS = ['login','verify','update','secure','password','credentials','reset','otp','signin','account locked'];
  const PRIZE_WORDS = ['congratulations','winner','prize','claim','reward','voucher','gift card'];
  const DELIVERY_WORDS = ['tracking','delivery','package','shipment','held','out for delivery'];
  const JOB_WORDS = ['interview','offer','position','salary','onboarding','job offer'];
  const NEW_CONTACT_WORDS = ['new number','changed my number','lost my phone'];
  const DIRECT_REQUEST_WORDS = ['send me','transfer','wire','pay me','send money'];
  const BANK_DETAILS_WORDS = ['account number','bank details','routing','iban','paypal','venmo'];
  const OTP_WORDS = ['otp','one-time code','verification code'];
  const IMPERSONATION_WORDS = ['ceo','hr','manager','director','bank','irs','legal'];
  const TIME_PRESSURE_WORDS = ['urgent','immediately','asap','today','now','deadline'];

  function norm(arr){
    const s = arr.reduce((a,b)=>a+b,0) || 1;
    return arr.map(v => v / s);
  }

  function safe(o,k,d){ try{ return o && o[k] !== undefined ? o[k] : d }catch(e){ return d } }

  // ---------- CORE GENERATOR ----------
  window.generateScenario = function(out, rawText){

    out = out || {};
    rawText = (rawText || '').toLowerCase();

    const hits = safe(out,'hitsByCat',{});
    const link = out.linkAnalysis && out.linkAnalysis[0];
    const riskScore = out.riskScore || 0;

    const containsAttach = ATTACH_HINTS.some(w=>rawText.includes(w));
    const containsFinance = FINANCE_WORDS.some(w=>rawText.includes(w));
    const containsPrize = PRIZE_WORDS.some(w=>rawText.includes(w));
    const containsDelivery = DELIVERY_WORDS.some(w=>rawText.includes(w));
    const containsNewContact = NEW_CONTACT_WORDS.some(w=>rawText.includes(w));
    const containsDirectRequest = DIRECT_REQUEST_WORDS.some(w=>rawText.includes(w));
    const containsBankRequest = BANK_DETAILS_WORDS.some(w=>rawText.includes(w));
    const containsOTP = OTP_WORDS.some(w=>rawText.includes(w));
    const containsImpersonation = IMPERSONATION_WORDS.some(w=>rawText.includes(w));
    const containsTimePressure = TIME_PRESSURE_WORDS.some(w=>rawText.includes(w));
    const hasShort = link ? SHORTENERS.some(s=>link.url?.includes(s)) : false;
    const hasSuspiciousKw = SUSPICIOUS_WORDS.some(w=>rawText.includes(w));

    // ---------- ROOT ----------
    const root = {
      id: 'root',
      label: 'Suspicious message detected',
      children: {}
    };

    // ---------- LEVEL 1: PERCEPTIONS ----------
    let pImportant = 0.3 + (containsTimePressure?0.2:0) + (containsImpersonation?0.1:0);
    let pRoutine = 0.25 + (containsDelivery?0.1:0);
    let pUnfamiliar = 0.25 + (containsNewContact?0.2:0);
    let pUncertain = 0.2;

    [pImportant,pRoutine,pUnfamiliar,pUncertain] = norm([
      pImportant,pRoutine,pUnfamiliar,pUncertain
    ]);

    const perceptions = [
      ['important','Treat as important or urgent',pImportant],
      ['routine','Treat as routine or normal',pRoutine],
      ['unfamiliar','Something feels unfamiliar',pUnfamiliar],
      ['uncertain','I am not sure what this is',pUncertain]
    ];

    perceptions.forEach(([k,label,p])=>{
      root.children['p_'+k] = {
        id:'p_'+k,
        label:`${label} (${Math.round(p*100)}%)`,
        children:{}
      };
    });

    // ---------- LEVEL 2: ACTIONS ----------
    function actionsFor(node){
      const acts = [
        ['review','Review message details'],
        ['verify','Verify through another channel'],
      ];
      if(link) acts.push(['click','Click the link']);
      if(containsAttach) acts.push(['open','Open the attachment']);
      if(containsDirectRequest || containsFinance) acts.push(['send','Send money / comply']);
      if(containsOTP) acts.push(['otp','Share verification code']);

      acts.forEach(([k,label])=>{
        node.children[node.id+'_'+k] = {
          id: node.id+'_'+k,
          label: label,
          children:{}
        };
      });
    }

    Object.values(root.children).forEach(actionsFor);

    // ---------- LEVEL 3: CONSEQUENCES ----------
    function consequencesFor(action){
      const id = action.id;
      let cons = [];

      if(id.includes('click')){
        cons = ['Login page appears','Redirected to another site'];
      } else if(id.includes('open')){
        cons = ['File executes malicious code','File appears harmless'];
      } else if(id.includes('send')){
        cons = ['Money transferred','Payment held'];
      } else if(id.includes('otp')){
        cons = ['Account takeover','Attack fails'];
      } else {
        cons = ['No immediate harm'];
      }

      cons.forEach((label,i)=>{
        action.children[id+'_c'+i] = {
          id:id+'_c'+i,
          label:label,
          children:{}
        };
      });
    }

    Object.values(root.children).forEach(p=>{
      Object.values(p.children).forEach(consequencesFor);
    });

    // ---------- LEVEL 4: OUTCOMES ----------
    function outcomesFor(con){
      const bad = /takeover|malicious|transferred/.test(con.label.toLowerCase());
      con.children[con.id+'_o1'] = {
        id:con.id+'_o1',
        label: bad ? 'Serious compromise occurs' : 'No damage occurs'
      };
      con.children[con.id+'_o2'] = {
        id:con.id+'_o2',
        label: bad ? 'Account or funds lost' : 'Attack avoided'
      };
    }

    Object.values(root.children).forEach(p=>{
      Object.values(p.children).forEach(a=>{
        Object.values(a.children).forEach(outcomesFor);
      });
    });

    // ---------- MODEL-LINE ENFORCEMENT (THE FIX) ----------
    function enforceModelLine(node, depth=0, maxDepth=5){
      if(!node || depth>=maxDepth){
        delete node.children;
        delete node.options;
        return;
      }
      if(!node.children || typeof node.children!=='object'){
        delete node.children;
        delete node.options;
        return;
      }
      const keys = Object.keys(node.children);
      if(keys.length===0){
        delete node.children;
        delete node.options;
        return;
      }
      node.options = keys.map(id=>({id}));
      keys.forEach(k=>enforceModelLine(node.children[k],depth+1,maxDepth));
    }

    enforceModelLine(root);

    // ---------- EXPORT ----------
    window.__manifestationScenario = root;
    return root;
  };

})();
