
(function () {
  let userInteracted = false;
  let alerted = false;
  let PROTECTION_ENABLED = true;

  chrome.storage.local.get(["enabled"], res => {
    PROTECTION_ENABLED = res.enabled !== false;
  });
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.enabled) {
      PROTECTION_ENABLED = changes.enabled.newValue !== false;
    }
  });

    //  Payload signatures 
    const PAYLOAD_PATTERNS = {
        'SQL Injection': [
            /or\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
            /union\s+select/i,
            /select\s+.*from/i,
            /order\s+by/i,
            /group\s+by/i,
            /having\b/i,
            /and\s+1=1/i,
            /or\s+1=1/i,
            /like\s+['"]?%/i,
            /between\b/i,
            /\binsert\b.*\binto\b/i,
            /\bupdate\b.*\bset\b/i,
            /\bdelete\b.*\bfrom\b/i,
            /\bdrop\b.*\btable\b/i,
            /\balter\b.*\btable\b/i,
            /\bcreate\b.*\btable\b/i,
            /sleep\s*\(/i,
            /benchmark\s*\(/i,
            /waitfor\s+delay/i,
            /pg_sleep\s*\(/i,
            /@@version/i,
            /information_schema/i,
            /mysql\./i,
            /sys\./i,
            /\/\*.*\*\//i,
            /--\s*$/i,
            /#.*$/i,
            /'.*or.*'/i,
            /'.*and.*'/i,
            /'.*1=1.*'/i,
            /[\"'`]\s*=\s*[\"'`]/i
        ],
        
        'XSS': [
            /<script[^>]*>/i,
            /javascript:/i,
            /onload\s*=/i,
            /onerror\s*=/i,
            /onclick\s*=/i,
            /onmouseover\s*=/i,
            /onsubmit\s*=/i,
            /onchange\s*=/i,
            /onfocus\s*=/i,
            /onscroll\s*=/i,
            /ontoggle\s*=/i,
            /onmouseout\s*=/i,
            /onkeydown\s*=/i,
            /onkeypress\s*=/i,
            /onkeyup\s*=/i,
            /onblur\s*=/i,
            /onfocusin\s*=/i,
            /onfocusout\s*=/i,
            /oninput\s*=/i,
            /onselect\s*=/i,
            /ondblclick\s*=/i,
            /oncontextmenu\s*=/i,
            /ondrag\s*=/i,
            /ondrop\s*=/i,
            /alert\s*\(/i,
            /prompt\s*\(/i,
            /confirm\s*\(/i,
            /eval\s*\(/i,
            /document\.cookie/i,
            /window\.location/i,
            /document\.write/i,
            /innerHTML/i,
            /outerHTML/i,
            /<iframe/i,
            /<img.*onerror/i,
            /script.*src=/i,
            /data:text\/html/i,
            /vbscript:/i,
            /expression\(/i,
            /%3Cscript/i,
            /%22onload%3D/i,
            /%27onerror%3D/i,
            /%3Ciframe/i,
            /%3Cimg/i,
            /%3Csvg/i,
            /<svg.*onload/i,
            /<marquee.*onstart/i,
            /<body.*onload/i,
            /<input.*onfocus/i,
            /<details.*ontoggle/i,
            /<video.*onplay/i,
            /<audio.*onplay/i,
            /<form.*onsubmit/i,
            /<select.*onchange/i,
            /<textarea.*oninput/i,
            /<link.*onerror/i,
            /<meta.*onload/i,
            /<base.*onerror/i,
            /<source.*onerror/i,
            /<track.*onload/i,
            /<canvas.*onerror/i,
            /<object.*onload/i,
            /<embed.*onerror/i,
            /<applet.*onstart/i,
            /<frameset.*onload/i,
            /<frame.*onload/i,
            /<noframes.*onload/i,
            /<isindex.*onfocus/i,
            /<keygen.*onchange/i,
            /<menu.*onclick/i,
            /<menuitem.*onclick/i,
            /<noscript.*onload/i,
            /<optgroup.*onfocus/i,
            /<option.*onselect/i,
            /<output.*onload/i,
            /<progress.*onload/i,
            /<rp.*onload/i,
            /<rt.*onload/i,
            /<ruby.*onload/i,
            /<summary.*ontoggle/i,
            /<time.*onload/i,
            /<wbr.*onload/i
        ],
        
        'Command Injection': [
         /(?:^|[\s"'`])(?:;|\|\||&&|\|)\s*/,
         /\b(whoami|id|uname|ls|dir|cat|type|pwd|ipconfig|ifconfig|netstat|ping)\b/i,
         /\b(wget|curl|nc|netcat|ncat)\b/i,
         /\b(bash|sh|zsh|ksh|powershell|cmd\.exe)\b/i,
         /\b(exec|system|shell_exec|passthru|popen|proc_open)\s*\(/i,
         /`[^`]+`/,
         /\$\([^)]*\)/,
        ],

        
        'Path Traversal': [
            /\.\.\//,
            /%2e%2e%2f/i,
            /%2e%2e%5c/i,
            /(etc|windows)\/(passwd|system32)/i,
            /\.\.\//i,
            /\.\.\\+/i,
            /%2e%2e%2f/i,
            /%2e%2e%5c/i,
            /%252e%252e%252f/i,
            /%252e%252e%255c/i,
            /%c0%ae%c0%ae\//i,
            /etc\/passwd/i,
            /etc\/shadow/i,
            /etc\/hosts/i,
            /boot\.ini/i,
            /win\.ini/i,
            /\.htaccess/i,
            /\.env/i,
            /\/proc\/self\/environ/i,
            /\/proc\/self\/cmdline/i,
            /file:\/\//i,
            /ftp:\/\//i,
            /smb:\/\//i,
            /gopher:\/\//i,
            /\.\.%00/i,
            /\.\.%0a/i,
            /\.\.%0d/i,
            /\.\.%09/i,
            /\.\.\x00/i,
            /\.\.\x0a/i,
            /\.\.\x0d/i,
            /(^|[^\w])\.\.(\/|\\)/i
        ],
        
        'SSRF': [
            /localhost/i,
            /127\.0\.0\.1/i,
            /0\.0\.0\.0/i,
            /::1/i,
            /192\.168\.\d+\.\d+/i,
            /10\.\d+\.\d+\.\d+/i,
            /172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+/i,
            /169\.254\.169\.254/i,
            /metadata\.google\.internal/i,
            /metadata\.aliyun\.com/i,
            /169\.254\.170\.2/i,
            /@(localhost|127\.0\.0\.1|192\.168|10\.|172\.|169\.254)/i,
            /\/\/(localhost|127\.0\.0\.1|192\.168|10\.|172\.|169\.254)/i,
            /admin\.internal/i,
            /internal\.api/i,
            /staging\.local/i,
            /dev\.internal/i,
            /test\.local/i,
            /private\.network/i,
            /(?:https?|ftp|gopher|file|smtp|ldap):\/\/(?:localhost|127\.|192\.168|10\.|172\.)/i,
            /:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/i,
            /\/\/(0x[0-9a-f]+|0[0-7]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|[0-9]+)){3}/i,
            /\/\/(?:[a-f0-9:]+::?|::)/i,
            /\.local(?:domain)?\b/i,
            /\.internal\b/i,
            /\.localnet\b/i,
            /\.home\b/i,
            /\.lan\b/i,
            /\.corp\b/i,
            /\.office\b/i,
            /\.intranet\b/i,
            /\.priv\b/i,
            /\.private\b/i,
            /^http:\/\/(?:[^/@]*@)?(?:localhost|127\.|192\.168|10\.|172\.)/i,
            /^ftp:\/\/(?:[^/@]*@)?(localhost|127\.|192\.168|10\.|172\.)/i,
            /^file:\/\/\/(?:etc|proc|dev|sys|boot|windows)/i
        ],
        
        'CSRF': [
            /csrf/i,
            /token/i,
            /nonce/i,
            /authenticity/i,
            /_token/i,
            /anticsrf/i,
            /csrf_token/i,
            /csrfmiddlewaretoken/i,
            /requestverificationtoken/i,
            /x-csrf-token/i,
            /x-xsrf-token/i,
            /^[a-f0-9]{32}$/i,
            /^[a-f0-9]{64}$/i,
            /^[A-Za-z0-9+/]{20,}={0,2}$/i,
            /^[A-Za-z0-9\-_]{20,}$/i,
            /<form[^>]+action=/i,
            /method=["']?post/i,
            /csrf_token/i,
            /requestverificationtoken/i
        ],
        
        'SSTI': [
            /\{\{.*?\}\}/i,
            /\{\%.*?\%\}/i,
            /\$\{.*?\}/i,
            /<%.*%>/i,
            /#{.*}/i,
            /\(\{.*\}\)/i
        ],

        'LFI': [
           /\.\.\/\.\.\/\.\.\/(etc|proc|dev|sys)\//i,
           /\.\.%2f\.\.%2f\.\.%2f/i,
           /\.\.\\\.\.\\\.\.\\/i,
           /\/etc\/passwd/i,
           /\/etc\/shadow/i,
           /\/etc\/hosts/i,
           /\/proc\//i,
           /\/dev\//i,
           /\.htaccess/i,
           /\.env/i,
           /boot\.ini/i,
           /win\.ini/i,
           /file:\/\/\/etc\//i,
           /\.\.%00/i,
           /\.\.%0a/i,
           /\.\.%0d/i
        ],

        'RFI': [
           /\b(https?|ftp|gopher|file|smtp|ldap):\/\/.*\.(php|txt|inc|html)/i,
           /\bphp:\/\/filter\b/i,
           /\bphp:\/\/input\b/i,
           /\bphp:\/\/stdin\b/i,
           /\bzip:\/\/.*\.php\b/i,
           /\bphar:\/\/.*\b/i,
           /data:text\/html/i,
           /expect:\/\/.*/i
        ],
        
       'RCE': [
          /\beval\s*\(/i,
          /\bassert\s*\(/i,
          /\bphpinfo\s*\(/i,
          /\bRuntime\.getRuntime\(\)\.exec\b/i,
          /\(\)\s*\{.*\};/i
        ],


        
        'API Abuse': [
          /redirect=.*http/i,
          /callback=.*http/i,
          /return_url=.*http/i,
          /url=.*\/\/[^\s]+/i,
          /\blimit\s*[:=]\s*\d{6,}\b/i,
          /\bpage_size\s*[:=]\s*\d{4,}\b/i,
          /"limit"\s*:\s*\d{6,}/i,
          /"page(size)?"\s*:\s*\d{4,}/i,
          /\b(limit|page_size|offset)\s*=\s*\d{4,}\b/i,
          /"offset"\s*:\s*\d{6,}/
        ],

        
        'JS Exploitation': [
            /__proto__/i,
            /constructor\s*\(/i,
            /atob\s*\(/i,
            /btoa\s*\(/i
        ],
        
        'Serialization': [
          /O:[0-9]+:"[A-Za-z0-9_]+":/i,
          /a:[0-9]+:{.*}/i,
          /s:[0-9]+:"([^"]*)";/i,
          /\brO0AB\b/,              
          /^rO0AB/,
        ],

        
        'XXE': [
            /<!ENTITY/i,
            /SYSTEM\s+"file:/i,
            /SYSTEM\s+"http:/i,
            /DOCTYPE.*ENTITY/i,
            /ENTITY.*SYSTEM/i,
            /xmlns:xsi/i,
            /xsi:schemaLocation/i,
            /<!\[CDATA\[.*\]\]>/i,        
            /<!DOCTYPE/i,
            /<!ENTITY/i,
            /SYSTEM\s+"(file|http):/i,
            /&xxe;/i,
            /%26xxe%3B/i           
        ],
        
        'NoSQL Injection': [
            /\$where/i,
            /\$ne/i,
            /\$gt/i,
            /\$lt/i,
            /\$gte/i,
            /\$lte/i,
            /\$in/i,
            /\$nin/i,
            /\$regex/i,
            /\$exists/i,
            /\$type/i,
            /\$mod/i,
            /\$size/i,
            /\$all/i,
            /\$elemMatch/i,
            /\$not/i,
            /\$or/i,
            /\$and/i,
            /\$nor/i
        ],
        
        'JWT Tampering': [
            /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i,
            /alg\s*:\s*['"]none['"]/i,
            /RS256.*HS256/i,
            /"kid".*"http/i,
            /"jku".*"http/i,
            /"x5u".*"http/i,
            /"x5c".*BEGIN/i,
            /"alg"\s*:\s*"none"/i,
            /eyJ[A-Za-z0-9_-]+\./,
            /"kid"\s*:\s*"http/i,
            /\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b/,   // JWT general
            /"alg"\s*:\s*"none"/i,
            /\balg\s*[:=]\s*none\b/i,
            /RS256\s*.*HS256/i,
            /"kid"\s*:\s*"http/i,
            /"jku"\s*:\s*"http/i
        ],
        
        'GraphQL Injection': [
            /query\s*{.*__typename.*}/i,
            /mutation\s*{.*}/i,
            /fragment.*on/i,
            /\.\.\./i,  
            /__schema/i,
            /__type/i,
            /__directive/i
        ],
        
        'WebSocket Injection': [
           /ws:\/\//i,
           /wss:\/\//i,
           /Upgrade:\s*websocket/i,
           /Connection:\s*Upgrade/i,
           /Sec-WebSocket-Key/i,
           /"action"\s*:\s*"send"/i,
           /"msg"\s*:/i,
           /"cmd"\s*:\s*"\.\.\//i,
           /"ws(s)?"\s*:/i
        ]

    }; 

    function pickBestAttack(detectedAttacks) {
  const severityLevels = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

  const typeBias = {
    "RCE": 50,
    "XXE": 40,
    "WebSocket Injection": 35,
    "Path Traversal": 30,
    "SQL Injection": 25,
    "XSS": 25,
    "LFI": 10,
    "RFI": 10
  };

  return detectedAttacks
    .slice()
    .sort((a,b) => {
      const sa = severityLevels[a.severity] || 0;
      const sb = severityLevels[b.severity] || 0;
      if (sb !== sa) return sb - sa;
      return (typeBias[b.type] || 0) - (typeBias[a.type] || 0);
    })[0];
}

  function isReasonableMatch(attackType, matchedText, fullPayload, source) {
    const falsePositives = {
      'Command Injection': [
        (text) => text.toLowerCase().includes('/etc/passwd'),
        (text) => text === '..' || text === '../'
      ],
      'SQL Injection': [(text) => text === "'" || text === '"'],
      'XSS': [(text) => text === '<' || text === '>']
    };

    
if (attackType === "XXE") {
  if (!/(<!ENTITY|<!DOCTYPE|SYSTEM\s+file|SYSTEM\s+http)/i.test(fullPayload)) {
    return false;
  }
}

if (attackType === "LFI" && /<!DOCTYPE|<!ENTITY|&xxe;/i.test(fullPayload)) {
  return false;
}

if (attackType === "WebSocket Injection") {
  if (!/wss?:\/\//i.test(fullPayload)) return false;
}

if (attackType === "LFI" && /wss?:\/\//i.test(fullPayload)) {
  return false;
}

if (attackType === "JWT Tampering") {
  if (!/eyJ[A-Za-z0-9_-]+\./.test(fullPayload)) return false;
}

if (attackType === "API Abuse") {
  if (!/(redirect|callback|return_url|limit|page_size|offset)/i.test(fullPayload)) {
    return false;
  }
}

if (attackType === "API Abuse") {
  if (source === "url" && !/[?&]/.test(fullPayload)) return false;
}

if (attackType === "LFI" && /<!DOCTYPE|<!ENTITY|&xxe;/i.test(fullPayload)) {
  return false;
}

if (attackType === "LFI") {
  if (/^\s*wss?:\/\//i.test(fullPayload) || /Upgrade:\s*websocket/i.test(fullPayload)) return false;
}

if (attackType === "JS Exploitation") {
  if (!/(?:__proto__|constructor|atob|btoa|javascript:)/i.test(fullPayload)) {
    return false;
  }
}

    const rules = falsePositives[attackType] || [];
    return !rules.some(rule => rule(matchedText));
  }

function detectContext(value, source) {
  if (source === "url") {
    if (/\.\.\//i.test(value) || /%2e%2e%2f/i.test(value)) {
      return "path-traversal";
    }
    if (/^(\?|&|[^=]+=)/.test(value)) {
      return "query";
    }
    return "path";
  }

  if (source === "dom") {
    if (/<[a-z][\s\S]*>/i.test(value)) return "html";
    if (/javascript:|eval\(|new Function/i.test(value)) return "js";
    return "text";
  }

  if (source === "input") {
    if (/^\d+$/.test(value)) return "numeric";
    return "text";
  }
  
  if (source === "url") {
  if (/javascript:|__proto__|constructor\s*\(/i.test(value)) {
    return "js";
  }
  if (/\.\.\//i.test(value)) return "path-traversal";
  if (/^(\?|&|[^=]+=)/.test(value)) return "query";
  return "path";
}

  return "unknown";
}

const SOURCE_ATTACK_MAP = {
  input: [
    "RCE",
    "Command Injection",
    "SQL Injection",
    "XSS",
    "SSTI",
    "NoSQL Injection",
    "XXE",
    "LFI",
    "RFI",
    "Path Traversal",
    "SSRF"
  ],

  url: [
    "SQL Injection",
    "API Abuse",
    "SSRF",
    "JWT Tampering",
    "WebSocket Injection",
    "Path Traversal",
    "LFI",
    "RFI",
    "XSS",
    "Command Injection",
    "RCE",
    "SSTI",
    "XXE",
    "CSRF",
    "NoSQL Injection",
    "JS Exploitation",
    "Serialization"
  ],

  dom: [
    "XSS",
    "JS Exploitation"
  ],
};



function detectAllAttackTypes(value, source,urlCtx = null) {
const context = urlCtx || detectContext(value, source);
const PRIORITY_BY_SOURCE = {
  input: [
    "RCE",
    "Command Injection",
    "SQL Injection",
    "XSS",
    "SSTI",
    "NoSQL Injection",
    "XXE",
    "LFI",
    "RFI",
    "Path Traversal",
    "CSRF",
    "JWT Tampering",
    "Insecure Deserialization",
    "API Abuse",
    "WebSocket Injection"
  ],
  url: [
    "SQL Injection",
    "API Abuse",
    "SSRF",
    "JWT Tampering",
    "WebSocket Injection",
    "Path Traversal",
    "LFI",
    "RFI",
    "XSS",
    "Command Injection",
    "RCE",
    "SSTI",
    "XXE",
    "CSRF",
    "NoSQL Injection",
    "JS Exploitation",
    "Serialization"
  ],
  dom: [
    "XSS",
    "JS Exploitation"
  ]
};

const PRIORITY =
  PRIORITY_BY_SOURCE[source] ||
  PRIORITY_BY_SOURCE["input"];

 const allowed =
  SOURCE_ATTACK_MAP[source] ||
  SOURCE_ATTACK_MAP["input"];

  const detectedTypes = [];

const scanOrder =
  PRIORITY.filter(a => allowed.includes(a)).length
    ? PRIORITY.filter(a => allowed.includes(a))
    : allowed;

for (const attackType of scanOrder) {

    const patterns = PAYLOAD_PATTERNS[attackType] || [];
    for (const pattern of patterns) {
      if (!pattern.test(value)) continue;
      const match = value.match(pattern);
      if (match && isReasonableMatch(attackType, match[0], value, source)) {
        detectedTypes.push({
          type: attackType,
          severity: getSeverityByType(attackType),
          matchedPattern: match[0],
          context
        });

          if (attackType === "WebSocket Injection") {
    return detectedTypes;
  }

        break;
      }
    }
  }
  return detectedTypes;
}

  const CONTEXT_RULES = {
  query: [
    "SQL Injection",
    "NoSQL Injection",
    "SSRF",
    "API Abuse",
    "Path Traversal",
    "XXE",
    "RCE",
    "JWT Tampering",
    "XSS",
    "JS Exploitation"
  ],
  path: [
    "Path Traversal",
    "LFI",
    "RFI"
  ],
  html: ["XSS"],
  js: ["XSS", "JS Exploitation"],
  numeric: ["SQL Injection"],
  text: Object.keys(PAYLOAD_PATTERNS),
  unknown: Object.keys(PAYLOAD_PATTERNS)
};

  function isMalicious(value) {
    for (const patterns of Object.values(PAYLOAD_PATTERNS)) {
      if (patterns.some(rx => rx.test(value))) return true;
    }
    return false;
  }

  function detectSources(payload, url) {
    const s = [];
    let decoded = String(payload || "");
    try { decoded = decodeURIComponent(decoded); } catch (_) {}

    try {
      const u = new URL(url);
      if (u.search && u.search.length > 1) s.push("url");
    } catch (_) {}

    if (/<script|onerror\s*=|onload\s*=|javascript:/i.test(decoded)) s.push("dom");
    if (decoded.length >= 120) s.push("post");
    if (s.length === 0) s.push("unknown");
    return [...new Set(s)];
  }

  function extractSuspiciousPart(text) {
    if (!text) return "";
    const patterns = [
      /or\s+1=1/i,
      /union\s+select/i,
      /<script.*?>/i,
      /\.\.\//,
      /\{\{.*?\}\}/,
      /__schema/i,
      /\$ne|\$gt|\$where/i
    ];
    for (const p of patterns) {
      const m = String(text).match(p);
      if (m) return m[0];
    }
    return String(text).slice(0, 80);
  }

function detectUrlContext(value, fullUrl) {
  let decodedValue = value;
  let decodedUrl = fullUrl;

  try {
    decodedValue = decodeURIComponent(value);
    decodedUrl = decodeURIComponent(fullUrl);
  } catch (_) {}

  //  Traversal token
  const hasTraversal = (
    /\.\.\//i.test(decodedValue) ||
    /\.\.\\/i.test(decodedValue) ||
    /%2e%2e%2f/i.test(value) ||
    /%2e%2e%5c/i.test(value)
  );

  //  Is inside query parameter?
  if (hasTraversal && /^[^=]+=/.test(decodedValue)) {
    return "query-param";
  }

  //  Is query string itself
  if (/^(\?|&)/.test(decodedValue)) {
    return hasTraversal ? "query-traversal" : "query";
  }

  //  Path-based traversal
  if (hasTraversal) {
    return "path-traversal";
  }

  return "path";
}

  function isLikelyCSS(text) {
    return (
      /{[^}]+}/.test(text) &&
      /:[^;]+;/.test(text) &&
      !/\b(select|union|insert|delete|update|drop|alter)\b/i.test(text) &&
      !/\bor\s+1=1\b/i.test(text)
    );
  }

function saveDetection(entry) {
  chrome.storage.local.get(["detections"], (res) => {
    let detections = res.detections || [];
        if (detections.length > 0) {
      const lastEntry = detections[0]; 
      
      const isDuplicate = 
        lastEntry.type === entry.type && 
        lastEntry.payload === entry.payload &&
        lastEntry.url === entry.url &&
        (Date.now() - Date.parse(lastEntry.time)) < 10000; 

      if (isDuplicate) {
        console.log("Duplicate detection ignored (Anti-Spam)");
        return; 
      }
    }

    detections.unshift(entry); 
    
    if (detections.length > 10) detections = detections.slice(0, 10);
    
    chrome.storage.local.set({ detections });
  });
}

// ZG SCORING LOGIC
function calculateDynamicScore(type, source, baseSeverity) {
    let base = 5.0;
    if (baseSeverity === 'CRITICAL') base = 9.0;
    else if (baseSeverity === 'HIGH') base = 7.5;
    else if (baseSeverity === 'MEDIUM') base = 5.0;
    else base = 2.5;

    let multiplier = 1.0;
    if (source === 'dom' || source === 'input') multiplier = 1.1; 
    if (source === 'url') multiplier = 0.9; 

    let score = Math.min(10.0, (base * multiplier));
    return parseFloat(score.toFixed(1));
}

function getSeverityLabel(score) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
}
 function triggerAlert(value, source) {
    const now = Date.now();
if (window.__lastAlertTime && now - window.__lastAlertTime < 1500) return;
window.__lastAlertTime = now;

const detectedAttacks = detectAllAttackTypes(value, source);

detectedAttacks.sort((a, b) => {
  if (a.context === "html" && a.type === "XSS") return -1;
  if (a.context === "query" && a.type.includes("SQL")) return -1;
  return 0;
});

    if (!detectedAttacks.length) {
      alerted = false;
      return;
    }

    const severityLevels = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const highest = detectedAttacks.reduce((max, attack) =>
      severityLevels[attack.severity] > severityLevels[max.severity] ? attack : max
    );

    const detectedSources = detectSources(value, window.location.href);

    let finalSource = detectedSources[0];
    if (finalSource === "unknown") {
      finalSource = "dom";
    }

    
    const calculatedScore = calculateDynamicScore(highest.type, finalSource, highest.severity);
    const dynamicSeverity = getSeverityLabel(calculatedScore);

    const detectionEntry = {
      id: crypto.randomUUID(),
      type: highest.type,
      severity: dynamicSeverity, 
      payload: extractSuspiciousPart(value),
      url: window.location.href,
      score: calculatedScore,    
      time: new Date().toISOString(),
      sources: [finalSource],
      source: finalSource
    };


    saveDetection(detectionEntry);

    chrome.runtime.sendMessage({
  type: "PAYLOAD_DETECTED",
  data: {
    success: true,
    alert: detectionEntry
  }
});

    setTimeout(() => { alerted = false; }, 1200);
  }

  function scanValue(value, source = "unknown") {
  if (!PROTECTION_ENABLED) return;
  if (!value || typeof value !== 'string') return;
  if (!userInteracted && source !== "url") return;
  if (isLikelyCSS(value) && !/<form/i.test(value)) return;

  triggerAlert(value, source);
}

  function detectUrlAttacksOnLoad() {
  try {
    if (!PROTECTION_ENABLED) return;
    if (window.self !== window.top) return;

    const decodedQuery = decodeURIComponent(window.location.search || "");
    const decodedPath  = decodeURIComponent(window.location.pathname || "");

    if (decodedQuery && decodedQuery.length > 1) {
      const params = new URLSearchParams(window.location.search);
     for (const [key, value] of params.entries()) {
  let decoded = `${key}=${value}`;
  try { decoded = decodeURIComponent(decoded); } catch {}
  triggerAlert(decoded, "url");
}
      return;
    }

    if (decodedPath && decodedPath.length > 1) {
      if (/[.<>{}'";$]|\.{2}\/|%2e%2e/i.test(decodedPath)) {
        triggerAlert(decodedPath, "url");
      }
    }
  } catch (err) {
    console.warn("[URL Detection Error]", err);
  }
}

  detectUrlAttacksOnLoad();

  (function () {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    function onUrlChange() {
      try { detectUrlAttacksOnLoad(); } catch (e) { console.warn("[SPA URL Monitor]", e); }
    }

    history.pushState = function () {
      originalPushState.apply(this, arguments);
      onUrlChange();
    };
    history.replaceState = function () {
      originalReplaceState.apply(this, arguments);
      onUrlChange();
    };
    window.addEventListener("popstate", onUrlChange);
  })();

  // input monitoring
  document.addEventListener('input', e => {
    if (!PROTECTION_ENABLED) return;
    userInteracted = true;
    const el = e.target;
    if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
      scanValue(el.value, "input");

    }
  }, true);

  // DOM mutation monitoring (filtered)
  const observer = new MutationObserver(mutations => {
    if (!PROTECTION_ENABLED) return;
    if (!userInteracted) return;

    mutations.forEach(m => {
      m.addedNodes.forEach(node => {
        if (node.nodeType !== 1) return;
        const tag = (node.tagName || "").toUpperCase();
        if (tag === "SCRIPT" || tag === "STYLE" || tag === "LINK") return;

        const text = (node.textContent || "").slice(0, 220);
        if (!/[<>{}'";]|__schema|\$ne|\.\.\//i.test(text)) return;
        scanValue(text, "dom");

      });
    });
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  function detectCSRFOnSubmit(form) {
  const method = (form.getAttribute("method") || "GET").toUpperCase();
  if (method !== "POST") return null;

  const hasToken = !!form.querySelector(
    'input[name*="csrf" i], input[name*="xsrf" i], input[name*="token" i], input[value][name][value^="eyJ"]'
  );

  if (!hasToken) {
    return {
      id: crypto.randomUUID(),
      type: "CSRF",
      severity: "MEDIUM",
      payload: "POST form without CSRF token",
      url: window.location.href,
      score: null,
      time: new Date().toISOString(),
      sources: ["form"],
      source: "form"
    };
  }
  return null;
}

  // form submissions
 document.addEventListener('submit', e => {
  const form = e.target;
  if (!form) return;

    if (PROTECTION_ENABLED){  const csrfEntry = detectCSRFOnSubmit(form);
  if (csrfEntry) {
    saveDetection(csrfEntry);
    chrome.runtime.sendMessage({ type: "PAYLOAD_DETECTED", data: csrfEntry });
  }} return;
    userInteracted = true;
    if (!form) return;
    const inputs = form.querySelectorAll('input, textarea, select');
    inputs.forEach(input => {
      if (input.value) scanValue(input.value);
    });
  }, true);

  
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === "FORCE_SCAN") {
      try {
        if (!PROTECTION_ENABLED) {
          sendResponse({ ok: false, disabled: true });
          return;
        }
        userInteracted = true;
        detectUrlAttacksOnLoad();
        sendResponse({ ok: true });
      } catch (e) {
        console.warn("[FORCE_SCAN error]", e);
        sendResponse({ ok: false, error: String(e) });
      }
    }
    return true;
  });
})();
