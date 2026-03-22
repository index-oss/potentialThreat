// rules.js
// ================================
// Full-stack OWASP Top 10 + Advanced JS/HTML Scanner Rules
// ================================

// Each rule has: name, regex pattern, severity, description
export const rules = [
  // ================================
  // XSS / DOM Injection
  // ================================
  {
    name: "DOM Injection / XSS - innerHTML",
    pattern: /(\.innerHTML\s*=|\.outerHTML\s*=)/i,
    severity: "HIGH",
    description: "User input assigned directly to innerHTML/outerHTML may allow XSS."
  },
  {
    name: "DOM Injection - insertAdjacentHTML",
    pattern: /\.insertAdjacentHTML\s*\(/i,
    severity: "HIGH",
    description: "User input inserted into DOM using insertAdjacentHTML without sanitization."
  },
  {
    name: "Dynamic Code Execution - eval/Function/setTimeout",
    pattern: /(eval|Function|setTimeout\s*\(|setInterval\s*\()/i,
    severity: "HIGH",
    description: "Dynamic execution of strings may allow code injection."
  },
  {
    name: "DOM Event Handler Injection",
    pattern: /\.on(click|submit|mouseover|keydown)\s*=\s*.*\b(userInput|input)\b/i,
    severity: "HIGH",
    description: "Assigning user input to DOM event handlers can lead to XSS."
  },

  // ================================
  // Template Injection
  // ================================
  {
    name: "React Template Injection",
    pattern: /dangerouslySetInnerHTML/i,
    severity: "HIGH",
    description: "React dangerouslySetInnerHTML may inject unsafe content."
  },
  {
    name: "Vue Template Injection",
    pattern: /v-html/i,
    severity: "HIGH",
    description: "Vue v-html directive may render unsafe user content."
  },
  {
    name: "Handlebars Template Injection",
    pattern: /\{\{\{.*\}\}\}/i,
    severity: "HIGH",
    description: "Handlebars triple mustache may render raw HTML from untrusted input."
  },
  {
    name: "Inline <script> in HTML",
    pattern: /<script.*>.*<\/script>/i,
    severity: "HIGH",
    description: "Inline script tags may contain unsafe code."
  },

  // ================================
  // API Calls / Frontend Exploits
  // ================================
  {
    name: "Fetch with User-Controlled URL",
    pattern: /\bfetch\s*\(\s*.*userInput.*\)/i,
    severity: "HIGH",
    description: "User input used in fetch URL may allow SSRF / API abuse."
  },
  {
    name: "Axios / XHR User Input",
    pattern: /\b(axios|get|post|put|delete)\s*\(.*userInput.*\)/i,
    severity: "HIGH",
    description: "User input in frontend API calls may bypass authorization or cause injections."
  },

  // ================================
  // DB / Command Injection
  // ================================
  {
    name: "MongoDB Injection",
    pattern: /(find|findOne|update|remove|deleteMany)\s*\(.*\b(userInput|req\.body|req\.query)\b.*\)/i,
    severity: "HIGH",
    description: "User input directly used in MongoDB queries may allow NoSQL injection."
  },
  {
    name: "SQL / Raw Query Injection",
    pattern: /(sequelize\.query|knex\.raw|db\.query)\s*\(.*\b(userInput|req\.body|req\.query)\b.*\)/i,
    severity: "HIGH",
    description: "User input used in raw SQL queries may allow SQL injection."
  },
  {
    name: "Command Injection - child_process",
    pattern: /(exec|execSync|spawn|spawnSync)\s*\(.*\b(userInput|req\.body|req\.query)\b.*\)/i,
    severity: "HIGH",
    description: "User input in child_process commands may allow OS command execution."
  },

  // ================================
  // Broken Access Control / IDOR
  // ================================
  {
    name: "Broken Access Control / Admin Bypass",
    pattern: /(isAdminUser|user\.role|user\.isAdmin)/i,
    severity: "HIGH",
    description: "Admin roles checked incorrectly or hardcoded may allow privilege escalation."
  },
  {
    name: "IDOR - Direct Object Reference",
    pattern: /(req\.params\.id|req\.query\.id|req\.body\.id)/i,
    severity: "HIGH",
    description: "Direct object references without authorization check may allow data access."
  },
  {
    name: "Dangerous DB Operation with User Input",
    pattern: /(deleteMany|update|remove|drop)\s*\(.*\b(userInput|req\.body|req\.query)\b.*\)/i,
    severity: "HIGH",
    description: "Database operation might delete or modify data using unvalidated input."
  },

  // ================================
  // Auth / Session
  // ================================
  {
    name: "JWT / Auth Misuse",
    pattern: /(jwt\.sign|jwt\.verify)/i,
    severity: "HIGH",
    description: "JWT usage may be insecure if keys or verification are weak."
  },
  {
    name: "Plain Password / LocalStorage",
    pattern: /(localStorage|sessionStorage).*password/i,
    severity: "HIGH",
    description: "Storing passwords in localStorage / sessionStorage is insecure."
  },

  // ================================
  // Sensitive Data Exposure
  // ================================
  {
    name: "Hardcoded Secrets / API Keys",
    pattern: /(process\.env|api_key|secret|password)/i,
    severity: "HIGH",
    description: "Hardcoded secrets or env keys may expose sensitive data."
  },

  // ================================
  // Security Misconfigurations
  // ================================
  {
    name: "CORS Misconfiguration",
    pattern: /cors\s*\(\s*\{\s*origin\s*:\s*["']?\*["']?\s*\}\s*\)/i,
    severity: "HIGH",
    description: "CORS configured to allow all origins may expose APIs publicly."
  },
  {
    name: "Missing Security Headers",
    pattern: /(helmet|res\.setHeader\(['"]Content-Security-Policy|X-Frame-Options)/i,
    severity: "MEDIUM",
    description: "Missing critical HTTP headers reduces security."
  },
  {
    name: "Verbose Error Messages",
    pattern: /(console\.log|console\.error|res\.send\(error\.message)/i,
    severity: "MEDIUM",
    description: "Verbose error messages may leak sensitive info."
  },

  // ================================
  // Logging / Exceptions
  // ================================
  {
    name: "Sensitive Logging",
    pattern: /(console\.log|console\.error).*password|token|api/i,
    severity: "MEDIUM",
    description: "Sensitive data should not be logged in console."
  },
  {
    name: "Missing Try/Catch",
    pattern: /(await .*;)/i, // simple heuristic for unwrapped async calls
    severity: "MEDIUM",
    description: "Async operations without try/catch may crash server or leak info."
  },

  // ================================
  // Dependencies / Supply Chain
  // ================================
  {
    name: "Outdated / Unsafe Dependencies",
    pattern: /(require|import).*(express|mongoose|axios|react)/i,
    severity: "MEDIUM",
    description: "Check for outdated or vulnerable libraries."
  },
  {
    name: "Unsafe CDN / External Scripts",
    pattern: /https?:\/\/cdn.*\.js/i,
    severity: "MEDIUM",
    description: "Loading JS from untrusted CDN may lead to supply chain attacks."
  },

  // ================================
  // Logic Flaws / Design Issues
  // ================================
  {
    name: "Hardcoded Roles / Flags",
    pattern: /(isAdmin\s*=\s*true|role\s*=\s*'admin')/i,
    severity: "HIGH",
    description: "Hardcoded roles may allow privilege escalation."
  },
  {
    name: "Unrestricted File Uploads",
    pattern: /(req\.files|multer)/i,
    severity: "HIGH",
    description: "File upload without validation may allow RCE or data overwrite."
  },
  {
    name: "Client-Side Only Validation",
    pattern: /(if\s*\(.*document\.getElementById|addEventListener.*submit)/i,
    severity: "MEDIUM",
    description: "Relying only on client-side validation is insecure."
  }
];

// ================================
// Scan function
// ================================
export function scanCode(code, filePath) {
  const findings = [];
  rules.forEach(rule => {
    if (rule.pattern.test(code)) {
      findings.push({
        file: filePath,
        name: rule.name,
        severity: rule.severity,
        description: rule.description
      });
    }
  });
  return findings;
}
