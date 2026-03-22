// rules.js - Advanced OWASP Top 10 scanning rules for Node/Express

export const rules = [
  // 1. Broken Access Control
  {
    name: "Broken Access Control / Admin Bypass",
    pattern: /isAdminUser\(|req\.query\.userEmail|req\.body\.userEmail/i,
    severity: "HIGH",
    description: "User-supplied email or missing auth check may allow privilege escalation."
  },
  // 2. IDOR
  {
    name: "IDOR - Insecure Direct Object Reference",
    pattern: /req\.params\.id|req\.query\.id/i,
    severity: "HIGH",
    description: "Direct object references without authorization check can expose data."
  },
  // 3. Dangerous DB Operation
  {
    name: "Dangerous DB Operation",
    pattern: /(deleteMany|deleteOne|update|remove|drop|insertMany)/i,
    severity: "HIGH",
    description: "Database operation using unvalidated input may compromise data integrity."
  },
  // 4. XSS / Stored XSS
  {
    name: "XSS / Stored XSS",
    pattern: /res\.send\(|res\.write\(|innerHTML|document\.write/i,
    severity: "HIGH",
    description: "User input outputted without sanitization may allow XSS attacks."
  },
  // 5. Security Misconfiguration
  {
    name: "CORS / Misconfiguration",
    pattern: /cors\(\{[^}]*\*\}/i,
    severity: "MEDIUM",
    description: "CORS allowing all origins or misconfigured headers."
  },
  {
    name: "Verbose Error / Stack Trace Exposure",
    pattern: /(console\.error|console\.log|err\.stack)/i,
    severity: "MEDIUM",
    description: "Exposing stack traces or verbose errors may reveal sensitive information."
  },
  // 6. Injection (SQL / NoSQL / Command)
  {
    name: "Injection Flaw",
    pattern: /(find\(|findOne\(|where\(|exec\(|query\(|execSync\(|child_process\.exec)/i,
    severity: "HIGH",
    description: "User-controlled input in DB queries or shell commands can cause injection attacks."
  },
  // 7. Authentication / Weak Login
  {
    name: "Authentication Weakness",
    pattern: /(req\.body\.password|bcrypt\.compare|jwt\.sign)/i,
    severity: "HIGH",
    description: "Weak or missing authentication mechanisms or improper token handling."
  },
  // 8. Sensitive Data Exposure
  {
    name: "Sensitive Data Exposure",
    pattern: /(process\.env\.API_KEY|process\.env\.PASSWORD|Buffer\.from\(|atob\()/i,
    severity: "HIGH",
    description: "Secrets, keys, or passwords may be exposed in code or logs."
  },
  // 9. Logging & Alerting Failures
  {
    name: "Logging / Alerting Missing",
    pattern: /console\.log\(|logger\.info|logger\.error/i,
    severity: "MEDIUM",
    description: "Logging without proper security context or alerting may hide incidents."
  },
  // 10. Software / Dependency Risk
  {
    name: "Outdated / Vulnerable Dependencies",
    pattern: /(require\(['"]express['"]\)|require\(['"]mongoose['"]\))/i,
    severity: "MEDIUM",
    description: "Check for outdated packages or vulnerable modules in dependencies."
  }
];

// Scan function: returns array of matched rules
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
