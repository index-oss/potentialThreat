// rules.js - Ultimate SAST Engine (Black Hat Mindset)

export const rules = [
  // 🔴 1. SENSITIVE DATA & SECRETS (Hardcoded DBs, APIs, Passwords)
  {
    name: "Exposed Database URI / Credentials",
    pattern: /(mongodb(?:\+srv)?:\/\/[^'"`]+|postgres:\/\/[^'"`]+|mysql:\/\/[^'"`]+|redis:\/\/[^'"`]+)/i,
    severity: "CRITICAL",
    description: "Hardcoded Database connection strings found. Complete infrastructure compromise possible."
  },
  {
    name: "Hardcoded Cloud/API Secrets",
    pattern: /(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24})/i,
    severity: "CRITICAL",
    description: "High-value API keys (AWS, Stripe, GitHub, Slack) exposed in source code."
  },
  {
    name: "Hardcoded JWT Secret / Passwords",
    pattern: /(jwt_secret|secret_key|secretkey|password|db_pass)\s*[:=]\s*['"`][a-zA-Z0-9\-_@!#]{8,}['"`]/i,
    severity: "HIGH",
    description: "Hardcoded application secrets allow token forgery and unauthorized access."
  },

  // 🔴 2. MASS ASSIGNMENT & DATA DESTRUCTION (Mass Deletion)
  {
    name: "Mass Deletion / Insecure Bulk Operations",
    pattern: /(deleteMany|remove|destroy)\s*\(\s*(req\.body|req\.query|req\.params|{})/i,
    severity: "CRITICAL",
    description: "Passing unvalidated user input to bulk delete operations. Hacker can wipe the database."
  },
  {
    name: "Mass Assignment / Parameter Tampering",
    pattern: /(Object\.assign\s*\(\s*\{\}\s*,\s*req\.body|updateMany\s*\(\s*.*,\s*req\.body)/i,
    severity: "HIGH",
    description: "Directly assigning request body to objects/DB. Hacker can overwrite admin privileges or internal fields."
  },

  // 🔴 3. SSRF & CSRF (Server/Cross-Site Request Forgery)
  {
    name: "SSRF (Server-Side Request Forgery)",
    pattern: /(fetch|axios(\.get|\.post)?|http\.get|https\.request|request|got|node-fetch)\s*\(\s*[^,]*\b(req\.query|req\.body|req\.params)/i,
    severity: "CRITICAL",
    description: "Server makes external HTTP requests based on user input. Hacker can scan internal networks or AWS metadata."
  },
  {
    name: "Disabled CSRF Protection",
    pattern: /(csrf\s*\(\s*\{\s*ignoreMethods|csurf\s*\(\s*\{\s*ignore)/i,
    severity: "MEDIUM",
    description: "CSRF protection explicitly bypassed or disabled for sensitive routes."
  },

  // 🔴 4. PROTOTYPE POLLUTION & RE-DOS (Advanced Logic Flaws)
  {
    name: "Prototype Pollution",
    pattern: /(lodash\.merge|deepmerge|Object\.assign|util\._extend)\s*\(\s*[^,]+,\s*(req\.body|req\.query|JSON\.parse)/i,
    severity: "HIGH",
    description: "Merging untrusted data into objects can pollute the prototype chain, leading to RCE or logic bypass."
  },
  {
    name: "ReDoS (Regular Expression Denial of Service)",
    pattern: /(new\s+RegExp\s*\(\s*(req\.body|req\.query|req\.params)|req\.body\..*\.match\s*\()/i,
    severity: "HIGH",
    description: "Creating Regex from user input. A crafted string can freeze the Node.js event loop."
  },

  // 🔴 5. PATH TRAVERSAL, LFI & FILE UPLOADS
  {
    name: "Path Traversal / Local File Inclusion (LFI)",
    pattern: /(fs\.(readFile|readFileSync|createReadStream|unlink|unlinkSync)|path\.(join|resolve))\s*\(\s*[^,]*\b(req\.query|req\.body|req\.params)/i,
    severity: "CRITICAL",
    description: "User input used in file paths. Hacker can read /etc/passwd or delete server files."
  },
  {
    name: "Insecure File Upload Handlers",
    pattern: /(req\.files\..*\.mv\s*\(|fs\.createWriteStream\s*\(\s*req\.files)/i,
    severity: "HIGH",
    description: "Moving uploaded files directly to disk without strict extension and MIME-type validation. Can lead to webshells."
  },

  // 🔴 6. INJECTION (XSS, HTML, Template, SQL/NoSQL, Command)
  {
    name: "HTML Injection / XSS",
    pattern: /(\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML|document\.write|dangerouslySetInnerHTML|v-html)/i,
    severity: "HIGH",
    description: "Raw HTML injected into DOM/Templates. Hacker can execute arbitrary JavaScript in victim's browser."
  },
  {
    name: "NoSQL / SQL Injection",
    pattern: /(find|findOne|findById|update|sequelize\.query|db\.query|mongoose\.model)\s*\(\s*.*(req\.body|req\.query|req\.params).*\)/i,
    severity: "HIGH",
    description: "Raw user input in DB queries. Hacker can bypass auth using {\"$gt\": \"\"} payloads."
  },
  {
    name: "OS Command Injection / RCE",
    pattern: /(exec|execSync|spawn|spawnSync|child_process)\s*\(\s*[^,]*\b(req\.body|req\.query|req\.params)/i,
    severity: "CRITICAL",
    description: "User input in system commands. Complete server takeover."
  },

  // 🔴 7. MISCONFIGURATION & BROKEN ACCESS CONTROL
  {
    name: "Insecure CORS Policy",
    pattern: /(cors\s*\(\s*\{\s*origin\s*:\s*['"`]\*['"`]|Access-Control-Allow-Origin['"`]\s*,\s*['"`]\*['"`])/i,
    severity: "MEDIUM",
    description: "CORS allows all origins. Malicious sites can read sensitive API responses."
  },
  {
    name: "Admin / Privilege Escalation",
    pattern: /(req\.(user|body|query)\.role\s*=\s*|isAdmin|role\s*[=:]\s*['"`]admin['"`])/i,
    severity: "HIGH",
    description: "Directly checking, setting, or leaking admin privileges. Potential vertical privilege escalation."
  },
  {
    name: "Dynamic Code Execution (Eval)",
    pattern: /(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*req\.(body|query))/i,
    severity: "CRITICAL",
    description: "Executing strings as JavaScript. Hacker can run arbitrary code."
  }
];

export function scanCode(code, filePath) {
  const findings = [];
  const lines = code.split('\n');

  rules.forEach(rule => {
    lines.forEach((line, index) => {
      // Clean up the line for accurate matching
      const trimmedLine = line.trim();
      
      // KACHRA FILTER: Ignore single-line comments and console.logs
      if (
        trimmedLine.startsWith('//') || 
        trimmedLine.includes('console.log') || 
        trimmedLine.includes('console.error')
      ) {
        return; // Skip this line
      }

      // Check against the offensive rule patterns
      if (rule.pattern.test(line)) {
        findings.push({
          file: filePath,
          line: index + 1,
          snippet: trimmedLine,
          name: rule.name,
          severity: rule.severity,
          description: rule.description
        });
      }
    });
  });
  
  return findings;
}
