
const ZGSTemplates = {
  //  SQL INJECTION 
  'SQL Injection': {
    attackType: 'SQL Injection',
    severityColor: '#B20000',
    defaultScore: 9.8,
    cvssVector: 'ZGS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L',
    exploitability: {
      attackVector: { value: 'N', desc: 'Exploitable remotely over the internet.' },
      attackComplexity: { value: 'L', desc: 'Common, well-known attack technique.' },
      privilegesRequired: { value: 'N', desc: 'Attacker needs no prior access.' },
      userInteraction: { value: 'N', desc: 'No user interaction required.' },
      scope: { value: 'U', desc: 'Attack does not affect systems beyond the target.' }
    },
    impact: {
      confidentiality: { value: 'H', desc: 'Total disclosure of all sensitive database data.' },
      integrity: { value: 'H', desc: 'Attacker can modify, delete, or inject any data.' },
      availability: { value: 'L', desc: 'Possible performance degradation, but no total outage.' }
    },
    description: 'This SQL injection vulnerability allows attackers to manipulate backend SQL queries by injecting malicious payloads through user-controlled input fields. This may lead to extraction of user credentials and full compromise of database integrity.',
    recommendations: {
      general: [
        'Use parameterized queries (prepared statements) instead of string concatenation.',
        'Implement strict input validation and allow-list filtering.',
        'Deploy a Web Application Firewall (WAF) with SQLi rules.',
        'Apply the principle of least privilege to database accounts.'
      ],
      references: ['OWASP A03: Injection', 'CWE-89: SQL Injection']
    }
  },
  
  //  XSS 
  'XSS': {
    attackType: 'Cross-Site Scripting',
    severityColor: '#FF5A33',
    defaultScore: 8.5,
    cvssVector: 'ZGS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N',
    exploitability: {
      attackVector: { value: 'N', desc: 'Exploitable remotely via web interface.' },
      attackComplexity: { value: 'L', desc: 'Simple script injection with no special conditions.' },
      privilegesRequired: { value: 'N', desc: 'No privileges required for reflected/stored XSS.' },
      userInteraction: { value: 'R', desc: 'Victim must interact with malicious content.' },
      scope: { value: 'U', desc: 'Affects user\'s session within the same security scope.' }
    },
    impact: {
      confidentiality: { value: 'H', desc: 'Session cookies, tokens, and sensitive user data can be stolen.' },
      integrity: { value: 'L', desc: 'Content can be modified, but not system data.' },
      availability: { value: 'N', desc: 'Typically does not affect system availability.' }
    },
    description: 'This XSS vulnerability enables attackers to inject malicious scripts into web pages viewed by other users. This can lead to session hijacking, credential theft, defacement, or redirection to malicious sites.',
    recommendations: {
      general: [
        'Implement proper output encoding for HTML, JavaScript, and URL contexts.',
        'Use Content Security Policy (CSP) headers to restrict script sources.',
        'Validate and sanitize all user inputs before rendering.',
        'Set HttpOnly and Secure flags on session cookies.'
      ],
      references: ['OWASP A03: Injection', 'CWE-79: Cross-site Scripting']
    }
  },
  
  //  RCE 
  'RCE': {
    attackType: 'Remote Code Execution',
    severityColor: '#B20000',
    defaultScore: 9.9,
    cvssVector: 'ZGS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    exploitability: {
      attackVector: { value: 'N', desc: 'Exploitable remotely without physical access.' },
      attackComplexity: { value: 'L', desc: 'Public exploit often available for known vulnerabilities.' },
      privilegesRequired: { value: 'N', desc: 'No authentication required for unauthenticated RCE.' },
      userInteraction: { value: 'N', desc: 'No user interaction needed.' },
      scope: { value: 'C', desc: 'Can lead to full system compromise beyond the application.' }
    },
    impact: {
      confidentiality: { value: 'H', desc: 'Complete system access and data exfiltration.' },
      integrity: { value: 'H', desc: 'Full system compromise and arbitrary code execution.' },
      availability: { value: 'H', desc: 'Can cause complete system shutdown or service disruption.' }
    },
    description: 'This critical vulnerability allows attackers to execute arbitrary code on the target system remotely. Successful exploitation leads to full system compromise, data theft, lateral movement, and complete control over the affected host.',
    recommendations: {
      general: [
        'Immediately patch the affected software or system component.',
        'Implement network segmentation to limit blast radius.',
        'Use application allowlisting to prevent unauthorized code execution.',
        'Deploy intrusion detection/prevention systems (IDS/IPS).'
      ],
      references: ['OWASP A06: Vulnerable Components', 'CWE-78: OS Command Injection']
    }
  }
};

ZGSTemplates.getTemplate = function(attackType) {
  const normalizedType = String(attackType || '').trim();
  
  for (const [key, template] of Object.entries(this)) {
    if (key === 'getTemplate') continue;
    
    if (normalizedType.toLowerCase().includes(key.toLowerCase()) || 
        key.toLowerCase().includes(normalizedType.toLowerCase())) {
      return template;
    }
  }
  
  return {
    attackType: attackType || 'Unknown Attack',
    severityColor: '#FF5A33',
    defaultScore: 6.0,
    cvssVector: 'ZGS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:L',
    exploitability: {
      attackVector: { value: 'N', desc: 'Network accessible attack.' },
      attackComplexity: { value: 'L', desc: 'Common attack patterns.' },
      privilegesRequired: { value: 'N', desc: 'No privileges required.' },
      userInteraction: { value: 'N', desc: 'No user interaction required.' },
      scope: { value: 'U', desc: 'Attack does not affect systems beyond the target.' }
    },
    impact: {
      confidentiality: { value: 'M', desc: 'Medium confidentiality impact.' },
      integrity: { value: 'M', desc: 'Medium integrity impact.' },
      availability: { value: 'L', desc: 'Low availability impact.' }
    },
    description: 'Security threat detected. Further investigation recommended.',
    recommendations: {
      general: ['Investigate the payload', 'Review security logs', 'Update security controls'],
      references: []
    }
  };
};