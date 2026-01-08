
class ZGSScoringEngine {
  static calculate(threat) {
    // 1. Attack Vector based on threat.vector
    const attackVector = this.getAttackVector(threat.vector);
    
    // 2. Attack Complexity based on threat.type
    const attackComplexity = this.getAttackComplexity(threat.type);
    
    // 3. User Interaction based on threat.type
    const userInteraction = this.getUserInteraction(threat.type);
    
    // 4. Impact based on threat.severity and threat.type
    const impact = this.getImpact(threat.severity, threat.type);
    
    // ZGS Score Calculation (Simplified and transparent)
    const exploitability = attackVector.score * attackComplexity.score * userInteraction.score;
    const impactScore = (impact.confidentiality.score + impact.integrity.score + impact.availability.score) / 3;
    const finalScore = (exploitability + impactScore) * 5; // Scale to 0-10
    
    // Cap score at 10.0
    const cappedScore = Math.min(10.0, parseFloat(finalScore.toFixed(1)));
    
    return {
      score: cappedScore,
      severity: this.getSeverity(cappedScore),
      vector: this.buildVectorString(
        attackVector.label,
        attackComplexity.label,
        userInteraction.label,
        impact.confidentiality.label,
        impact.integrity.label,
        impact.availability.label
      ),
      metrics: {
        attackVector,
        attackComplexity,
        userInteraction,
        impact
      },
      calculation: {
        exploitability: parseFloat(exploitability.toFixed(2)),
        impactScore: parseFloat(impactScore.toFixed(2)),
        formula: 'ZGS Score = (AV × AC × UI + (C+I+A)/3) × 5'
      }
    };
  }
  
  static getAttackVector(vector) {
    const vectors = {
      'Network': { label: 'N', score: 1.0, description: 'Network accessible attack' },
      'Local': { label: 'L', score: 0.7, description: 'Requires local access' },
      'Physical': { label: 'P', score: 0.4, description: 'Requires physical access' }
    };
    
    // Mapping from threat.vector
    const vectorStr = String(vector || '').toLowerCase();
    
    if (vectorStr.includes('url') || vectorStr.includes('sql') || vectorStr.includes('ssrf') || 
        vectorStr.includes('xss') || vectorStr.includes('dom') || vectorStr.includes('input')) {
      return vectors.Network;
    } else if (vectorStr.includes('local') || vectorStr.includes('file') || vectorStr.includes('path')) {
      return vectors.Local;
    } else {
      return vectors.Network; // Default assumption for web attacks
    }
  }
  
  static getAttackComplexity(attackType) {
    const complexities = {
      'Low': { label: 'L', score: 1.0, description: 'Common, well-known attack' },
      'Medium': { label: 'M', score: 0.7, description: 'Moderate complexity' },
      'High': { label: 'H', score: 0.4, description: 'Complex attack requiring special conditions' }
    };
    
    const type = String(attackType || '').toLowerCase();
    
    // SQL Injection, XSS, Path Traversal - Common and well-known
    if (type.includes('sql') || type.includes('xss') || type.includes('path traversal')) {
      return complexities.Low;
    }
    
    // Command Injection, RCE - Moderate complexity
    else if (type.includes('command') || type.includes('rce') || type.includes('lfi')) {
      return complexities.Medium;
    }
    
    // SSRF, XXE, CSRF - Higher complexity
    else if (type.includes('ssrf') || type.includes('xxe') || type.includes('csrf')) {
      return complexities.High;
    }
    
    // Default
    return complexities.Medium;
  }
  
  static getUserInteraction(attackType) {
    const interactions = {
      'None': { label: 'N', score: 1.0, description: 'No user interaction required' },
      'Required': { label: 'R', score: 0.6, description: 'Requires user interaction' }
    };
    
    const type = String(attackType || '').toLowerCase();
    
    // XSS and CSRF require user interaction
    if (type.includes('xss') || type.includes('csrf')) {
      return interactions.Required;
    }
    
    // Most other attacks don't require user interaction
    return interactions.None;
  }
  
  static getImpact(severity, attackType) {
    const type = String(attackType || '').toLowerCase();
    const sev = String(severity || 'MEDIUM').toUpperCase();
    
    // Default impact scores
    let cScore = 0.5; // Confidentiality
    let iScore = 0.5; // Integrity
    let aScore = 0.3; // Availability
    
    // Adjust based on attack type
    if (type.includes('sql') || type.includes('injection')) {
      cScore = 0.9; // Data theft
      iScore = 0.8; // Data manipulation
    } else if (type.includes('xss')) {
      iScore = 0.8; // Session hijacking, defacement
    } else if (type.includes('rce') || type.includes('command')) {
      cScore = 1.0; // Full system access
      iScore = 1.0;
      aScore = 0.8;
    } else if (type.includes('path') || type.includes('lfi')) {
      cScore = 0.8; // File disclosure
    } else if (type.includes('ssrf')) {
      cScore = 0.7; // Internal network access
    } else if (type.includes('csrf')) {
      iScore = 0.7; // Unauthorized actions
    }
    
    // Adjust based on severity level
    if (sev === 'CRITICAL') {
      cScore = Math.min(1.0, cScore * 1.3);
      iScore = Math.min(1.0, iScore * 1.3);
      aScore = Math.min(1.0, aScore * 1.3);
    } else if (sev === 'HIGH') {
      cScore = Math.min(1.0, cScore * 1.1);
      iScore = Math.min(1.0, iScore * 1.1);
    } else if (sev === 'LOW') {
      cScore *= 0.7;
      iScore *= 0.7;
      aScore *= 0.7;
    }
    
    // Convert to labels
    const toLabel = (score) => {
      if (score >= 0.8) return 'H';
      if (score >= 0.4) return 'M';
      return 'L';
    };
    
    return {
      confidentiality: { label: toLabel(cScore), score: cScore },
      integrity: { label: toLabel(iScore), score: iScore },
      availability: { label: toLabel(aScore), score: aScore }
    };
  }
  
  static buildVectorString(av, ac, ui, c, i, a) {
    return `ZGS:AV=${av};AC=${ac};UI=${ui};C=${c};I=${i};A=${a}`;
  }
  
  static getSeverity(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 1.0) return 'LOW';
    return 'INFO';
  }
  
  static getMetricDescription(metric, value) {
    const descriptions = {
      'AV': {
        'N': 'Network-accessible attack vector',
        'L': 'Local access required',
        'P': 'Physical access required'
      },
      'AC': {
        'L': 'Low complexity - Common attack patterns',
        'M': 'Medium complexity - Requires specific conditions',
        'H': 'High complexity - Complex exploitation required'
      },
      'UI': {
        'N': 'No user interaction required',
        'R': 'Requires user interaction'
      },
      'C': {
        'H': 'High confidentiality impact - Data disclosure',
        'M': 'Medium confidentiality impact',
        'L': 'Low confidentiality impact'
      },
      'I': {
        'H': 'High integrity impact - Data manipulation',
        'M': 'Medium integrity impact',
        'L': 'Low integrity impact'
      },
      'A': {
        'H': 'High availability impact - Service disruption',
        'M': 'Medium availability impact',
        'L': 'Low availability impact'
      }
    };
    
    return descriptions[metric]?.[value] || 'Not assessed';
  }
  
  static explainCalculation(scoreResult) {
    return {
      formula: 'ZGS Score = (AV × AC × UI + (C + I + A)/3) × 5',
      components: {
        attackVector: `${scoreResult.metrics.attackVector.label} (${scoreResult.metrics.attackVector.score})`,
        attackComplexity: `${scoreResult.metrics.attackComplexity.label} (${scoreResult.metrics.attackComplexity.score})`,
        userInteraction: `${scoreResult.metrics.userInteraction.label} (${scoreResult.metrics.userInteraction.score})`,
        impact: {
          confidentiality: `${scoreResult.metrics.impact.confidentiality.label} (${scoreResult.metrics.impact.confidentiality.score.toFixed(2)})`,
          integrity: `${scoreResult.metrics.impact.integrity.label} (${scoreResult.metrics.impact.integrity.score.toFixed(2)})`,
          availability: `${scoreResult.metrics.impact.availability.label} (${scoreResult.metrics.impact.availability.score.toFixed(2)})`
        }
      },
      calculation: `(${scoreResult.metrics.attackVector.score} × ${scoreResult.metrics.attackComplexity.score} × ${scoreResult.metrics.userInteraction.score} + (${scoreResult.metrics.impact.confidentiality.score.toFixed(2)} + ${scoreResult.metrics.impact.integrity.score.toFixed(2)} + ${scoreResult.metrics.impact.availability.score.toFixed(2)})/3) × 5 = ${scoreResult.score.toFixed(1)}`
    };
  }
    static getCVSSColor(score) {
    
    if (score >= 9.0) return '#FF6A6A';  // Critical
    if (score >= 7.0) return '#FF8C00';  // High 
    if (score >= 4.0) return '#FFC14D';  // Medium 
    if (score >= 0.1) return '#00FFAA';  // Low 
    return '#94A3B8';                     // None/Info 
  }

}