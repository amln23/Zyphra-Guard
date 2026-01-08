
from flask import Flask, request, jsonify
import numpy as np
import pandas as pd
import json
import re
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

ALERT_BUFFER = []
MAX_ALERTS = 10

print("Loading optimized detection system...")

# Global Model Containers

models_loaded = False
feature_order = []
loaded_models = {}

try:
    import sklearn
    from sklearn.preprocessing import StandardScaler
    import pickle

    print("Core libraries loaded successfully")

    # Load Scaler
    try:
        with open('cic_scaler.pkl', 'rb') as f:
            loaded_models['scaler'] = pickle.load(f)
        print("Scaler loaded")
    except:
        print("Using default scaler")
        loaded_models['scaler'] = StandardScaler()
        loaded_models['scaler'].mean_ = np.zeros(41)
        loaded_models['scaler'].scale_ = np.ones(41)

    # Load XGBoost Model
    try:
        with open('xgb_model.pkl', 'rb') as f:
            loaded_models['xgb_model'] = pickle.load(f)
        print("XGBoost model loaded")
    except Exception as e:
        print(f"Failed to load XGBoost: {e}")
        # Continue without model
        loaded_models['xgb_model'] = None

    # Load Feature Order
    try:
        with open('unified_feature_index.json', 'r') as f:
            feature_data = json.load(f)
            feature_order = feature_data.get("feature_order", [])
        print(f"Loaded {len(feature_order)} features")
    except:
        print("Using default feature order")
        feature_order = [f"feature_{i}" for i in range(41)]

    models_loaded = True
    print("All components initialized!")

except Exception as e:
    print(f"Initialization error: {e}")


# ENHANCED HEURISTIC ANALYSIS

# Comprehensive payload patterns
PAYLOAD_PATTERNS = {
    "SQL_INJECTION": [
        (r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", 20),
        (r"union\s+select", 25),
        (r"select\s+.*from", 20),
        (r"--\s*$", 15),
        (r"'.*or.*'", 15),
        (r"information_schema", 20),
        (r"sleep\s*\(", 20),
        (r"drop\s+table", 25),
        (r"insert\s+into", 20),
        (r"update\s+.*set", 20),
        (r"delete\s+from", 20),
        (r"truncate\s+table", 25),
        (r"exec\s*\(|sp_", 20),
        (r"waitfor\s+delay", 20),
        (r"benchmark\s*\(", 20),
        (r"@@version", 15),
        (r"mysql\.|sys\.", 15),
        (r"\/\*.*\*\/", 10),
        (r"'.*--", 15),
        (r"'.*#", 15),
        (r"[\"'`]\s*=\s*[\"'`]", 20),
        (r"and\s+1=1", 15),
        (r"or\s+1=1", 15),
        (r"'\s+or\s+'", 15),
        (r"'\s+and\s+'", 15)
    ],
    
    "XSS": [
        (r"<script[^>]*>", 25),
        (r"javascript:", 20),
        (r"onload\s*=", 20),
        (r"onerror\s*=", 20),
        (r"alert\s*\(", 15),
        (r"document\.cookie", 20),
        (r"innerHTML|outerHTML", 15),
        (r"eval\s*\(", 25),
        (r"<iframe", 20),
        (r"<img.*onerror", 20),
        (r"<svg.*onload", 20),
        (r"expression\s*\(", 15),
        (r"vbscript:", 20),
        (r"data:text\/html", 25),
        (r"document\.write", 15),
        (r"window\.location", 15),
        (r"<body.*onload", 20),
        (r"<input.*onfocus", 15),
        (r"<form.*onsubmit", 15)
    ],
    
    "COMMAND_INJECTION": [
        (r"\b(wget|curl|nc|netcat)\b", 20),
        (r"\b(rm -rf|rm -r)\b", 25),
        (r"\b(bash|sh|zsh|ksh)\b", 20),
        (r"\b(exec|system|passthru|shell_exec)\b", 25),
        (r"`.*`", 20),
        (r"\|\s*sh\b", 20),
        (r"\$\(.+\)", 20),
        (r"python\d?\s+-c", 20),
        (r"perl\s+-e", 20),
        (r"php\s+-r", 20),
        (r"base64\s+-d", 15),
        (r"chmod\s+[0-9]+", 15),
        (r"chown\s+.*root", 20),
        (r"useradd|adduser", 20),
        (r"passwd", 15)
    ],
    
    "PATH_TRAVERSAL": [
        (r"\.\.\/", 20),
        (r"\.\.\\", 20),
        (r"etc/passwd", 25),
        (r"etc/shadow", 25),
        (r"\.htaccess", 15),
        (r"\.env", 15),
        (r"file://", 20),
        (r"proc/self", 20),
        (r"boot\.ini", 20),
        (r"win\.ini", 20),
        (r"system32", 15),
        (r"%2e%2e%2f", 20),
        (r"%2e%2e%5c", 20),
        (r"%252e%252e%252f", 20),
        (r"%c0%ae%c0%ae\/", 20)
    ],
    
    "SSRF": [
        (r"localhost", 15),
        (r"127\.0\.0\.1", 20),
        (r"192\.168\.\d+\.\d+", 20),
        (r"10\.\d+\.\d+\.\d+", 20),
        (r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+", 20),
        (r"169\.254\.169\.254", 25),
        (r"metadata\.google", 25),
        (r"metadata\.aliyun", 25),
        (r"169\.254\.170\.2", 25),
        (r"internal\.api", 20),
        (r"private\.network", 20),
        (r"\.local(?:domain)?\b", 15),
        (r"\.internal\b", 15),
        (r"\.corp\b", 15),
        (r"\.intranet\b", 15)
    ],
    
    "BRUTEFORCE": [
        (r"ftp://|sftp://", 20),
        (r"ssh://", 20),
        (r"user.*pass|pass.*user", 20),
        (r"login.*password", 20),
        (r"auth.*failed", 15),
        (r"connection.*refused", 15),
        (r"too many attempts", 20),
        (r"invalid credentials", 15),
        (r"authentication failed", 15),
        (r"brute.*force", 25),
        (r"password.*guess", 20),
        (r"credential.*stuffing", 25)
    ],
    
    "DOS": [
        (r"flood", 20),
        (r"syn.*ack", 25),
        (r"packet.*storm", 20),
        (r"connection.*overflow", 20),
        (r"rate.*limit.*exceed", 15),
        (r"bandwidth.*exceed", 15),
        (r"request.*flood", 20),
        (r"slowloris", 25),
        (r"ddos", 25),
        (r"denial.*service", 20)
    ],
    
    "CSRF": [
        (r"csrf", 15),
        (r"_token", 15),
        (r"anticsrf", 15),
        (r"csrf_token", 15),
        (r"csrfmiddlewaretoken", 15),
        (r"requestverificationtoken", 15),
        (r"x-csrf-token", 15),
        (r"x-xsrf-token", 15)
    ],
    
    "FTP_SPECIFIC": [
        (r"ftp.*brute", 30),
        (r"ftp.*force", 30),
        (r"port\s+21", 20),
        (r"ftp\s+server", 15),
        (r"anonymous\s+login", 20),
        (r"ftp\s+credentials", 25),
        (r"ftp\s+password", 25),
        (r"ftp\s+user", 20)
    ]
}

def enhanced_heuristic_analysis(input_data):
    """Enhanced heuristic analysis with weighted scoring"""
    results = {
        "detected": False,
        "attack_types": {},
        "total_score": 0,
        "indicators": [],
        "primary_attack": None,
        "confidence": 0
    }
    
    if not input_data:
        return results
    
    # Convert to string
    if isinstance(input_data, dict):
        analysis_text = json.dumps(input_data).lower()
    elif isinstance(input_data, list):
        analysis_text = str(input_data).lower()
    else:
        analysis_text = str(input_data).lower()
    
    # Check each pattern category
    for attack_type, patterns in PAYLOAD_PATTERNS.items():
        type_score = 0
        type_indicators = []
        
        for pattern, weight in patterns:
            try:
                matches = re.finditer(pattern, analysis_text, re.IGNORECASE)
                for match in matches:
                    if match:
                        type_score += weight
                        indicator_text = match.group()
                        if len(indicator_text) > 50:
                            indicator_text = indicator_text[:50] + "..."
                        indicator = f"{attack_type.replace('_', ' ')}: {indicator_text}"
                        if indicator not in type_indicators:
                            type_indicators.append(indicator)
            except:
                continue
        
        if type_score > 0:
            results["attack_types"][attack_type] = {
                "score": min(100, type_score),
                "indicators": type_indicators[:3]
            }
            results["total_score"] += type_score
            results["indicators"].extend(type_indicators[:2])
    
    # Determine primary attack
    if results["attack_types"]:
        results["detected"] = True
        results["total_score"] = min(100, results["total_score"])
        
        # Find primary attack (highest score)
        primary = max(results["attack_types"].items(), key=lambda x: x[1]["score"])
        results["primary_attack"] = primary[0]
        
        # Calculate confidence
        results["confidence"] = min(100, results["total_score"] * 0.8)
    
    return results

# FEATURE-BASED DETECTION

def analyze_features(features):
    """Analyze features for attack patterns"""
    analysis = {
        "suspicious": False,
        "indicators": [],
        "score": 0,
        "attack_types": []
    }
    
    if len(features) < 30:
        return analysis
    
    # Extract key features with safe access
    def safe_get(idx, default=0):
        return features[idx] if idx < len(features) else default
    
    url_len = safe_get(0)
    num_dots = safe_get(1)
    num_slashes = safe_get(2)
    susp_tokens = safe_get(5)
    has_ip = safe_get(6) > 0.5
    query_len = safe_get(11)
    is_https = safe_get(12) > 0.5
    js_eval = safe_get(14)
    login_kw = safe_get(30) > 0.5
    bank_kw = safe_get(33) > 0.5
    
    # FTP/Bruteforce detection
    if has_ip and not is_https:
        analysis["score"] += 30
        analysis["indicators"].append("Direct IP without HTTPS")
        analysis["attack_types"].append("BRUTEFORCE")
        if login_kw:
            analysis["score"] += 20
            analysis["indicators"].append("Login keywords with insecure connection")
    
    # SQL Injection patterns
    if query_len > 100 or susp_tokens > 5:
        analysis["score"] += 25
        analysis["indicators"].append("Suspicious query patterns")
        analysis["attack_types"].append("SQL_INJECTION")
    
    # XSS patterns
    if js_eval > 0 or safe_get(13) > 20:  # js_total_functions
        analysis["score"] += 20
        analysis["indicators"].append("JavaScript exploitation patterns")
        analysis["attack_types"].append("XSS")
    
    # DoS patterns
    if url_len > 200 or num_dots > 15:
        analysis["score"] += 25
        analysis["indicators"].append("Resource exhaustion patterns")
        analysis["attack_types"].append("DOS")
    
    # Phishing patterns
    if (login_kw or bank_kw) and not is_https:
        analysis["score"] += 20
        analysis["indicators"].append("Sensitive content without encryption")
        analysis["attack_types"].append("PHISHING")
    
    # Port scan patterns
    if num_slashes > 20 and has_ip:
        analysis["score"] += 15
        analysis["indicators"].append("Port scanning patterns")
        analysis["attack_types"].append("PORT_SCAN")
    
    if analysis["score"] > 0:
        analysis["suspicious"] = True
        analysis["score"] = min(100, analysis["score"])
    
    return analysis

# UNIFIED DECISION ENGINE

def check_https_security(url):
    if not url:
        return None

    if url.startswith("http://"):
        return {
            "issue": "INSECURE_CONNECTION",
            "severity": "LOW",
            "message": "This page is not using HTTPS. Data may be exposed to attackers.",
            "recommendation": "Avoid entering sensitive information and prefer HTTPS websites."
        }

    return None


def make_final_decision(model_result, heuristic_result, feature_result):
    """Make unified decision based on all detection methods"""
    
    scores = {
        "model": 0,
        "heuristic": 0,
        "features": 0
    }
    
    indicators = []
    attack_types = set()
    
    # Model scoring
    if model_result and "probability_attack" in model_result:
        scores["model"] = model_result["probability_attack"] * 100
    
    # Heuristic scoring
    if heuristic_result and heuristic_result["detected"]:
        scores["heuristic"] = heuristic_result["total_score"]
        indicators.extend(heuristic_result.get("indicators", [])[:3])
        if heuristic_result.get("primary_attack"):
            attack_types.add(heuristic_result["primary_attack"])
    
    # Feature scoring
    if feature_result and feature_result["suspicious"]:
        scores["features"] = feature_result["score"]
        indicators.extend(feature_result.get("indicators", [])[:2])
        attack_types.update(feature_result.get("attack_types", []))
    
    # Calculate total score (weighted 0-100)
    raw_score = (
        scores["model"] * 3.0 +     
        scores["heuristic"] * 4.0 + 
        scores["features"] * 3.0    
    )
    
    zgs_score = round(raw_score, 1) 
    decision = "SAFE"
    severity_label = "LOW"

    if zgs_score >= 9.0:
        decision = "ATTACK"
        severity_label = "CRITICAL"
    elif zgs_score >= 7.0:
        decision = "ATTACK" # or SUSPICIOUS based on preference
        severity_label = "HIGH"
    elif zgs_score >= 4.0:
        decision = "SUSPICIOUS"
        severity_label = "MEDIUM"
    else:
        decision = "SAFE"
        severity_label = "LOW"

    confidence = raw_score / 100.0
       
    # Primary attack type
    primary_attack = "UNKNOWN"
    if attack_types:
        # Prioritize certain attack types
        priority_order = ["SQL_INJECTION", "XSS", "BRUTEFORCE", "COMMAND_INJECTION", 
                         "DOS", "SSRF", "PATH_TRAVERSAL", "PHISHING"]
        for attack in priority_order:
            if attack in attack_types:
                primary_attack = attack
                break
        else:
            primary_attack = list(attack_types)[0]
    
    # Clean up indicators
    if not indicators:
        indicators = ["No specific indicators found"]
    
    return {
        "decision": decision,
        "severity": severity_label,
        "confidence": round(confidence, 3),
        "score": zgs_score,        
        "primary_attack": primary_attack.replace("_", " "),
        "indicators": indicators[:3],
        "breakdown": {
            "model_score": round(scores["model"], 1),
            "heuristic_score": round(scores["heuristic"], 1),
            "feature_score": round(scores["features"], 1)
        }
    }


def push_alert(attack_type, severity, confidence, source="NETWORK"):
    alert = {
        "attack": attack_type,
        "severity": severity,
        "confidence": round(confidence, 2),
        "source": source,
        "timestamp": pd.Timestamp.now().isoformat()
    }

    ALERT_BUFFER.append(alert)

    # Keep buffer size limited
    if len(ALERT_BUFFER) > MAX_ALERTS:
        ALERT_BUFFER.pop(0)

# API ENDPOINTS

@app.route('/')
def home():
    return jsonify({
        'status': 'running',
        'system': 'Unified Cyber Attack Detection',
        'version': '5.0',
        'endpoints': {
            '/predict': 'Full analysis with all detectors',
            '/analyze': 'Heuristic analysis only',
            '/scan': 'Quick scan for extensions',
            '/health': 'System status'
        }
    })

@app.route('/health')
def health():
    xgb_loaded = loaded_models.get('xgb_model') is not None
    return jsonify({
        'status': 'healthy',
        'models_loaded': models_loaded,
        'xgb_available': xgb_loaded,
        'features': len(feature_order),
        'pattern_categories': len(PAYLOAD_PATTERNS)
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    """Heuristic analysis endpoint"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        result = enhanced_heuristic_analysis(data)
        
        return jsonify({
            'success': True,
            'analysis': result,
            'recommendation': 'Immediate investigation recommended' if result['detected'] else 'No threats detected'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/predict', methods=['POST'])
def predict():
    """Unified prediction endpoint"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No input data'}), 400
        url = data.get('url', '')
        https_warning = check_https_security(url)
        
        # 1. HEURISTIC ANALYSIS
        
        heuristic_result = enhanced_heuristic_analysis(data)
        
        # 2. EXTRACT FEATURES
    
        features_dict = {}
        
        # Try to extract from features field
        if isinstance(data, dict) and 'features' in data:
            for key, value in data['features'].items():
                try:
                    features_dict[key] = float(value)
                except:
                    features_dict[key] = 0.0
        else:
            # Generate basic features from URL/data
            url = data.get('url', '') if isinstance(data, dict) else ''
            features_dict['url_length'] = len(url)
            features_dict['num_dots'] = url.count('.')
            features_dict['num_slashes'] = url.count('/')
            features_dict['has_ip_address'] = 1.0 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0.0
            features_dict['is_https'] = 1.0 if url.startswith('https://') else 0.0
            
            # Check keywords
            url_lower = url.lower()
            for kw in ['login', 'signin', 'bank', 'pay', 'wallet', 'verify', 'password']:
                if kw in url_lower:
                    features_dict[f'has_{kw}_keyword'] = 1.0
        
        # Build feature vector
        final_features = []
        for feature_name in feature_order:
            final_features.append(features_dict.get(feature_name, 0.0))
        final_features = (final_features + [0.0] * 41)[:41]
        
        
        # 3. FEATURE-BASED ANALYSIS
        
        feature_result = analyze_features(final_features)
        
        # 4. MODEL PREDICTION (if available)
        
        model_result = None
        if loaded_models.get('xgb_model') is not None:
            try:
                X = np.array([final_features], dtype=np.float32)
                X_scaled = loaded_models['scaler'].transform(X)
                
                xgb_model = loaded_models['xgb_model']
                model_pred = int(xgb_model.predict(X_scaled)[0])
                
                proba = xgb_model.predict_proba(X_scaled)[0]
                model_result = {
                    "prediction": "attack" if model_pred == 1 else "safe",
                    "probability_attack": float(proba[1]),
                    "confidence": float(proba[model_pred])
                }
            except Exception as e:
                print(f"Model prediction error: {e}")
                model_result = {
                    "prediction": "error",
                    "probability_attack": 0.5,
                    "confidence": 0.5
                }
        
        
        # 5. UNIFIED DECISION
        
        final_decision = make_final_decision(model_result, heuristic_result, feature_result)
        
        # PUSH NETWORK / ML ALERTS FOR EXTENSION
        
        ML_ATTACK_KEYWORDS = [
            "BRUTEFORCE",
            "DOS",
            "DDOS",
            "HOIC",
            "LOIC",
            "HULK",
            "SLOWHTTP",
            "SSH",
            "FTP"
        ]

        primary = final_decision["primary_attack"].upper()
        indicators_text = " ".join(final_decision.get("indicators", [])).upper()

        is_ml_attack = any(
            kw in primary or kw in indicators_text
            for kw in ML_ATTACK_KEYWORDS
        )
        
        def resolve_ml_attack_name(final_decision):
            indicators = final_decision.get("indicators", [])

            for ind in indicators:
                ind_upper = ind.upper()

                if "BRUTEFORCE" in ind_upper and "FTP" in ind_upper:
                    return "FTP Bruteforce"

                if "BRUTEFORCE" in ind_upper and "SSH" in ind_upper:
                    return "SSH Bruteforce"

                if "DDOS" in ind_upper:
                    return "DDoS Attack"

                if "DOS" in ind_upper:
                    return "DoS Attack"

            return final_decision["primary_attack"]

        attack_name = resolve_ml_attack_name(final_decision)
        #  CONFIRMED ATTACK (High Confidence)
        if final_decision["decision"] == "ATTACK" and is_ml_attack:
            push_alert(
                attack_type=attack_name,
                severity="CRITICAL",
                confidence=final_decision["confidence"],
                source="ML_ENGINE"
            )
        #  EARLY WARNING (Predictive / Future Threat) 
        elif heuristic_result["detected"] and is_ml_attack:
            push_alert(
                attack_type=f"Potential {attack_name}",
                severity="HIGH",
                confidence=0.7,
                source="HEURISTIC_ENGINE"
            )
               
        # 6. GENERATE RESPONSE
        
        response = {
            'success': True,
            'detection': final_decision,
            'components': {
                'heuristic': {
                    'detected': heuristic_result['detected'],
                    'primary_attack': heuristic_result.get('primary_attack'),
                    'score': heuristic_result.get('total_score', 0)
                },
                'features': {
                    'suspicious': feature_result['suspicious'],
                    'score': feature_result['score'],
                    'attack_types': feature_result['attack_types']
                },
                'model': model_result if model_result else {'available': False}
            },
            'metadata': {
                'timestamp': pd.Timestamp.now().isoformat(),
                'feature_count': len([f for f in final_features if f != 0]),
                'analysis_methods': ['heuristic', 'feature', 'model' if model_result else 'heuristic_only']
            }
        }
        
        # Add recommendations
        if final_decision['decision'] == 'ATTACK':
            response['recommendations'] = [
                '🚨 IMMEDIATE ACTION REQUIRED',
                'Block the source IP address',
                'Review security logs',
                'Update firewall rules',
                f'Investigate {final_decision["primary_attack"]} attempt'
            ]
        elif final_decision['decision'] == 'SUSPICIOUS':
            response['recommendations'] = [
                '⚠️ Monitor closely',
                'Review activity logs',
                'Consider temporary restrictions',
                'Increase monitoring frequency'
            ]
        else:
            response['recommendations'] = [
                '✅ No immediate action needed',
                'Continue normal monitoring',
                'Maintain security updates'
            ]
        if https_warning:
            response["connection_security"] = https_warning
       
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f"Prediction error: {str(e)}"
        }), 500

@app.route('/scan', methods=['POST'])
def scan():
    """Quick scan for browser extension"""
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data'}), 400
        
        # Simple analysis for extension
        url = data.get('url', '')
        content = data.get('content', '')
        
        analysis_text = f"{url} {content}".lower()
        
        # Quick checks
        checks = {
            'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
            'is_https': url.startswith('https://'),
            'has_suspicious_keywords': any(kw in analysis_text for kw in 
                                          ['login', 'password', 'bank', 'verify', 'secure']),
            'suspicious_patterns': any(re.search(pattern, analysis_text) for pattern in 
                                      [r'or\s+1=1', r'<script', r'javascript:', r'\.\./'])
        }
        
        # Simple decision
        risk_score = 0
        if checks['has_ip'] and not checks['is_https']:
            risk_score += 30
        if checks['suspicious_patterns']:
            risk_score += 40
        if checks['has_suspicious_keywords'] and not checks['is_https']:
            risk_score += 25
        
        if risk_score >= 50:
            status = "warning"
            message = "Potential security risk detected"
        elif risk_score >= 20:
            status = "caution"
            message = "Some suspicious indicators"
        else:
            status = "safe"
            message = "Looks clean"
        return jsonify({
            'status': status,
            'message': message,
            'risk_score': risk_score,
            'checks': checks
        })
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify({
        "success": True,
        "count": len(ALERT_BUFFER),
        "alerts": ALERT_BUFFER
    })

    

# CORS & RUN

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    return response

if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("OPTIMIZED UNIFIED DETECTION SYSTEM - VERSION 5.0")
    print("=" * 70)
    print(f"✓ Detection Methods: Heuristic + Features + Model")
    print(f"✓ Attack Categories: {len(PAYLOAD_PATTERNS)}")
    print(f"✓ Features: {len(feature_order)}")
    print(f"✓ XGBoost: {'Available' if loaded_models.get('xgb_model') else 'Not available'}")
    print(f"✓ Endpoints: /predict, /analyze, /scan, /health")
    print(f"Server: http://localhost:5000")
    print("=" * 70)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except Exception as e:
        print(f"Server error: {e}")
