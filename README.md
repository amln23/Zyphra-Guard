# Zyphra-Guard
### A Hybrid Machine Learning & Heuristic-Based Framework for Real-Time Web Attack Detection

Zyphra-Guard is an advanced security system designed to protect users from web-based attacks in real-time. It operates as a Chrome Extension (Frontend) integrated with a Flask-based Inference Server (Backend).

## Key Features
- **Hybrid Detection:** Combines lightweight heuristic rules for speed and Machine Learning (XGBoost) for high-accuracy detection of complex patterns.
- **Real-Time Monitoring:** Continuous scanning of URLs, DOM mutations, and User Inputs.
- **Privacy-First:** Operates on extracted features (41-dimensional vector) without storing or transmitting raw user data.
- **ZGS Scoring System:** A custom 10-point risk scoring engine inspired by CVSS v3.1 to quantify threat severity.

**Performance Results:**  
Zyphra-Guard achieves very high accuracy in detecting known web-based attacks on standard datasets, with minimal latency, ensuring a seamless browsing experience.

##  Tech Stack
- **Frontend:** JavaScript (Chrome Extension API), HTML/CSS.
- **Backend:** Python (Flask), Scikit-learn, XGBoost, TensorFlow/Keras.
- **Data:** CICIDS-2018 augmented with synthetic web-oriented features.

##  Installation & Setup
1. **Backend:**
   - Install dependencies: `pip install -r requirements.txt`
   - Run the server: `python server2.py` (Server starts at http://localhost:5000).
2. **Frontend:**
   - Open Chrome and go to `chrome://extensions/`.
   - Enable "Developer mode".
   - Click "Load unpacked" and select the `extension/` folder.

##  Project Team
Amal Alidmat, Aya Hamdi, Heba AlHusban, Shaimaa Almashaqbeh.
**Supervised by:** Dr. Mohammad Alshinwan.

--------------------------------------------------------------------------------
