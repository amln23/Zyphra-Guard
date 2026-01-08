# Zyphra-Guard (ZGS) 
### A Hybrid Machine Learning & Heuristic-Based Framework for Real-Time Web Attack Detection

Zyphra-Guard is an advanced security system designed to protect users from web-based attacks in real-time. It operates as a Chrome Extension (Frontend) integrated with a Flask-based Inference Server (Backend) [1].

## Key Features
- **Hybrid Detection:** Combines lightweight heuristic rules for speed and Machine Learning (XGBoost) for high-accuracy detection of complex patterns [2, 3].
- **Real-Time Monitoring:** Continuous scanning of URLs, DOM mutations, and User Inputs [4, 5].
- **Privacy-First:** Operates on extracted features (41-dimensional vector) without storing or transmitting raw user data [6, 7].
- **ZGS Scoring System:** A custom 10-point risk scoring engine inspired by CVSS v3.1 to quantify threat severity [8, 9].

##  Performance Results
Based on our system evaluation using the CICIDS-2018 dataset, Zyphra-Guard achieved exceptional results [10, 11]:
- **Detection Accuracy:** **100%** precision and recall using the XGBoost model for known threats [12, 13].
- **Latency:** Total processing delay of only **35ms** (12ms for extraction + 23ms for inference), ensuring a seamless browsing experience [15].

##  Tech Stack
- **Frontend:** JavaScript (Chrome Extension API), HTML/CSS [1, 16].
- **Backend:** Python (Flask), Scikit-learn, XGBoost, TensorFlow/Keras [1, 17, 18].
- **Data:** CICIDS-2018 augmented with synthetic web-oriented features [10, 19].

##  Installation & Setup
1. **Backend:**
   - Install dependencies: `pip install -r requirements.txt`
   - Run the server: `python server2.py` (Server starts at http://localhost:5000) [20, 21].
2. **Frontend:**
   - Open Chrome and go to `chrome://extensions/`.
   - Enable "Developer mode".
   - Click "Load unpacked" and select the `extension/` folder [16].

##  Project Team
Amal Alidmat, Aya Hamdi, Heba AlHusban, Shaimaa Almashaqbeh.
**Supervised by:** Dr. Mohammad Alshinwan [22].

--------------------------------------------------------------------------------
