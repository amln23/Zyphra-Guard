# Zyphra-Guard
### A Hybrid Machine Learning & Heuristic-Based Framework for Real-Time Web Attack Detection

Zyphra-Guard is an advanced security system designed to protect users from web-based attacks in real-time. It operates as a Chrome Extension (Frontend) integrated with a Flask-based Inference Server (Backend).


## Requirements & Running the Server

### 1. Install the Required Packages
Ensure you have Python 3.8+ installed, then run:
pip install -r requirements.txt
> This installs Flask, Scikit-learn, XGBoost, TensorFlow/Keras, and other necessary libraries.

### 2. Frontend Setup
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked** and select the `extension/` folder

### 3. Start the Backend Server
Run:python server2.py
> The server will start at [http://localhost:5000](http://localhost:5000). Keep this terminal open while using the Chrome Extension frontend.

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
