# Cyber Security AI Detection Systems

A comprehensive suite of AI-powered cybersecurity detection tools for identifying various types of cyber threats.

## 📋 Overview

This project contains 5 independent detection systems:

| System | Technology | Purpose |
|--------|------------|---------|
| DDoS Detection | Random Forest | Detect DDoS attacks in network traffic |
| Malware Detection | Deep Learning (CNN) | Identify malicious software from EXE files |
| SQL Injection Detection | NLP + ML | Detect SQL injection attempts in queries |
| Brute Force Detection | Isolation Forest + RF | Identify brute force and credential stuffing attacks |
| Log Analysis | Multiple ML Models | Analyze logs for suspicious activities |

## 🚀 Installation

### Prerequisites

```bash
pip install numpy pandas scikit-learn tensorflow pillow joblib
```

### Quick Setup

```bash
cd cyber_security_ai
pip install -r requirements.txt
```

## 📁 Project Structure

```
cyber_security_ai/
├── ddos_detection/
│   └── ddos_detector.py       # DDoS attack detection using Random Forest
├── malware_detection/
│   └── malware_detector.py    # Malware detection using CNN
├── sql_injection_detection/
│   └── sql_injection_detector.py  # SQL injection detection using NLP
├── brute_force_detection/
│   └── brute_force_detector.py    # Brute force detection system
├── log_analysis/
│   └── log_analyzer.py        # AI-powered log analysis
└── README.md
```

## 🔧 Usage

### 1. DDoS Detection System

```python
from ddos_detection.ddos_detector import DDoSDetector

# Initialize
detector = DDoSDetector()

# Train with your data
detector.train(X_train, y_train)

# Predict
prediction, confidence = detector.predict(network_traffic_data)
```

**Features:**
- Packet size and rate analysis
- Source IP entropy calculation
- TCP flag pattern recognition
- Protocol distribution analysis

### 2. Malware Detection System

```python
from malware_detection.malware_detector import MalwareDetector

# Initialize
detector = MalwareDetector()

# Convert EXE to image and predict
prediction, confidence = detector.predict('suspicious_file.exe')
```

**Features:**
- EXE to grayscale image conversion
- CNN-based classification
- Pattern recognition in binary files

### 3. SQL Injection Detection

```python
from sql_injection_detection.sql_injection_detector import SQLQueryAnalyzer

# Initialize
analyzer = SQLQueryAnalyzer()

# Analyze query
prediction, confidence, analysis = analyzer.predict(user_input)
```

**Features:**
- Pattern matching for known attacks
- TF-IDF vectorization
- Feature extraction from queries
- Risk analysis reporting

### 4. Brute Force Detection

```python
from brute_force_detection.brute_force_detector import LoginAttemptAnalyzer, RealTimeMonitor

# Initialize
analyzer = LoginAttemptAnalyzer()
monitor = RealTimeMonitor(analyzer)

# Process login attempt
decision, info = monitor.process_login_attempt(login_data)
```

**Features:**
- Real-time monitoring
- IP reputation tracking
- User behavior analysis
- Automatic IP blocking

### 5. Log Analysis System

```python
from log_analysis.log_analyzer import LogAnalyzer, RealTimeLogMonitor

# Initialize
analyzer = LogAnalyzer()
monitor = RealTimeLogMonitor(analyzer)

# Analyze log entry
result = analyzer.analyze(log_line)
```

**Features:**
- Multi-format log parsing
- Threat signature matching
- Anomaly detection
- Risk scoring

## 📊 Model Training

Each system includes synthetic data generation for demonstration. For production use:

1. **Collect real data** from your environment
2. **Label the data** appropriately
3. **Train the models** using the `train()` method
4. **Save trained models** using `save_model()`
5. **Load models** in production using `load_model()`

## ⚠️ Important Notes

- These systems are designed for **educational and research purposes**
- For production deployment, train on **real-world data** from your environment
- Regular model updates are necessary to detect new attack patterns
- Consider integrating with SIEM systems for enterprise deployment

## 🔬 Technical Details

### DDoS Detection
- **Algorithm**: Random Forest Classifier
- **Features**: 10 network traffic features
- **Accuracy**: ~98% on synthetic data

### Malware Detection
- **Algorithm**: Convolutional Neural Network (CNN)
- **Input**: 256x256 grayscale images
- **Architecture**: 3 convolutional blocks + FC layers

### SQL Injection Detection
- **Algorithm**: Gradient Boosting + TF-IDF
- **Features**: Text n-grams + statistical features
- **Patterns**: 17+ known injection patterns

### Brute Force Detection
- **Algorithms**: Isolation Forest + Random Forest
- **Features**: 14 behavioral features
- **Real-time**: Sub-second prediction

### Log Analysis
- **Algorithms**: Random Forest + Isolation Forest + KMeans
- **Parsing**: Apache, Nginx, Syslog, Auth logs
- **Signatures**: 20+ threat signatures

## 📝 License

MIT License - Free for educational and commercial use

## 🤝 Contributing

Contributions welcome! Please feel free to submit issues and pull requests.

## 📧 Support

For questions and support, please open an issue on GitHub.

---

**⚠️ Disclaimer**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before deploying security monitoring systems.
