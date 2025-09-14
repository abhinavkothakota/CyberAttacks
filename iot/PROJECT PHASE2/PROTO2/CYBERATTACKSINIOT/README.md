# Cyber Attacks in IoT Networks - Intrusion Detection System

## 🚀 Project Overview

This project implements a comprehensive **Real-Time Network Intrusion Detection System** specifically designed for IoT networks. The system captures live network traffic, analyzes packet features using machine learning models, and automatically detects and blocks malicious activities in real-time.

## 🎯 Key Features

- **Real-time Packet Capture**: Live network traffic monitoring using Scapy
- **Machine Learning Classification**: Pre-trained Random Forest model for attack detection
- **Multiple Attack Types Detection**:
  - **DOS** (Denial of Service)
  - **Probe** (Vulnerability Scanning)
  - **R2L** (Remote to Local attacks)
  - **U2R** (User to Root escalation)
- **Automatic IP Blocking**: Real-time blocking of detected malicious IPs
- **Interactive Web Interface**: Streamlit-based dashboard for monitoring
- **Flask WebSocket Support**: Real-time data streaming and visualization
- **Flow Analysis**: Advanced packet flow tracking and analysis
- **Risk Assessment**: Probability-based risk scoring system

## 🛠️ Technologies Used

### Core Technologies
- **Python 3.10.13** - Primary programming language
- **Streamlit** - Interactive web application framework
- **Flask** - Web framework for API endpoints
- **Flask-SocketIO** - Real-time bidirectional communication

### Machine Learning & Data Science
- **scikit-learn** - Machine learning algorithms and preprocessing
- **TensorFlow** - Deep learning framework for autoencoder models
- **pandas** - Data manipulation and analysis
- **numpy** - Numerical computing
- **joblib** - Model serialization and loading

### Network Analysis
- **Scapy** - Packet manipulation and network analysis
- **psutil** - System and process monitoring

### Visualization & UI
- **Plotly** - Interactive data visualization
- **Matplotlib** - Static plotting
- **Seaborn** - Statistical data visualization

### Model Explainability
- **LIME** - Local Interpretable Model-agnostic Explanations
- **dill** - Advanced serialization for complex objects

### Additional Libraries
- **Werkzeug** - WSGI toolkit
- **simple-websocket** - WebSocket support

## 📁 Project Structure

```
CYBERATTACKSINIOT/
├── app.py                          # Main Streamlit application
├── main6BS.py                      # Enhanced Streamlit app with additional features
├── application.py                  # Flask application with WebSocket support
├── ALGO.py                         # Machine learning algorithm implementation
├── ACC.py                          # Model accuracy testing
├── appcsv.py                       # CSV data processing utilities
├── appcsv2.py                      # Additional CSV processing
├── flow/                           # Flow analysis module
│   ├── __init__.py
│   ├── Flow.py                     # Flow tracking class
│   └── PacketInfo.py               # Packet information extraction
├── others/                         # Additional implementations
│   ├── main.py
│   ├── main3N.py
│   ├── main4L.py
│   └── main5B.py
├── pics/                           # Screenshots and documentation images
├── models/                         # Pre-trained ML models
│   ├── model.pkl                   # Main classification model
│   ├── randomforest_trained.pkl    # Random Forest model
│   └── autoencoder_39ft.hdf5      # Autoencoder model
├── *.csv                           # Dataset files
├── requirements.txt                # Python dependencies
└── runtime.txt                     # Python version specification
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10.13
- Administrative privileges (for packet capture and IP blocking)
- Network interface access

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CYBERATTACKSINIOT
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Streamlit application**
   ```bash
   streamlit run app.py
   # or for enhanced version
   streamlit run main6BS.py
   ```

4. **Run the Flask application (alternative)**
   ```bash
   python application.py
   ```

### Usage

1. **Start Real-Time Capture**: Click the "Start Real-Time Capture" button
2. **Configure Parameters**: Adjust packet count and reset intervals via sidebar
3. **Monitor Results**: View real-time classification results and attack detection
4. **Review Blocked IPs**: Check automatically blocked malicious IPs

## 🔧 Configuration

### Streamlit App Configuration
- **Packet Count**: Number of packets to capture per batch (1-50)
- **Reset Interval**: Time interval for counter reset (1-10 seconds)
- **Model Path**: Ensure `model.pkl` is in the project root

### Flask App Configuration
- **Port**: Default Flask port (5000)
- **WebSocket**: Real-time data streaming enabled
- **Flow Timeout**: 600 seconds for flow termination

## 📊 Features in Detail

### Real-Time Packet Analysis
- **Live Capture**: Continuous network packet monitoring
- **Feature Extraction**: Automatic extraction of 15+ network features
- **Flow Tracking**: Advanced packet flow analysis and classification
- **Rate Calculation**: Dynamic calculation of connection rates and patterns

### Machine Learning Pipeline
- **Pre-trained Models**: Random Forest classifier for attack detection
- **Feature Engineering**: Automatic feature scaling and normalization
- **Probability Scoring**: Risk assessment based on prediction confidence
- **Model Explainability**: LIME-based feature importance analysis

### Security Features
- **Automatic Blocking**: Real-time IP blocking for detected attacks
- **Cross-platform Support**: Windows (netsh) and Linux (iptables) blocking
- **Risk Assessment**: Multi-level risk scoring (Minimal to Very High)
- **Attack Classification**: Detailed attack type identification

## 📈 Performance Metrics

- **Model Accuracy**: ~65% (as configured in ALGO.py)
- **Real-time Processing**: 10 packets per batch (configurable)
- **Memory Efficient**: Optimized data structures for continuous operation
- **Low Latency**: Near real-time detection and response

## 🔒 Security Considerations

- **Administrative Access**: Required for packet capture and IP blocking
- **Network Permissions**: Ensure proper network interface access
- **Model Security**: Pre-trained models should be validated before deployment
- **Data Privacy**: Network packet data should be handled according to privacy policies

## 🐛 Troubleshooting

### Common Issues
1. **Permission Denied**: Run with administrative privileges
2. **Model Not Found**: Ensure `model.pkl` exists in project root
3. **Network Interface Issues**: Check network interface permissions
4. **Dependencies**: Verify all requirements are installed correctly

### Debug Mode
- Enable logging in `main6BS.py` for detailed debugging
- Check console output for error messages
- Verify model loading and feature extraction

## 📝 Dataset Information

The system uses network intrusion datasets for training and testing:
- **network_intrusion_data.csv**: Main training dataset
- **network_packets.csv**: Packet-level data
- **input_logs.csv**: Real-time input logging
- **output_logs.csv**: Classification results logging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is part of academic research on IoT network security. Please ensure compliance with your institution's policies and local regulations.

## 📞 Support

For technical support or questions:
- Check the troubleshooting section
- Review the code documentation
- Contact the development team

## 🔄 Version History

- **v1.0**: Initial implementation with basic Streamlit interface
- **v2.0**: Added Flask WebSocket support and enhanced visualization
- **v2.1**: Improved flow analysis and model explainability
- **v2.2**: Enhanced security features and automatic IP blocking

---

**⚠️ Important Note**: This system is designed for educational and research purposes. Ensure you have proper authorization before monitoring network traffic in any environment.
