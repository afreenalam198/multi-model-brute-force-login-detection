# Multi-model Brute-Force Login Attack Detection System

## 🌐 Project Overview

### Background
In an era of increasingly sophisticated cyber threats, traditional security mechanisms often fall short in detecting complex brute-force attacks. This project addresses this critical challenge by developing a multi-layered, intelligent anomaly detection system that leverages advanced machine learning techniques.

### Key Objectives
- Generate synthetic dataset with various login attack patterns
- Develop a robust, adaptive anomaly detection framework
- Implement multiple detection strategies

## 🏗️ System Architecture

### High-Level Components
1. **Log Generation Module**
   - Synthetic log creation for training and testing
   - Simulates realistic network login scenarios

2. **Preprocessing Pipeline**
   - Feature extraction
   - Data normalization
   - Sequence preparation

3. **Detection Models**
   - IP-based Isolation Forest
   - Time-Series Isolation Forest
   - LSTM Neural Network

4. **Evaluation and Visualization Module**
   - Performance metrics generation
   - Graphical result representation

## 🔬 Detailed Technical Specifications

### Supported Features
- Multiple anomaly detection algorithms
- Configurable detection parameters
- Comprehensive log analysis
- Adaptive learning mechanisms
  
### Technology Stack 
- Python 3.8+
- Faker Library
- Machine Learning Libraries
  - TensorFlow
  - Scikit-learn
  - Keras
- Data Processing
  - Pandas
  - NumPy
- Visualization
  - Matplotlib
  - Seaborn

## 🕵️ Anomaly Detection Techniques

### 1. IP-based Isolation Forest
- Analyzes login attempts per IP address
- Identifies statistically unusual network behaviors
- Low computational complexity

### 2. Time-Series Isolation Forest
- Examines temporal login attempt patterns
- Detects sequential anomalies
- Captures complex temporal dependencies

### 3. LSTM Neural Network
- Deep learning-based sequence prediction
- Learns intricate temporal relationships
- Captures non-linear attack patterns

## 🔄 Data Preprocessing

### Feature Engineering
- IP address aggregation
- Temporal feature extraction
- Login attempt characterization
- Protocol-specific analysis

### Normalization Techniques
- StandardScaler for numerical features
- MinMaxScaler for neural network inputs
- Handling missing/irregular data

## 🏋️ Model Training

### Training Strategies
- Sequential temporal splitting
- Preserving chronological context
- Avoiding data leakage
- Incremental learning support

### Hyperparameter Considerations
- Contamination rate
- Sequence length
- Model complexity
- Regularization techniques

## 📊 Evaluation Metrics

### Performance Indicators
- Classification Report
- Confusion Matrix
- ROC-AUC Curve
- Precision/Recall
- F1 Score

### Visualization Outputs
- Anomaly distribution charts
- Model performance graphs
- Temporal anomaly progression

### Limitations
- Relies on training data quality
- Potential false positives/negatives

## 🗺️ Future Roadmap
- Real-time detection integration
- Cloud deployment support
- Use Real-world dataset
- Advanced attack pattern recognition

