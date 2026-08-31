# Intrusion Detection System Using Machine Learning

## 📌 Overview
In the modern digital era, cybersecurity threats are increasing at an alarming rate. Our **Intrusion Detection System (IDS)** leverages machine learning to identify and prevent unauthorized access attempts, ensuring network security against cyber threats.

## ❓ Problem Statement
The goal is to develop a **predictive model** capable of distinguishing between normal network connections and malicious intrusions, including:
- Denial-of-service (DoS) attacks
- Unauthorized access attempts
- Probing activities

## 🔥 Key Features
- ✅ **Real-time Intrusion Detection**: Monitors and classifies network traffic.
- 🔍 **Machine Learning Algorithms**: Implements multiple classification techniques.
- 📊 **Comprehensive Dataset**: Uses the KDD Cup 1999 dataset.
- 📈 **Detailed Analysis**: Evaluates model performance across various metrics.
- 🔧 **Scalability**: Designed for adaptation to real-world network security systems.

## 🛡 Attack Categories
The IDS detects and classifies attacks into four main categories:
- **🛑 Denial-of-Service (DoS)**: Flooding the network to make services unavailable.
- **🔓 Remote-to-Local (R2L)**: Unauthorized remote access attempts.
- **⚠️ User-to-Root (U2R)**: Privilege escalation attacks.
- **🔍 Probing**: Scanning for vulnerabilities and weak points.

## 📂 Dataset Used
We utilize the **KDD Cup 1999** dataset, a well-known benchmark dataset for evaluating IDS performance. It contains various network traffic records, each labeled as normal or an attack type.

The raw `.gz` archives (~35MB) are **not checked into this repo** — download them
from the [UCI KDD Cup 1999 archive](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)
and place them under `dataset/`:

```bash
mkdir -p dataset
cd dataset
curl -O http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data.gz
curl -O http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz
curl -O http://kdd.ics.uci.edu/databases/kddcup99/corrected.gz
curl -O http://kdd.ics.uci.edu/databases/kddcup99/kddcup.testdata.unlabeled.gz
curl -O http://kdd.ics.uci.edu/databases/kddcup99/kddcup.testdata.unlabeled_10_percent.gz
curl -O http://kdd.ics.uci.edu/databases/kddcup99/kddcup.newtestdata_10_percent_unlabeled.gz
```

`dataset/kddcup.names` and `dataset/training_attack_types` (feature/label
reference files, not raw traffic data) are still tracked in the repo.

## 📌 Machine Learning Models
To achieve accurate intrusion detection, we apply and compare the following models:
- 🤖 **Gaussian Naive Bayes**
- 🌳 **Decision Tree**
- 🌲 **Random Forest**
- 🔥 **Support Vector Machine (SVM)**
- 🏛 **Logistic Regression**

## 🚀 Implementation Approach
1. **📌 Data Preprocessing**: Cleaning and transforming the dataset.
2. **📊 Feature Selection**: Extracting relevant network traffic features.
3. **🤖 Model Training**: Applying machine learning algorithms.
4. **📈 Evaluation & Optimization**: Comparing results and improving accuracy.
5. **🛠 Deployment & Monitoring**: Future integration into real-world systems.

## ⚡ Installation & Usage
```bash
# Clone the repository
git clone https://github.com/HumerousFi/IDS-using-ML-algorithms.git
cd IDS-using-ML-algorithms

# Download the dataset (see "Dataset Used" above), then run
python main.py
```

## 🔮 Future Enhancements
- 🔄 **Integration with real-time network monitoring tools**
- 🤖 **Implementation of deep learning techniques**
- 🔍 **Enhanced feature engineering for better accuracy**

## 📜 License
This project is licensed under the **MIT License** — see [LICENSE](LICENSE).

## 🙌 Acknowledgments
- 📂 **KDD Cup 1999** for providing the dataset.
- 🛠 **Open-source libraries** and community contributions.
