# 🛡️ Phishing Website Detection using Machine Learning (URL Based)

Detect phishing (malicious) URLs using Machine Learning based only on URL structure — **no webpage loading**, making this approach fast, lightweight, and secure.

---

## 📌 Project Overview

This project classifies URLs as:

* ✅ **Safe (Legitimate URL)**
* 🚨 **Phishing / Malicious URL**

The ML model analyzes **patterns inside the URL only**, without accessing the webpage, avoiding potential security risks.

> Model Accuracy: **97.8%**

---

## 🧠 Tech Stack / Libraries Used

| Component            | Technology                                        |
| -------------------- | ------------------------------------------------- |
| Programming Language | Python                                            |
| Machine Learning     | scikit-learn (Linear SVC)                         |
| Feature Extraction   | TF-IDF (Character-level), Custom Numeric Features |
| Dataset Handling     | Pandas, NumPy                                     |
| Model Export         | joblib                                            |
| UI                   | Streamlit (app.py)                                |

---

## 📂 Repository Structure (your real structure)

```
📁 Project Root/
│
├── app.py                     # Streamlit web UI to check URLs
├── Phishing.ipynb             # Jupyter notebook – model training + evaluation
├── phishing_url_model.joblib  # Final trained ML model (used in app.py)
├── phishing_model.pkl         # (Optional model — earlier version)
├── phishing_site_urls.csv     # Dataset (URLs + Labels)
├── scaler.pkl                 # Extra artifact (if used)
├── original.jpg               # UI header image (optional)
├── requirements.txt           # Required Python packages
└── README.md                  # Documentation (this file)
```

---

## 🚀 How to Run the Streamlit App

### 1️⃣ Install dependencies

```sh
pip install -r requirements.txt
```

### 2️⃣ Run the web application

```sh
streamlit run app.py
```

### 3️⃣ Enter a URL and click **Check URL**

Example:

```
https://accounts.google.com/
```

It will return:

* ✅ SAFE (if the URL appears legitimate)
* 🚨 PHISHING (if model detects malicious patterns)

---

## 🧠 How the Model Works

1. Input URL is preprocessed
2. URL features are extracted:

   * Character-level TF-IDF (ngrams: 3–4)
   * Numeric features (length, dots, hyphens, presence of IP, suspicious keywords)
3. Combined features → ML model (`LinearSVC`)
4. Model returns: `good` or `bad`

---

## 📊 Training (Phishing.ipynb)

Notebook includes:

* Dataset loading (`phishing_site_urls.csv`)
* Feature extraction (`UrlNumericFeatures`)
* Model building (pipeline)
* Evaluation: Confusion Matrix, Accuracy

Output model: `phishing_url_model.joblib`

---

## 📈 Results

| Metric             | Score       |
| ------------------ | ----------- |
| Accuracy           | **97.8%**   |
| Precision / Recall | High (≈98%) |

🔳 Confusion Matrix (example):

|             | Predicted Bad | Predicted Good |
| ----------- | ------------- | -------------- |
| Actual Bad  | 29,608        | 1,677          |
| Actual Good | 870           | 77,715         |

---

## 📥 Dataset

Dataset used:

```
phishing_site_urls.csv
```

Format:

| URL                                                      | Label |
| -------------------------------------------------------- | ----- |
| nobell.it/70ffb5…                                        | bad   |
| [https://www.wikipedia.org/](https://www.wikipedia.org/) | good  |

Labels: `good`, `bad`

---

## ✅ Requirements

`requirements.txt` includes:

```
scikit-learn
pandas
numpy
joblib
tldextract
streamlit
```

---

## 🔮 Future Scope

* Deep Learning (LSTM / Transformer)
* Browser extension for real-time detection
* Add WHOIS info and SSL certificate validation
