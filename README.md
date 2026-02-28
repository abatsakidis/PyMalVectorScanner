# 🔥 PyMalVectorScanner v4.x

**PyMalVectorScanner** is an advanced semantic malware scanner for Python source code.

It detects malicious behavior at **function level** using AI-based vector embeddings and FAISS similarity search.

Unlike traditional signature-based scanners, this tool performs **semantic comparison** against known malware samples.

---

## 🚀 Features

- 🔍 Function-level semantic malware detection
- 🧠 Sentence Transformers embedding model
- ⚡ FAISS vector similarity search
- 📁 Single file OR full directory scanning
- 📊 HTML report generation
- 🎯 Top-K similarity matching
- 🎨 Clean color-coded terminal output
- 📈 Progress bar during scanning
- 💾 Automatic FAISS index caching
- 🔇 Silent model loading (no noisy logs)
- 🧹 Stable CLI interface

---

## 🧠 How It Works

1. Extracts all functions from:
   - A target file
   - Or all `.py` files inside a folder
2. Converts each function into vector embeddings
3. Compares against known malware samples
4. Calculates similarity scores
5. Flags suspicious functions above threshold

---

## 📦 Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/your-repo/PyMalVectorScanner.git
cd PyMalVectorScanner
```

### 2️⃣ Install Dependencies

```bash
pip install faiss-cpu sentence-transformers numpy colorama tqdm jinja2
```

Optional (only if testing sample malware):

```bash
pip install pynput requests
```

### 📁 Project Structure

PyMalVectorScanner/
│
├── scanner.py
├── malware_samples/
│   ├── keylogger.py
│   ├── trojan.py
│
├── malware.index
├── malware_functions.pkl
└── report.html

### ⚙️ First Run

On first execution:

- Builds FAISS index

- Saves:

	malware.index
	malware_functions.pkl

Subsequent runs reuse cached index for faster scanning.

## 🖥️ Usage

### 🔹 Scan Single File

```bash
python scanner.py test_file.py
```

### 🔹 Scan Entire Folder

```bash
python scanner.py -f test_files/
```

### 🔹 Show Only Suspicious Functions

```bash
python scanner.py test_file.py -s
```

### 🔹 Generate HTML Report

```bash
python scanner.py -f test_files -s -r report.html
```

### 🔹 Help

```bash
python scanner.py -h
```

## 📊 Example Output

Scanning 3 files...

[████████████████████████] 100%

File: test_files/logger.py
--------------------------------------------------
Function: on_press
Top match: keylogger.py:on_press
Similarity: 0.9341
⚠ POSSIBLE MALICIOUS CODE DETECTED

## 📄 HTML Report

Generated report includes:

- File name
- Function name
- Top malware match
- Similarity score
- Clean formatted table

## 🎯 Detection Logic

Default threshold:

```bash
Similarity >= 0.80 → Suspicious
```

You can modify the threshold inside scanner.py.

## 🧪 Use Cases

Malware research

* Educational demonstrations
* Code similarity experiments
* Security research
* AI-based detection studies

## ⚠️ Disclaimer

This tool is intended for:

* Educational purposes
* Malware analysis
* Defensive security research

Do NOT use it for malicious activity.

## 🛠 Requirements

* Python 3.8+
* faiss-cpu
* sentence-transformers
* numpy
* colorama
* tqdm
* jinja2

## 📸 Screenshot

![App Screenshot](screenshot/screen.jpg)

## 🗺 Roadmap

* Future improvements:
* CLI adjustable threshold
* JSON report export
* GPU acceleration support
* Multiple embedding model support
* Real-time folder monitoring mode
* Web dashboard version

## 👨‍💻 Author

Athanasios Batsakidis
PyMalVectorScanner v4.x

## 📜 License

MIT License © 2026 Athanasios Batsakidis
