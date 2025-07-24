# 🔐 Log Anomaly Detection Framework (with Chainlit + Detectors)

This project is a lightweight yet extensible framework for detecting suspicious activity in system and web server logs. It combines rule-based detection algorithms, custom log parsers, and LLM-based summarization via Chainlit and LangChain.

---

## 📦 Features

- ✅ **Modular Detectors**: Includes detectors for brute-force SSH attempts, web attack patterns, port scans, user enumeration, DoS attempts, suspicious HTTP methods, and more.
- 📈 **LLM Summarization**: Uses OpenAI's GPT-4o via LangChain to summarize threats and allow follow-up natural language queries.
- 💡 **Interactive UI**: Built on Chainlit for a simple, chat-style web interface.
- 🧪 **Standalone Runner**: CLI utility for testing detectors directly and exporting results as `.csv`/`.json`.

---

## 📁 Project Structure

```
.
├── access_log_files/          # Sample web access logs
├── auth_log_files/            # Sample SSH/auth logs
├── detectors/                 # All individual detection modules
│   ├── bf_detector.py
│   ├── web_attack_detector.py
│   ├── intrusion_detector.py
│   ├── user_enum_detector.py
│   ├── port_scan_detector.py
│   ├── suspicious_http_detector.py
│   └── dos_detector.py
├── utils/
│   └── exporter.py            # CSV and JSON exporters
├── auth_log_parser.py         # SSH log parser
├── access_log_parser.py       # Web log parser
├── summarise_chainlit.py      # Main Chainlit app
├── run_detectors.py           # CLI runner script
├── .env                       # Your OpenAI API key
└── README.md
```

---

## 🚀 Getting Started

### 1. 🧱 Requirements

- Python 3.10+
- `pip install -r requirements.txt`

Required packages include:
- `chainlit`
- `openai`
- `langchain`
- `python-dotenv`

---

### 2. 🔑 Setup

1. Create a `.env` file in the root directory:

```env
OPENAI_API_KEY=your-openai-api-key-here
```

2. Place sample logs in:
   - `auth_log_files/` for SSH-related logs
   - `access_log_files/` for web server logs

---

## 💬 Usage Modes

### Mode 1: 🧠 Chainlit UI with LLM Summary

Run:

```bash
chainlit run summarise_chainlit.py
```

Upload `.log` files and interact via chat. The LLM will summarize detected anomalies and answer your follow-up questions.

---

### Mode 2: 🧪 Standalone CLI Runner (No LLM)

Run:

```bash
python run_detectors.py
```

It will:
- Parse log files in `auth_log_files/` and `access_log_files/`
- Run all detectors
- Print findings to terminal
- Export results to `/output/` as `.csv` and `.json`

---

## 🔍 Detectors Implemented

| Detector                  | Log Type    | Description                                                                 |
|--------------------------|-------------|-----------------------------------------------------------------------------|
| Brute Force              | `auth.log`  | Detects repeated failed login attempts from same IP                         |
| Intrusion Attempts       | `auth.log`  | Detects rapid SSH login attempts within short time windows                  |
| User Enumeration         | `auth.log`  | Detects scanning for valid usernames via SSH                                |
| Web Attack Detection     | `access.log`| Detects suspicious User-Agents, SQLi, XSS, Path Traversal, sensitive paths  |
| Port Scan Detection      | `access.log`| Detects access to multiple uncommon ports from same IP                      |
| Suspicious HTTP Methods  | `access.log`| Detects rare/unsafe methods (e.g. PUT, DELETE)                              |
| DoS Attempt Detection    | `access.log`| Detects IPs with unusually high request counts                              |

---

## 📂 Outputs

- Printed in terminal for CLI runner
- Summarized in Chainlit UI
- Exported to:
  - `output/brute_force.json`
  - `output/web_attacks.csv`, etc.

---

## 🛠️ Extending This Project

Want to add new detectors?

1. Create a new file in `detectors/`, e.g. `rfi_detector.py`
2. Define a function like: `def detect_remote_file_inclusion(entries): ...`
3. Import and call it in:
   - `summarise_chainlit.py`
   - `run_detectors.py`
4. Format its output as structured data (e.g. list of tuples or dicts)

---

## ✨ Credits

Developed by Abhishek Deshpande (COMP6441 UNSW Project)  
Powered by [Chainlit](https://www.chainlit.io/) and [LangChain](https://www.langchain.com/)

---

## 📜 License

MIT License. Free for educational and research use.