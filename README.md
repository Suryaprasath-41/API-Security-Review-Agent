# API Security Review Agent

An AI-powered DevSecOps static analysis assistant that parses Swagger/OpenAPI specifications, detects design-level security vulnerabilities, maps findings to the OWASP API Security Top 10 (2023), calculates risk scores, and generates detailed compliance assessment reports (PDF and Markdown) with AI explanations and code-level mitigations.

---

## 🚀 Features

- **Multi-Format Upload**: Supports Swagger 2.0 and OpenAPI 3.0 specs in JSON or YAML.
- **Reference Resolution**: Recursively resolves local `$ref` schemas.
- **20 Security Rules**: Automated checks covering rate limiting, BOLA, IDOR, SQL injection, unrestricted DELETE, and wildcard CORS.
- **OWASP API Top 10 mapping**: Correlates every finding to industry standards.
- **AI-Powered Explainer Node**: Connects to OpenAI or Ollama, with a deterministic offline fallback database.
- **Interactive UI**: Metrics dashboard and report downloader built in Streamlit.
- **FastAPI Backend**: Clean API routing interface for integrations.
- **Report Exporters**: Styled PDF generation using ReportLab, plus Markdown reports.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn
- **Frontend**: Streamlit
- **Agent Framework**: LangGraph
- **Database**: SQLite3
- **PDF Generation**: ReportLab
- **Containerization**: Docker, Docker Compose

---

## 📦 Running the Application

### Method 1: Using Docker Compose (Recommended)

Make sure you have Docker and Docker Compose installed.

1. Clone or download this project workspace.
2. In the project root, start the services:
   ```bash
   docker-compose up --build
   ```
3. Open your browser:
   - **Streamlit Dashboard**: [http://localhost:8501](http://localhost:8501)
   - **FastAPI Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

*(Note: If you have a local Ollama server or OpenAI token, you can pass them as environment variables inside `docker-compose.yml` or set them on your host).*

---

### Method 2: Running Locally

Ensure you have Python 3.10+ installed.

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the FastAPI Backend**:
   ```bash
   uvicorn app.backend_api:app --host 127.0.0.1 --port 8000 --reload
   ```

3. **Start the Streamlit Frontend Dashboard** (in a new terminal):
   ```bash
   streamlit run app/frontend_dashboard.py
   ```

4. Open the Streamlit Dashboard at [http://localhost:8501](http://localhost:8501).

---

## 🧪 Running Tests

We use `pytest` for unit testing the parser, security rule evaluations, OWASP mappings, and risk computations.

Run the test suite:
```bash
pytest tests/
```

To run with full logging output:
```bash
pytest -s -v tests/
```

---

## 📂 Project Structure

```
api-security-review-agent/
├── app/
│   ├── config.py                 # Application configurations
│   ├── database.py               # SQLite tables & database utilities
│   ├── backend_api.py            # FastAPI routing layer (Backend API)
│   ├── frontend_dashboard.py     # Streamlit dashboard layout (Frontend Dashboard)
│   ├── agents/                   # LangGraph nodes & logic
│   ├── parsers/                  # Spec parser classes
│   └── utils/                    # PDF report generators
├── docs/
│   └── PROJECT_REPORT.md         # Comprehensive 17-section project report
├── tests/
│   ├── test_rules.py             # Test suite
│   └── sample_vulnerable_openapi.yaml  # Test spec fixture
├── Dockerfile                    # Containerization settings
├── docker-compose.yml            # Container orchestration settings
└── requirements.txt              # Project requirements
```
