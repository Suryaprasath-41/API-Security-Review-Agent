import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Database configuration
DATABASE_PATH = str(BASE_DIR / "api_security_agent.db")

# Directory configurations
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

# Create directories if they do not exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# LLM Configurations
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# Automatically detect fallback or Ollama/OpenAI
if OPENAI_API_KEY:
    DEFAULT_LLM_PROVIDER = "openai"
else:
    DEFAULT_LLM_PROVIDER = "fallback" # Fallback mode by default if no key. Can switch to Ollama if service responds.
