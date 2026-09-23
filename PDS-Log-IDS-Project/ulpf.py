"""
ULPF — Universal Log Pre-processing Framework
CLI Entrypoint Script
=============================================
Usage:
    python ulpf.py pipeline --input data/raw/cisco_asa.log --output outputs/cisco.jsonl --manifest outputs/manifest.json
    python ulpf.py ingest --input data/raw/cisco_asa.log --classify -o outputs/cisco.jsonl
    python ulpf.py listen --mode syslog --port 514
    python ulpf.py demo --port 7000 --input outputs/live.jsonl
    python ulpf.py train --samples 3000 --model-type rf
    python ulpf.py evaluate --model models/classifier.joblib
    python ulpf.py parsers
"""

import sys
from pathlib import Path

# Add project root to sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.pipeline import cli_main

if __name__ == "__main__":
    sys.exit(cli_main())
