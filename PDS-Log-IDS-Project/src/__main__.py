"""
Entry point for: python -m ulpf

Delegates to src.pipeline.cli_main().
"""
import sys
from src.pipeline import cli_main

if __name__ == "__main__":
    sys.exit(cli_main())
