"""Entry point: ``python -m src``.

Launches the HyperGuard92 NiceGUI prototype interface.
"""

from __future__ import annotations

import os
import sys

from src.gui import run_app


def main() -> int:
    """Bootstrap and run the GUI. Returns process exit code."""
    host = os.environ.get("HG_HOST", "127.0.0.1")
    port = int(os.environ.get("HG_PORT", "8492"))
    native = os.environ.get("HG_NATIVE", "true").lower() == "true"

    try:
        run_app(host=host, port=port, native=native)
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ in {"__main__", "__mp_main__"}:
    sys.exit(main())
