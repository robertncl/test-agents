"""Make the repo importable when pytest is invoked from anywhere.

Per-sandbox test logic lives in ``tests/<backend>/``; the shared helper is
:func:`sandbox.testing.check`.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
