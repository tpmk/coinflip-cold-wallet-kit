import sys
from pathlib import Path

# Ensure project root is on sys.path so `import wallet_core` works
# regardless of how pytest is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
