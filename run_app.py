import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
try:
    from main_gui import main
except ImportError as e:
    print(e)
    sys.exit(1)

if __name__ == "__main__":
    main()
