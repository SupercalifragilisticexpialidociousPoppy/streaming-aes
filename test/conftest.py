import os
import sys

# The modules in src/ import each other by bare name (e.g. `from ghash import ...`),
# so put src/ on the path for every test.
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, os.path.abspath(SRC))

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
