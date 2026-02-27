import os
import sys
import pickle
import logging
import numpy as np
import faiss
import ast
from sentence_transformers import SentenceTransformer
from colorama import init, Fore, Style

# =============================
# CONFIG
# =============================
MALWARE_DIR = "malware_samples"
SIMILARITY_THRESHOLD = 0.80
PROGRAM_NAME = "PyMalVectorScanner"
VERSION = "v2.0"
AUTHOR = "Batsakidis Athanasios"
TOP_K = 3
INDEX_FILE = "malware.index"
NAMES_FILE = "malware_functions.pkl"

# Initialize colorama
init(autoreset=True, convert=True)
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# =============================
# ASCII BANNER
# =============================
BANNER = r"""
 ____        __  __       _       __  __           _
|  _ \ _   _|  \/  | __ _| |_ ___|  \/  | ___   __| | ___  ___  ___
| |_) | | | | |\/| |/ _` | __/ _ \ |\/| |/ _ \ / _` |/ _ \/ __|/ _ \
|  __/| |_| | |  | | (_| | ||  __/ |  | | (_) | (_| |  __/\__ \  __/
|_|    \__, |_|  |_|\__,_|\__\___|_|  |_|\___/ \__,_|\___||___/\___|
       |___/
"""

# =============================
# HELP / ARGUMENTS
# =============================
def print_help():
    print(BANNER)
    print(f"{PROGRAM_NAME} {VERSION} - Author: {AUTHOR}")
    print("Malware Semantic Scanner using Vector DB")
    print("="*70)
    print("""
Usage: python scanner.py <target_file> [options]

Options:
  -h, --help               Show this help message and exit
  -s, --only-suspicious    Show only functions flagged as malicious
  -r, --report <file>      Save suspicious functions report to <file>

Examples:
  python scanner.py test_file.py
  python scanner.py test_file.py -s
  python scanner.py test_file.py -s -r report.txt
""")

# Check help first before any loading
if "--help" in sys.argv or "-h" in sys.argv:
    print_help()
    sys.exit(0)

# =============================
# SUPPRESS HF WARNINGS
# =============================
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)

# =============================
# LOAD MODEL
# =============================
print(BANNER)
print(f"{PROGRAM_NAME} {VERSION} - Author: {AUTHOR}")
print("Malware Semantic Scanner using Vector DB")
print("="*70)
print("[+] Loading embedding model...")
model = SentenceTransformer("all-MiniLM-L6-v2")

# =============================
# FUNCTION EXTRACTION
# =============================
def extract_functions(code):
    functions = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return functions
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            start = node.lineno - 1
            end = getattr(node, 'end_lineno', node.lineno)
            func_lines = code.splitlines()[start:end]
            func_code = "\n".join(func_lines)
            functions.append((node.name, func_code))
    return functions

# =============================
# BUILD OR LOAD MALWARE INDEX
# =============================
def build_malware_index(directory):
    all_funcs = []
    func_names = []
    for file in os.listdir(directory):
        if file.endswith(".py"):
            path = os.path.join(directory, file)
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            funcs = extract_functions(code)
            if not funcs:
                funcs = [("whole_file", code)]
            for fname, fcode in funcs:
                all_funcs.append(fcode)
                func_names.append(f"{file}:{fname}")
    return all_funcs, func_names

if os.path.exists(INDEX_FILE) and os.path.exists(NAMES_FILE):
    print("[+] Loading existing FAISS index...")
    index = faiss.read_index(INDEX_FILE)
    with open(NAMES_FILE, "rb") as f:
        malware_func_names = pickle.load(f)
    print(f"[+] Loaded index with {len(malware_func_names)} malware functions.")
else:
    print("[+] Creating new FAISS index from malware functions...")
    malware_funcs, malware_func_names = build_malware_index(MALWARE_DIR)
    if not malware_funcs:
        print(f"{RED}No malware samples/functions found in folder: {MALWARE_DIR}{RESET}")
        sys.exit(1)
    embeddings = model.encode(malware_funcs)
    faiss.normalize_L2(embeddings)
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatIP(dimension)
    index.add(np.array(embeddings))
    # Save index and function names
    faiss.write_index(index, INDEX_FILE)
    with open(NAMES_FILE, "wb") as f:
        pickle.dump(malware_func_names, f)
    print(f"[+] Indexed {len(malware_funcs)} malware functions.")

# =============================
# SCAN FUNCTION
# =============================
def scan_file(filepath, show_only_suspicious=False, report_file=None):
    if not os.path.exists(filepath):
        print(f"{RED}❌ File '{filepath}' not found. Please check the path.{RESET}")
        return

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    functions = extract_functions(code)
    if not functions:
        functions = [("whole_file", code)]

    report_lines = []

    for func_name, func_code in functions:
        embedding = model.encode([func_code])
        faiss.normalize_L2(embedding)
        D, I = index.search(np.array(embedding), k=min(TOP_K, len(malware_func_names)))

        is_suspicious = float(D[0][0]) >= SIMILARITY_THRESHOLD

        if not show_only_suspicious or is_suspicious:
            output_lines = [f"\n=== Scan Result for function '{func_name}' ==="]
            for rank in range(len(I[0])):
                score = float(D[0][rank])
                match_name = malware_func_names[I[0][rank]]
                color = RED if score >= SIMILARITY_THRESHOLD else GREEN
                output_lines.append(f"{color}Top {rank+1} match: {match_name} - Similarity: {score:.4f}{RESET}")
            if is_suspicious:
                output_lines.append(f"{RED}⚠️  POSSIBLE MALICIOUS CODE DETECTED in '{func_name}'!{RESET}")
            elif not show_only_suspicious:
                output_lines.append(f"{GREEN}✅ Function '{func_name}' appears safe.{RESET}")
            print("\n".join(output_lines))

        if is_suspicious and report_file:
            report_lines.append(f"{func_name}: {float(D[0][0]):.4f} -> {malware_func_names[I[0][0]]}")

    # Write report file if requested
    if report_file and report_lines:
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("Suspicious Functions Report\n")
            f.write("="*50 + "\n")
            f.write("\n".join(report_lines))
        print(f"\n{YELLOW}Report saved to {report_file}{RESET}")

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    show_only_suspicious = "--only-suspicious" in sys.argv or "-s" in sys.argv
    report_file = None

    # Parse report file argument
    if "--report" in sys.argv:
        idx = sys.argv.index("--report")
        if idx + 1 < len(sys.argv):
            report_file = sys.argv[idx + 1]
    elif "-r" in sys.argv:
        idx = sys.argv.index("-r")
        if idx + 1 < len(sys.argv):
            report_file = sys.argv[idx + 1]

    # Get target file path (first arg that is not a flag)
    target = None
    for arg in sys.argv[1:]:
        if not arg.startswith("-") and arg != report_file:
            target = arg
            break

    if not target:
        target = input("Enter path to Python file to scan: ")

    scan_file(target, show_only_suspicious, report_file)