import os
import sys
import pickle
import faiss
import numpy as np
import ast
import logging
import warnings
import contextlib
from pathlib import Path
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time

# =============================
# CONFIG
# =============================
MALWARE_DIR = "malware_samples"
INDEX_FILE = "malware.index"
NAMES_FILE = "malware_functions.pkl"
TOP_K = 3
DEFAULT_THRESHOLD = 0.8
PROGRAM_NAME = "PyMalVectorScanner"
VERSION = "v4.4"
AUTHOR = "Batsakidis Athanasios"

# =============================
# COLORS
# =============================
init(autoreset=True, convert=True)
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL

# =============================
# BANNER
# =============================
BANNER = r"""
 ____        __  __       _       __  __           _
|  _ \ _   _|  \/  | __ _| |_ ___|  \/  | ___   __| | ___  ___  ___
| |_) | | | | |\/| |/ _` | __/ _ \ |\/| |/ _ \ / _` |/ _ \/ __|/ _ \
|  __/| |_| | |  | | (_| | ||  __/ |  | | (_) | (_| |  __/\__ \  __/
|_|    \__, |_|  |_|\__,_|\__\___|_|  |_|\___/ \__,_|\___||___/\___|
       |___/
"""
print(BANNER)
print(f"{PROGRAM_NAME} {VERSION} - Author: {AUTHOR}")
print("=" * 70)

# =============================
# HELP
# =============================
def print_help():
    print("""
Usage: python scanner.py [options]

Options:
  -h, --help               Show help
  -s, --only-suspicious    Show only suspicious functions
  -r, --report <file>      Save report (JSON or HTML)
  -f, --folder <path>      Scan folder recursively
  --threshold <float>      Similarity threshold (default 0.8)
  --verbose                Detailed output
""")
    sys.exit(0)

if "-h" in sys.argv or "--help" in sys.argv:
    print_help()

# =============================
# FULL SILENT MODE FOR HF
# =============================
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
warnings.filterwarnings("ignore")

# =============================
# SILENT MODEL LOADING
# =============================
print("[+] Loading embedding model...")

from sentence_transformers import SentenceTransformer

with contextlib.redirect_stdout(open(os.devnull, "w")), \
     contextlib.redirect_stderr(open(os.devnull, "w")):

    # Fake progress for UX
    for _ in tqdm(range(5), desc="Model loading", ncols=70):
        time.sleep(0.4)

    model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")

print("[+] Model loaded successfully ✅")

# =============================
# UTILS
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
            end = getattr(node, "end_lineno", node.lineno)
            func_lines = code.splitlines()[start:end]
            functions.append((node.name, "\n".join(func_lines)))

    return functions


def collect_files(path):
    p = Path(path)
    if p.is_file() and p.suffix == ".py":
        return [str(p)]
    elif p.is_dir():
        return [str(f) for f in p.rglob("*.py")]
    return []

# =============================
# LOAD / BUILD INDEX
# =============================
if os.path.exists(INDEX_FILE) and os.path.exists(NAMES_FILE):
    print("[+] Loading existing FAISS index...")
    index = faiss.read_index(INDEX_FILE)
    with open(NAMES_FILE, "rb") as f:
        malware_func_names = pickle.load(f)
    print(f"[+] Loaded index with {len(malware_func_names)} functions.")
else:
    print("[+] Creating FAISS index from malware samples...")
    malware_funcs = []
    malware_func_names = []

    for file in os.listdir(MALWARE_DIR):
        if file.endswith(".py"):
            with open(os.path.join(MALWARE_DIR, file), "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()

            funcs = extract_functions(code) or [("whole_file", code)]

            for fname, fcode in funcs:
                malware_funcs.append(fcode)
                malware_func_names.append(f"{file}:{fname}")

    embeddings = model.encode(malware_funcs)
    faiss.normalize_L2(embeddings)

    index = faiss.IndexFlatIP(embeddings.shape[1])
    index.add(np.array(embeddings))

    faiss.write_index(index, INDEX_FILE)
    with open(NAMES_FILE, "wb") as f:
        pickle.dump(malware_func_names, f)

    print(f"[+] Indexed {len(malware_funcs)} malware functions.")

# =============================
# ARGUMENT PARSING
# =============================
show_only_suspicious = "-s" in sys.argv or "--only-suspicious" in sys.argv
report_file = None
folder_path = None
threshold = DEFAULT_THRESHOLD

if "-r" in sys.argv:
    report_file = sys.argv[sys.argv.index("-r") + 1]
elif "--report" in sys.argv:
    report_file = sys.argv[sys.argv.index("--report") + 1]

if "-f" in sys.argv:
    folder_path = sys.argv[sys.argv.index("-f") + 1]
elif "--folder" in sys.argv:
    folder_path = sys.argv[sys.argv.index("--folder") + 1]

if "--threshold" in sys.argv:
    threshold = float(sys.argv[sys.argv.index("--threshold") + 1])

targets = []
for arg in sys.argv[1:]:
    if not arg.startswith("-") and arg not in [report_file, folder_path]:
        targets.append(arg)

if folder_path:
    targets.extend(collect_files(folder_path))

if not targets:
    targets.append(input("Enter file/folder to scan: "))

# =============================
# SCAN FUNCTION
# =============================
def scan_file(filepath):
    results = []

    if not os.path.exists(filepath):
        return results

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    functions = extract_functions(code) or [("whole_file", code)]

    for func_name, func_code in functions:
        embedding = model.encode([func_code])
        faiss.normalize_L2(embedding)

        D, I = index.search(np.array(embedding), k=min(TOP_K, len(malware_func_names)))
        score = float(D[0][0])
        is_suspicious = score >= threshold

        if not show_only_suspicious or is_suspicious:
            results.append({
                "file": filepath,
                "function": func_name,
                "top_match": malware_func_names[I[0][0]],
                "similarity": score,
                "is_suspicious": is_suspicious
            })

    return results

# =============================
# MULTITHREADED SCAN
# =============================
all_results = []

with ThreadPoolExecutor(max_workers=8) as executor:
    futures = {executor.submit(scan_file, f): f for f in targets}

    for future in tqdm(as_completed(futures),
                       total=len(futures),
                       desc="Scanning",
                       ncols=80,
                       position=0,
                       leave=True):

        all_results.extend(future.result())

# =============================
# RESULTS
# =============================
for r in all_results:
    color = RED if r["is_suspicious"] else GREEN
    print(f"\n=== {r['file']} :: {r['function']} ===")
    print(f"{color}Top match: {r['top_match']} | Similarity: {r['similarity']:.4f}{RESET}")

# =============================
# REPORT
# =============================
if report_file and all_results:
    ext = Path(report_file).suffix.lower()

    if ext == ".json":
        import json
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=4)
    else:
        from jinja2 import Template

        html = """
        <html><body>
        <h2>PyMalVectorScanner Report</h2>
        <table border=1 cellpadding=5>
        <tr><th>File</th><th>Function</th><th>Top Match</th><th>Similarity</th></tr>
        {% for r in results %}
        <tr style="color:{% if r.is_suspicious %}red{% else %}green{% endif %}">
        <td>{{r.file}}</td>
        <td>{{r.function}}</td>
        <td>{{r.top_match}}</td>
        <td>{{"%.4f"|format(r.similarity)}}</td>
        </tr>
        {% endfor %}
        </table></body></html>
        """

        template = Template(html)
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(template.render(results=all_results))

    print(f"{YELLOW}Report saved to {report_file}{RESET}")

print(f"\n{GREEN}✅ Scan completed successfully!{RESET}")