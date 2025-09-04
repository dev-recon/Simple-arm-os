import re
import sys
from pathlib import Path

# Regex pour trouver kprintf("...") avec arguments
call_re = re.compile(r'\b(KDEBUG|KWARN|KERROR|KINFO|kprintf)\s*\((.*)\)\s*;')

def count_formats(fmt: str) -> int:
    # enlève les "%%"
    fmt = fmt.replace("%%", "")
    # compte %d, %x, %p, %s etc
    return len(re.findall(r"%[-.0-9]*[Xduxpsczl]", fmt))

def analyze_file(path: Path):
    with path.open() as f:
        code = f.read()
    for match in call_re.finditer(code):
        func, args = match.groups()
        # args = '"..." , autres'
        parts = args.split(',', 1)
        if not parts:
            continue
        fmt_str = parts[0].strip()
        if not (fmt_str.startswith('"') and fmt_str.endswith('"')):
            continue
        fmt = fmt_str.strip('"')
        n_fmt = count_formats(fmt)
        n_args = 0
        if len(parts) > 1:
            n_args = len([a for a in parts[1].split(',') if a.strip()])
        if n_fmt != n_args:
            print(f"[WARN] {path}:{match.start()} {func} → {n_fmt} formats vs {n_args} args")
            print(f"       {args[:80]}...")

if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for file in root.rglob("*.c"):
        analyze_file(file)
