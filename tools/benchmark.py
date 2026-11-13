#!/usr/bin/env python3
"""
Repo Scan — benchmark deteksi.

Mengukur berapa banyak sampel BERBAHAYA yang terdeteksi dan berapa banyak sampel AMAN yang salah ditandai.
Sampel hanya DIBACA, tidak pernah dijalankan. Tetap jalankan di VM/container terpisah bila memakai malware asli.

Contoh:
  # dataset paket berbahaya (mis. DataDog malicious-software-packages-dataset, zip ber-password "infected")
  python3 -I tools/benchmark.py --malicious ~/datasets/npm-malicious --zip-password infected --limit 300
  # tambah sampel aman untuk mengukur alarm palsu
  python3 -I tools/benchmark.py --malicious ./mal --benign ./benign --csv hasil.csv

Setiap sampel boleh berupa folder, .zip, .tgz/.tar.gz, atau .whl. Arsip di dalam zip ikut diekstrak satu tingkat.
"""
import argparse, csv, importlib.util, os, shutil, sys, tempfile, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("repo_scan", os.path.join(HERE, "..", "skills", "repo-scan", "scripts", "repo_scan.py"))
rs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rs)

DETECTED = {"BAHAYA", "WASPADA"}


def unpack(path, work, password=None):
    """Kembalikan folder berisi isi sampel (diekstrak dengan aman)."""
    if os.path.isdir(path):
        return path
    dest = tempfile.mkdtemp(dir=work)
    low = path.lower()
    if low.endswith((".zip", ".whl")):
        with zipfile.ZipFile(path) as z:
            if password:
                z.setpassword(password.encode())
            root = os.path.realpath(dest)
            for info in z.infolist():
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/") or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    continue
                out = os.path.realpath(os.path.join(root, name))
                if out.startswith(root + os.sep):
                    z.extract(info, dest)
    elif low.endswith((".tgz", ".tar.gz", ".tar")):
        rs.safe_extract_tar(path, dest)
    else:
        os.makedirs(os.path.join(dest, "f"), exist_ok=True)
        shutil.copy(path, os.path.join(dest, "f"))
        return dest
    # arsip di dalam arsip (umum di dataset npm/PyPI)
    for dp, _, fs in os.walk(dest):
        for f in fs:
            if f.lower().endswith((".tgz", ".tar.gz", ".whl")):
                inner = os.path.join(dp, f)
                try:
                    if f.lower().endswith(".whl"):
                        rs.safe_extract_zip(inner, inner + "_x")
                    else:
                        rs.safe_extract_tar(inner, inner + "_x")
                except Exception:
                    pass
    return dest


def scan(folder):
    res = rs.finalize(rs.Scanner(folder).run())
    return res["summary"]["auto_level"], res["summary"]["by_severity"], sorted({f["rule"] for f in res["findings"]})


def run_set(folder, label, work, password, limit):
    rows = []
    items = sorted(os.listdir(folder))[:limit] if limit else sorted(os.listdir(folder))
    for i, name in enumerate(items, 1):
        p = os.path.join(folder, name)
        try:
            level, sev, rules = scan(unpack(p, work, password))
            rows.append({"set": label, "sample": name, "level": level, "critical": sev["critical"], "high": sev["high"],
                         "rules": " ".join(rules[:12]), "error": ""})
        except Exception as ex:
            rows.append({"set": label, "sample": name, "level": "ERROR", "critical": 0, "high": 0, "rules": "", "error": str(ex)[:120]})
        if i % 25 == 0:
            print(f"  {label}: {i}/{len(items)}", file=sys.stderr)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--malicious", help="folder berisi sampel berbahaya")
    ap.add_argument("--benign", help="folder berisi sampel aman")
    ap.add_argument("--zip-password", help="password arsip sampel (mis. 'infected')")
    ap.add_argument("--limit", type=int, default=0, help="batasi jumlah sampel per set")
    ap.add_argument("--csv", help="simpan hasil per sampel ke CSV")
    a = ap.parse_args()
    if not a.malicious and not a.benign:
        ap.error("isi --malicious dan/atau --benign")
    work = tempfile.mkdtemp(prefix="rs_bench_")
    rows = []
    try:
        if a.malicious:
            rows += run_set(a.malicious, "malicious", work, a.zip_password, a.limit)
        if a.benign:
            rows += run_set(a.benign, "benign", work, a.zip_password, a.limit)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for label in ("malicious", "benign"):
        rs_ = [r for r in rows if r["set"] == label and r["level"] != "ERROR"]
        if not rs_:
            continue
        hit = sum(r["level"] in DETECTED for r in rs_)
        crit = sum(r["level"] == "BAHAYA" for r in rs_)
        errs = sum(1 for r in rows if r["set"] == label and r["level"] == "ERROR")
        if label == "malicious":
            print(f"Berbahaya: {len(rs_)} sampel · terdeteksi (BAHAYA/WASPADA) {hit} = {hit / len(rs_):.1%} · BAHAYA {crit / len(rs_):.1%} · error {errs}")
        else:
            print(f"Aman: {len(rs_)} sampel · alarm palsu (BAHAYA/WASPADA) {hit} = {hit / len(rs_):.1%} · BAHAYA {crit / len(rs_):.1%} · error {errs}")
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"CSV: {a.csv}")


if __name__ == "__main__":
    main()
