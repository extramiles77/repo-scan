# Changelog

## 0.3.0
- **Cek update:** `--diff BASE..HEAD` membandingkan dua versi, menandai temuan BARU, dan mencantumkan file yang berubah. `--only-new` menyembunyikan temuan lama.
- **Pindai isi dependensi:** `--deep-deps N` mengunduh dependensi langsung npm/PyPI dari registry resmi (checksum diverifikasi, tidak di-install) lalu memindainya.
- **Aliran data:** aturan `DATAFLOW_EXFIL` untuk data sensitif yang dibaca lalu dikirim lewat jaringan di file yang sama. Akses kredensial tanpa pengiriman otomatis diturunkan tingkatnya.
- **Reputasi GitHub:** `--reputation` (umur akun & repo, lonjakan bintang, fork dari repo populer, repo diarsipkan).
- **Riwayat commit:** `--history N` mencari rahasia & payload yang pernah di-commit lalu dihapus.
- **Alat eksternal:** `--external` menggabungkan gitleaks, trufflehog, semgrep, osv-scanner; `--yara-rules`.
- **Ignore & baseline:** `--ignore FILE` dan `--baseline findings.json`; setiap temuan punya `fingerprint`.
- **Anti-manipulasi:** aturan `AI_SCANNER_MANIPULATION` dan `SCANNER_EVASION`.
- **Laporan dwibahasa:** `--lang en`.
- **GitHub Action** (`action.yml`) dengan komentar PR, job summary, dan mode diff.
- **Benchmark:** `tools/benchmark.py` untuk mengukur tingkat deteksi & alarm palsu.
- Git dijalankan tanpa hooks/fsmonitor/textconv; isi versi diambil langsung dari objek git (tanpa checkout).
- `--all` untuk mengaktifkan semua pemeriksaan sekaligus.

## 0.2.0
- Pembacaan `.env`, pola ransomware, Makefile/pyproject/Dockerfile/compose, decode base64/hex otomatis, izin tool terlalu luas, 267 paket populer untuk typosquatting, OSV, `report.md`, `--fail-on`, laporan bertema Modern SaaS.

## 0.1.0
- Rilis pertama: pemindai statis 10 kategori, tinjauan AI, laporan HTML, plugin + skill.
