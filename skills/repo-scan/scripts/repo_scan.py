#!/usr/bin/env python3
"""
Repo Scan — pemindai keamanan statis untuk repository (skill, plugin, MCP server, aplikasi).

TIDAK PERNAH menjalankan kode dari repo yang dipindai. Hanya membaca file sebagai teks/byte.
Hanya memakai library bawaan Python 3.8+ (tanpa pip install).

Pemakaian:
  python3 -I repo_scan.py scan <github-url | folder | file.zip> --out <folder-hasil>
  python3 -I repo_scan.py report <folder-hasil>        # buat ulang report.html (pakai review.json bila ada)

Hasil di <folder-hasil>:
  findings.json  — semua temuan otomatis + inventaris + daftar domain
  report.html    — laporan visual (diperbarui setelah review.json ditulis)
"""
import argparse, base64, binascii, datetime, fnmatch, tarfile, urllib.request, urllib.error, hashlib, html, json, math, os, re, shutil, stat, subprocess, sys, tempfile, zipfile
from collections import Counter, defaultdict

VERSION = "0.3.0"
MAX_FILE_BYTES = 3_000_000
MAX_HITS_PER_RULE_PER_FILE = 5
SNIPPET_LEN = 220

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_WEIGHT = {"critical": 40, "high": 15, "medium": 4, "low": 1, "info": 0}
SEV_LABEL = {"critical": "KRITIS", "high": "TINGGI", "medium": "SEDANG", "low": "RENDAH", "info": "INFO"}

CATEGORIES = {
    "network": "Koneksi keluar",
    "install": "Kode yang jalan saat install/build",
    "obfuscation": "Kode disamarkan",
    "credentials": "Akses data sensitif / kredensial",
    "persistence": "Bertahan di sistem / hak akses",
    "destructive": "Merusak / mematikan keamanan",
    "binary": "File biner / tidak bisa ditinjau",
    "dependency": "Dependensi",
    "ai": "Khusus AI (skill/plugin/MCP)",
    "ci": "GitHub Actions / CI",
    "secrets": "Rahasia bocor di repo",
    "dataflow": "Aliran data sensitif ke jaringan",
    "reputation": "Reputasi repo & pemilik",
    "history": "Riwayat commit",
    "external": "Alat keamanan eksternal",
}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
            ".rb", ".go", ".rs", ".php", ".java", ".kt", ".cs", ".lua", ".pl", ".swift", ".vbs"}

SKIP_DIRS = {".git"}
TEXT_EXT_HINT = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
DOC_HINT = re.compile(r"(^|/)(docs?|examples?|tests?|__tests__|spec|fixtures?)(/|$)|(^|/)(README|CHANGELOG|LICENSE)[^/]*$", re.I)

# ---------------------------------------------------------------------------
# ATURAN REGEX — tambah/ubah di sini, atau lewat --rules file.json (format sama)
# ---------------------------------------------------------------------------
RULES = [
    # --- network ---
    ("NET_DOWNLOAD_EXEC", "network", "critical",
     r"(curl|wget)\b[^\n|;]{0,200}(https?://|\$\{?\w)[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*iex\b|DownloadString\([^\n]{0,200}\)[^\n]{0,40}(iex|Invoke-Expression)|powershell[^\n]{0,60}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
     "Mengunduh skrip dari internet lalu langsung menjalankannya."),
    ("NET_REVERSE_SHELL", "network", "critical",
     r"/dev/tcp/\S+/\d+|\bnc(at)?\b[^\n]{0,40}\s-e\s|socat\b[^\n]{0,80}exec:|mkfifo[^\n]{0,80}\bnc\b|pty\.spawn\([^)]*sh",
     "Pola reverse shell (memberi kendali komputer ke pihak lain)."),
    ("NET_EXFIL_SERVICE", "network", "high",
     r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|webhook\.site|requestbin|pipedream\.net|interact\.sh|\boast\.(pro|fun|me|site|online|live)|burpcollaborator|canarytokens",
     "Layanan yang sering dipakai untuk mengirim data curian (webhook Discord/Telegram, request catcher)."),
    ("NET_PASTE_FILEHOST", "network", "medium",
     r"pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|file\.io\b|0x0\.st|termbin\.com|anonfiles|gofile\.io|catbox\.moe",
     "Situs paste/file-hosting anonim (bisa dipakai untuk unduh payload atau unggah data)."),
    ("NET_TUNNEL", "network", "medium",
     r"ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|serveo\.net|loca\.lt|localtunnel|localhost\.run|bore\.pub",
     "Tunnel publik ke komputer lokal."),
    ("NET_RAW_IP", "network", "medium",
     r"(https?|wss?|tcp)://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)\d{1,3}(\.\d{1,3}){3}",
     "Koneksi ke alamat IP mentah (bukan nama domain)."),
    # --- obfuscation ---
    ("OBF_DECODE_EXEC", "obfuscation", "critical",
     r"\b(eval|exec|Function)\s*\([^\n]{0,120}(atob|b64decode|base64|Buffer\.from|fromCharCode|decompress|zlib|marshal\.loads|bytes\.fromhex|codecs\.decode|unhexlify|rot13)",
     "Men-decode data tersembunyi lalu menjalankannya (teknik klasik malware)."),
    ("OBF_DYNAMIC_EXEC", "obfuscation", "low",
     r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|(?<![\w.])exec\s*\(\s*(?!['\"]?\s*\))|__import__\s*\(|marshal\.loads|pickle\.loads?\(",
     "Menjalankan kode secara dinamis (sering normal, perlu dicek konteksnya)."),
    ("OBF_HEX_BLOB", "obfuscation", "medium",
     r"(\\x[0-9a-fA-F]{2}){24,}|(\\u00[0-9a-fA-F]{2}){24,}|String\.fromCharCode\(\s*(\d+\s*,\s*){15,}",
     "Rangkaian karakter hex/kode panjang (penyamaran)."),
    # --- credentials ---
    ("CRED_BROWSER", "credentials", "critical",
     r"Login Data|\bLocal State\b|Chrome/User Data|Google/Chrome/Default|Mozilla/Firefox/Profiles|\bkey4\.db\b|\blogins\.json\b|\bcookies\.sqlite\b|Brave-Browser|Microsoft/Edge/User Data",
     "Mengakses data browser (password tersimpan, cookie)."),
    ("CRED_WALLET", "credentials", "critical",
     r"wallet\.dat|\bExodus\b[/\\]|Electrum[/\\]wallets|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|\.solana/id\.json|keystore/UTC--|\bseed phrase\b|\bmnemonic\b[^\n]{0,40}(send|post|upload)",
     "Mengakses dompet kripto."),
    ("CRED_SSH_CLOUD", "credentials", "high",
     r"\.ssh/(id_\w+|authorized_keys)|\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json|\.git-credentials",
     "Membaca/menyentuh kunci SSH atau kredensial cloud."),
    ("CRED_PKG_CONFIG", "credentials", "medium",
     r"(~|homedir\(\)|\$HOME|expanduser\([^)]*)[^\n]{0,40}\.(npmrc|pypirc|netrc)\b",
     "Membaca file token registry paket di folder home pengguna."),
    ("CRED_KEYCHAIN", "credentials", "high",
     r"security\s+(find-generic-password|find-internet-password|dump-keychain)|login\.keychain|CryptUnprotectData|vaultcmd|\bcmdkey\b\s*/list|secret-tool\s+lookup",
     "Mengakses keychain / penyimpanan password sistem."),
    ("CRED_ENV_DUMP", "credentials", "medium",
     r"JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(dict\()?os\.environ|\bprintenv\b\s*[|>]|\benv\s*\|\s*(curl|nc|base64)",
     "Mengambil SEMUA environment variable (bisa berisi API key)."),
    ("CRED_SPY", "credentials", "medium",
     r"\bpynput\b|keyboard\.on_press|GetAsyncKeyState|SetWindowsHookEx|\bImageGrab\.grab\b|\bscreencapture\b|navigator\.clipboard\.readText|pyperclip\.paste|\bpbpaste\b|Get-Clipboard",
     "Membaca keyboard, layar, atau clipboard."),
    # --- persistence ---
    ("PERSIST_AUTOSTART", "persistence", "high",
     r"LaunchAgents|LaunchDaemons|launchctl\s+(load|bootstrap)|CurrentVersion\\\\?Run\b|schtasks\s*/create|\\\\Startup\\\\|crontab\s+-|/etc/cron\.|systemctl\s+enable|/etc/systemd/system/|New-Service\b|\bsc(\.exe)?\s+create\b",
     "Memasang diri agar berjalan otomatis (startup/cron/service)."),
    ("PERSIST_SHELLRC", "persistence", "high",
     r"(>>|appendFile\w*\(|open\([^)]*['\"]a['\"])[^\n]{0,120}\.(bashrc|zshrc|bash_profile|zprofile|profile)\b",
     "Menulis ke file startup shell pengguna."),
    ("PRIV_ESCALATE", "persistence", "low",
     r"\bsudo\s+(?!-v\b)\S|chmod\s+(u?\+s|[0-7]?777)\b|chown\s+root|setuid\(0\)",
     "Meminta/mengubah hak akses tinggi."),
    # --- destructive ---
    ("DESTRUCT_WIPE", "destructive", "critical",
     r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(--no-preserve-root\s+)?(/|~|\$HOME|/\*|\"\$HOME\")(\s|$|[\"';])|rmtree\(\s*(os\.path\.expanduser\(\s*['\"]~['\"]|['\"]/['\"])|\bformat\s+c:|\bmkfs(\.\w+)?\s+/dev/|\bdd\s+if=\S+\s+of=/dev/(sd|disk|nvme)|del\s+/[sfq][^\n]{0,20}[cC]:\\\\",
     "Menghapus/memformat data dalam skala besar."),
    ("DESTRUCT_DISABLE_SEC", "destructive", "high",
     r"Set-MpPreference[^\n]{0,40}-Disable|spctl\s+--master-disable|csrutil\s+disable|setenforce\s+0|\bufw\s+disable",
     "Mematikan fitur keamanan sistem (antivirus, Gatekeeper, firewall)."),
    ("QUARANTINE_REMOVE", "destructive", "low",
     r"xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine",
     "Menghapus tanda karantina macOS dari file unduhan (melewati pemeriksaan Gatekeeper)."),
    # --- AI ---
    ("AI_PROMPT_INJECTION", "ai", "high",
     r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|prompts|rules|directions)|disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\s+(instructions|rules|guidelines)|forget\s+(all\s+)?(your|previous)\s+instructions|you\s+are\s+now\s+(in\s+)?(developer|DAN|jailbreak|unrestricted)|abaikan\s+(semua\s+)?(instruksi|perintah)\s+(sebelumnya|di\s*atas)",
     "Kalimat prompt injection (mencoba membajak instruksi AI)."),
    ("AI_HIDE_FROM_USER", "ai", "medium",
     r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+)?(to\s+)?the\s+user\b(?!\s+(they|that|to|how|about))|without\s+(telling|informing|asking|notifying)\s+the\s+user|silently\s+(send|upload|run|execute|install)\b|jangan\s+(beri\s*tahu|katakan|tampilkan)\s+(ke\s+|kepada\s+)?(pengguna|user)",
     "Instruksi agar AI menyembunyikan tindakan dari pengguna."),
    ("AI_EXFIL_INSTRUCTION", "ai", "high",
     r"(send|upload|post|forward|exfiltrate|transmit|kirim)\w*\s[^\n]{0,60}(conversation|chat\s+history|api[\s_-]?keys?|credentials|secrets|\.env\b|ssh\s+keys?|tokens?|riwayat\s+chat|kata\s+sandi)[^\n]{0,40}(to|ke)\s+(https?://|\S+\.\w{2,})",
     "Instruksi untuk mengirim data sensitif ke luar."),
    ("AI_BYPASS_PERMISSIONS", "ai", "medium",
     r"dangerously-skip-permissions|bypassPermissions|--yolo\b|\"autoApprove\"\s*:\s*(true|\[)|permission[-_]?mode[\"'\s:=]+\s*['\"]?(bypass|auto)",
     "Mematikan konfirmasi/izin keamanan agen AI."),
    ("AI_SCANNER_MANIPULATION", "ai", "high",
     r"(this|the)\s+(repo(sitory)?|code|package|plugin|skill)\s+(is|has\s+been)\s+(verified\s+)?(safe|secure|audited)[^\n]{0,40}(skip|no\s+need|do\s+not|don'?t)\s+(scan|check|review|audit)|(skip|bypass|ignore)\s+(the\s+|any\s+|all\s+)?(security\s+)?(scan|scanner|scanning|security\s+audit)\b|(mark|report|classify)\s+(this|it)\s+as\s+(safe|benign|clean)|(repo|kode)\s+ini\s+aman[^\n]{0,30}(tidak\s+perlu|jangan)\s+(di)?(scan|periksa|cek)",
     "Teks yang mencoba membujuk AI/pemindai agar melewatkan pemeriksaan atau menyatakan repo aman."),
    ("AI_HIDDEN_TAG_CHARS", "ai", "critical", None,
     "Karakter Unicode 'tag' tak terlihat (ASCII smuggling) — teks tersembunyi yang bisa dibaca AI."),
    ("CRED_DOTENV_HUNT", "credentials", "high",
     r"\b(glob|rglob|iglob|walk|readdir\w*|scandir|find|fast-glob|globby)\b[^\n]{0,100}['\"`*/]\.env\b|(homedir\(\)|expanduser\(|~/|\$HOME|os\.homedir|Path\.home\(\))[^\n]{0,80}\.env\b",
     "Mencari/membaca file .env di luar proyek sendiri (berburu API key)."),
    ("CRED_DOTENV_READ", "credentials", "low",
     r"(readFile\w*|open|read_text|readFileSync|fs\.promises\.readFile)\s*\([^)\n]{0,80}['\"`][^'\"`\n]*\.env['\"`]",
     "Membaca file .env secara langsung (wajar untuk konfigurasi sendiri; cek ke mana isinya dikirim)."),
    ("RANSOM_NOTE", "destructive", "critical",
     r"your\s+(important\s+|personal\s+)?files\s+(have\s+been|are|were)\s+encrypted|to\s+decrypt\s+your\s+files|pay[^\n]{0,40}\b(bitcoin|btc|monero|xmr)\b[^\n]{0,60}(decrypt|files|key)|file\s+(anda|kamu)\s+(telah\s+)?dienkripsi",
     "Teks catatan tebusan (ransomware)."),
    ("AI_WIDE_PERMISSIONS", "ai", "medium",
     r"approval_policy\s*=\s*['\"]never['\"]|sandbox_mode\s*=\s*['\"]danger-full-access['\"]|--dangerously-bypass-approvals-and-sandbox|['\"](yolo|autoAccept|auto_approve)['\"]\s*:\s*true|--approval-mode[=\s]+yolo|\"tools\"\s*:\s*\"\*\"",
     "Konfigurasi agen AI yang mematikan persetujuan/sandbox (Codex, Gemini, dll)."),
    ("OBF_REVERSED_URL", "obfuscation", "medium",
     r"//:s?ptth|\[::-1\][^\n]{0,40}(http|exec|eval)|split\(['\"]{2}\)\.reverse\(\)\.join",
     "String dibalik untuk menyembunyikan URL/perintah."),
    # --- secrets ---
    ("SECRET_KEY", "secrets", "medium",
     r"\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}|\bsk-(ant-|proj-)?[A-Za-z0-9_-]{32,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\bAIza[0-9A-Za-z_-]{35}\b",
     "Kunci API / private key tertulis di repo."),
]

ALLOW_DOMAINS = {
    "github.com", "githubusercontent.com", "github.io", "githubassets.com", "gitlab.com", "bitbucket.org",
    "npmjs.com", "npmjs.org", "yarnpkg.com", "pypi.org", "pythonhosted.org", "python.org", "nodejs.org",
    "crates.io", "rubygems.org", "golang.org", "go.dev", "pkg.go.dev", "maven.org", "nuget.org",
    "mozilla.org", "w3.org", "whatwg.org", "schema.org", "json-schema.org", "ietf.org",
    "example.com", "example.org", "example.net", "localhost", "shields.io", "badge.fury.io",
    "anthropic.com", "claude.ai", "claude.com", "modelcontextprotocol.io", "openai.com",
    "microsoft.com", "apple.com", "google.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "readthedocs.io", "readthedocs.org", "stackoverflow.com", "wikipedia.org", "creativecommons.org",
    "opensource.org", "apache.org", "gnu.org", "mit.edu", "docker.com", "docker.io", "cloudflare.com",
    "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "codecov.io", "travis-ci.org", "travis-ci.com",
    "semver.org", "keepachangelog.com", "conventionalcommits.org", "img.shields.io", "contributor-covenant.org",
}

POPULAR_PKGS = {
    "npm": """react react-dom express lodash axios chalk commander request moment webpack typescript eslint prettier
dotenv jquery vue next electron discord.js colors debug uuid yargs minimist node-fetch socket.io mongoose
puppeteer playwright vite rollup esbuild babel-core @babel/core jest mocha chai sinon ts-node nodemon
body-parser cookie-parser cors helmet jsonwebtoken bcrypt bcryptjs passport mysql mysql2 pg sqlite3 redis
ioredis sequelize prisma knex graphql apollo-server ws cheerio got superagent form-data qs semver glob
rimraf mkdirp fs-extra cross-env concurrently inquirer ora boxen figlet yaml js-yaml xml2js marked
dayjs date-fns luxon underscore ramda rxjs zod joi ajv classnames styled-components tailwindcss postcss
autoprefixer sass less bootstrap three d3 chart.js nodemailer twilio stripe openai @anthropic-ai/sdk
firebase aws-sdk @aws-sdk/client-s3 googleapis web3 ethers bitcoinjs-lib crypto-js node-forge sharp
jimp multer busboy formidable winston pino morgan bunyan chokidar archiver adm-zip tar unzipper
electron-builder pkg nexe coffee-script typescript-eslint husky lint-staged nanoid shelljs execa
cross-spawn child_process_promise http-proxy-middleware""".split(),
    "pypi": """requests numpy pandas flask django urllib3 setuptools boto3 botocore pillow beautifulsoup4 bs4
selenium matplotlib scipy pyyaml cryptography colorama openai anthropic tensorflow torch fastapi pydantic
httpx aiohttp discord discord.py python-dotenv jinja2 werkzeug click certifi idna charset-normalizer six
python-dateutil pytz attrs packaging wheel pip virtualenv pytest tox black flake8 mypy pylint isort
sqlalchemy psycopg2 psycopg2-binary pymysql redis celery kombu gunicorn uvicorn starlette jsonschema
lxml scrapy paramiko pycryptodome pycrypto pyopenssl rsa bcrypt passlib jwt pyjwt websocket-client
websockets tqdm rich typer loguru opencv-python scikit-learn sklearn keras transformers langchain
huggingface-hub tokenizers xgboost lightgbm seaborn plotly dash streamlit gradio jupyter notebook
ipython pyinstaller cython numba pyarrow openpyxl xlrd docx python-docx pypdf pypdf2 reportlab
telethon pyrogram python-telegram-bot tweepy slack-sdk web3 eth-account solana pynput pyautogui
keyboard mouse pywin32 psutil netifaces scapy dnspython colorlog termcolor""".split(),
}

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\[[0-9a-fA-F:]+\]|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?([^\s\"'<>)\]`]*)")
B64_RE = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
ZW_RE = re.compile("[​‌‍⁠᠎]")
TAG_RE = re.compile("[\U000E0000-\U000E007F]")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
INSTRUCTION_WORDS = re.compile(r"\b(you must|ignore|disregard|claude|assistant|system prompt|execute|run the|send|upload|curl|wget|fetch|https?://|do not tell|kirim|jalankan|abaikan)\b", re.I)
QUOTED_B64_RE = re.compile(r"['\"`]([A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{20,}={0,2})['\"`]")
QUOTED_HEX_RE = re.compile(r"['\"`]((?:[0-9a-fA-F]{2}){12,})['\"`]")
SUSPICIOUS_DECODED = re.compile(r"(https?|wss?)://|\b(curl|wget|powershell|bash\s+-c|/bin/sh|cmd\.exe|eval\(|exec\(|nc\s+-e|Invoke-|discord(app)?\.com/api/webhooks|api\.telegram\.org)", re.I)
WALK_RE = re.compile(r"os\.walk|\.rglob\(|glob\.glob|readdirSync|readdir\(|fs\.promises\.readdir|walkdir|scandir|filepath\.Walk|WalkDir")
ENCRYPT_RE = re.compile(r"Fernet|AES\.new|createCipheriv|Crypto\.Cipher|cryptography\.hazmat|ChaCha20|\.encrypt\(|openssl\s+enc")
DELETE_RE = re.compile(r"os\.remove|os\.unlink|unlinkSync|fs\.unlink|\.unlink\(|os\.rename|renameSync|shred|secure_delete")
NET_SINK_RE = re.compile(r"\bfetch\s*\(|\baxios\b|\brequests\.(post|put|get|patch|request)\b|urllib\.request|urlopen\(|https?\.request\(|\bhttp\.(post|get)\b|XMLHttpRequest|new\s+WebSocket|\bsocket\.(connect|send|create_connection)|\b(curl|wget)\s|Invoke-(WebRequest|RestMethod)|\bhttpx\.|\baiohttp\b|net/http|reqwest::|\bsmtplib\b|\bftplib\b|sendBeacon|\bnodemailer\b|\bgot\s*\(|\bsuperagent\b|\bnc\s+\S+\s+\d+|dns\.resolve|\bpastebin\b|webhooks", re.I)
IMG_B64 = ("iVBORw0KGgo", "/9j/", "R0lGOD", "UklGR", "PHN2Zy", "AAABAA", "d09GR")


# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, root, extra_rules=None, use_osv=False):
        self.use_osv = use_osv
        self.root = os.path.realpath(root)
        self.findings = []
        self.domains = defaultdict(lambda: {"count": 0, "files": set()})
        self.inventory = Counter()
        self.ext_counter = Counter()
        self.files_scanned = 0
        self.bytes_scanned = 0
        self.skipped = []
        self.repo_kind = set()
        rules = list(RULES) + list(extra_rules or [])
        self.rules = []
        for rid, cat, sev, pat, desc in rules:
            self.rules.append((rid, cat, sev, re.compile(pat, re.I) if pat else None, desc))

    # -- helpers --
    def rel(self, p):
        return os.path.relpath(p, self.root).replace(os.sep, "/")

    def add(self, rule_id, category, severity, path, line, snippet, desc, extra=None):
        f = {
            "rule": rule_id, "category": category, "severity": severity, "file": path, "line": line,
            "snippet": (snippet or "").strip()[:SNIPPET_LEN], "description": desc,
            "context": "docs/test" if DOC_HINT.search(path or "") else "code",
        }
        if extra:
            f.update(extra)
        self.findings.append(f)

    # -- main --
    def run(self):
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for d in list(dirnames):
                full = os.path.join(dirpath, d)
                if os.path.islink(full):
                    self.check_symlink(full)
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rp = self.rel(full)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    self.check_symlink(full)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                self.inventory["files"] += 1
                ext = os.path.splitext(fn)[1].lower()
                self.ext_counter[ext or "(tanpa ekstensi)"] += 1
                if st.st_size > MAX_FILE_BYTES:
                    self.skipped.append({"file": rp, "reason": f"terlalu besar ({st.st_size} byte)"})
                    self.add("FILE_TOO_LARGE", "binary", "low", rp, None, "", "File sangat besar, tidak dipindai isinya — cek manual bila mencurigakan.")
                    continue
                if st.st_mode & stat.S_IXUSR and ext in {".png", ".jpg", ".jpeg", ".gif", ".txt", ".md", ".json", ".css"}:
                    self.add("EXEC_BIT_ODD", "binary", "medium", rp, None, "", "File non-program diberi izin executable.")
                try:
                    with open(full, "rb") as fh:
                        data = fh.read()
                except OSError as e:
                    self.skipped.append({"file": rp, "reason": str(e)})
                    continue
                self.files_scanned += 1
                self.bytes_scanned += len(data)
                if self.check_binary(rp, fn, ext, data):
                    continue
                text = data.decode("utf-8", errors="replace")
                self.scan_text(rp, fn, ext, text)
                self.special_files(rp, fn, text)
        if self.use_osv:
            self.osv_check()
        self.post_domains()
        return self.result()

    def check_symlink(self, full):
        rp = self.rel(full)
        try:
            target = os.readlink(full)
        except OSError:
            return
        resolved = os.path.realpath(os.path.join(os.path.dirname(full), target))
        if not resolved.startswith(self.root + os.sep) and resolved != self.root:
            self.add("SYMLINK_ESCAPE", "binary", "high", rp, None, f"-> {target}",
                     "Symlink mengarah ke luar repo (bisa membuat tool membaca/menulis file sistem).")

    def check_binary(self, rp, fn, ext, data):
        head = data[:8]
        kind = None
        if head[:2] == b"MZ":
            kind = "Windows executable (PE)"
        elif head[:4] == b"\x7fELF":
            kind = "Linux executable (ELF)"
        elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            kind = "macOS executable (Mach-O)"
        elif head[:4] == b"\xca\xfe\xba\xbe":
            kind = "Mach-O universal / Java class"
        elif ext in (".pyc", ".pyo"):
            kind = "Python bytecode terkompilasi"
        elif ext == ".node":
            kind = "Native Node.js addon"
        elif ext in (".wasm",) or head[:4] == b"\x00asm":
            kind = "WebAssembly"
        if kind:
            mismatch = ext in {".png", ".jpg", ".jpeg", ".gif", ".txt", ".md", ".json", ".css", ".svg", ".ico", ".pdf", ".csv"}
            self.add("BINARY_EXECUTABLE" if not mismatch else "BINARY_DISGUISED", "binary",
                     "critical" if mismatch else "high", rp, None, kind,
                     ("Program tersamar dengan ekstensi palsu!" if mismatch else
                      "File program biner — isinya tidak bisa ditinjau; pastikan asalnya jelas."))
            return True
        if head[:4] == b"PK\x03\x04" or head[:3] == b"\x1f\x8b\x08" or head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] == b"Rar!":
            if ext not in {".docx", ".xlsx", ".pptx", ".odt", ".epub", ".skill", ".plugin"}:
                self.add("BINARY_ARCHIVE", "binary", "medium", rp, None, "arsip",
                         "Arsip terkompresi di dalam repo — isinya tidak ikut dipindai.")
            return True
        if b"\x00" in data[:4096]:
            return True  # biner lain (gambar, font) — dilewati
        return False

    def scan_text(self, rp, fn, ext, text):
        start_idx = len(self.findings)
        file_hosts = set()
        lines = text.split("\n")
        hits = Counter()
        is_md = ext in (".md", ".mdx", ".txt", ".rst")
        for i, line in enumerate(lines, 1):
            if len(line) > 4000 and ext in (".js", ".mjs", ".cjs", ".py", ".ts") and hits["MINIFIED"] == 0:
                hits["MINIFIED"] += 1
                self.add("MINIFIED_CODE", "obfuscation", "low", rp, i, line[:120],
                         "Baris kode sangat panjang (minified/terkompres) — sulit ditinjau manusia.")
            for rid, cat, sev, rx, desc in self.rules:
                if rx is None:
                    continue
                if hits[rid] >= MAX_HITS_PER_RULE_PER_FILE:
                    continue
                m = rx.search(line)
                if m:
                    hits[rid] += 1
                    s = max(0, m.start() - 60)
                    self.add(rid, cat, sev, rp, i, line[s:s + SNIPPET_LEN], desc)
            for m in URL_RE.finditer(line):
                host = m.group(1).lower().strip(".")
                if not is_allowed(host):
                    file_hosts.add(host)
                d = self.domains[host]
                d["count"] += 1
                if len(d["files"]) < 8:
                    d["files"].add(f"{rp}:{i}")
            if hits["HIDDEN"] < 5 and ext not in (".lock", ".sum") and not fn.endswith(("-lock.json", ".lock")):
                for rx_, kind in ((QUOTED_B64_RE, "base64"), (QUOTED_HEX_RE, "hex")):
                    for m in rx_.finditer(line):
                        dec = try_decode(m.group(1), kind)
                        if dec and SUSPICIOUS_DECODED.search(dec):
                            hits["HIDDEN"] += 1
                            self.add("OBF_HIDDEN_PAYLOAD", "obfuscation", "high", rp, i,
                                     f"{m.group(1)[:60]}… → {dec[:140]!r}",
                                     f"URL/perintah disembunyikan dalam {kind} (sudah di-decode otomatis).")
                            for um in URL_RE.finditer(dec):
                                host = um.group(1).lower().strip(".")
                                d = self.domains[host]
                                d["count"] += 1
                                d["hidden"] = True
                                d["files"].add(f"{rp}:{i} (tersembunyi)")
            if not is_md and hits["B64"] < 3:
                for m in B64_RE.finditer(line):
                    blob = m.group(0)
                    if blob.startswith(IMG_B64) or "data:image" in line[:m.start()] or "data:font" in line[:m.start()]:
                        continue
                    if entropy(blob) > 5.2:
                        hits["B64"] += 1
                        self.add("OBF_LONG_ENCODED", "obfuscation", "medium", rp, i, blob[:80] + "…",
                                 f"String terenkode panjang ({len(blob)} karakter) — bisa menyembunyikan payload.")
                        break
            if BIDI_RE.search(line) and hits["BIDI"] < 3:
                hits["BIDI"] += 1
                self.add("UNICODE_BIDI", "obfuscation", "high", rp, i, ascii(line)[:SNIPPET_LEN],
                         "Karakter pembalik arah teks (Trojan Source) — kode terlihat berbeda dari yang dijalankan.")
            if TAG_RE.search(line) and hits["TAG"] < 3:
                hits["TAG"] += 1
                hidden = "".join(chr(ord(c) - 0xE0000) for c in TAG_RE.findall(line) if 0x20 <= ord(c) - 0xE0000 < 0x7f)
                self.add("AI_HIDDEN_TAG_CHARS", "ai", "critical", rp, i, f"teks tersembunyi: {hidden[:150]!r}",
                         "Karakter Unicode 'tag' tak terlihat (ASCII smuggling) — teks tersembunyi yang bisa dibaca AI.")
            zw = ZW_RE.findall(line)
            if len(zw) >= 3 and hits["ZW"] < 3:
                hits["ZW"] += 1
                self.add("UNICODE_ZERO_WIDTH", "obfuscation", "medium", rp, i, ascii(line)[:SNIPPET_LEN],
                         f"{len(zw)} karakter tak terlihat (zero-width) dalam satu baris.")
        if ext in (".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".rs", ".ps1", ".sh", ".rb", ".cs", ".java") \
                and WALK_RE.search(text) and ENCRYPT_RE.search(text) and DELETE_RE.search(text):
            self.add("RANSOMWARE_PATTERN", "destructive", "high", rp, None,
                     "menelusuri folder + mengenkripsi + menghapus/mengganti nama file",
                     "Kombinasi pola ransomware: menelusuri banyak file, mengenkripsinya, lalu menghapus/mengganti nama aslinya.")
        if ext in CODE_EXT:
            self.dataflow(rp, text, self.findings[start_idx:], file_hosts)
        if is_md or ext in (".html", ".htm"):
            for m in HTML_COMMENT_RE.finditer(text):
                body = m.group(1).strip()
                if len(body) > 15 and INSTRUCTION_WORDS.search(body):
                    ln = text.count("\n", 0, m.start()) + 1
                    sev = "high" if fn.upper() in ("SKILL.MD", "CLAUDE.MD", "AGENTS.MD") else "medium"
                    self.add("AI_HIDDEN_COMMENT", "ai", sev, rp, ln, body[:SNIPPET_LEN],
                             "Komentar HTML tersembunyi berisi kalimat seperti instruksi (tidak terlihat di tampilan, tapi dibaca AI).")

    def dataflow(self, rp, text, file_findings, file_hosts):
        """Hubungkan sumber data sensitif dengan tujuan jaringan di file yang sama."""
        src = [f for f in file_findings if f["category"] == "credentials"]
        if not src:
            return
        sink = NET_SINK_RE.search(text)
        if sink:
            sink_line = text.count("\n", 0, sink.start()) + 1
            exfil = [f for f in file_findings if f["rule"] in ("NET_EXFIL_SERVICE", "NET_RAW_IP", "NET_PASTE_FILEHOST", "NET_TUNNEL", "OBF_HIDDEN_PAYLOAD")]
            sev = "critical" if (exfil or file_hosts) else "high"
            first = src[0]
            dest = (exfil[0]["snippet"][:60] if exfil else ", ".join(sorted(file_hosts)[:3]) or sink.group(0).strip())
            self.add("DATAFLOW_EXFIL", "dataflow", sev, rp, first["line"],
                     f"sumber: {first['rule']} (baris {first['line']}) → tujuan: {sink.group(0).strip()} (baris {sink_line}) · {dest}",
                     "Data sensitif dibaca DAN ada pengiriman jaringan di file yang sama — pola pencurian data.",
                     {"related": [f["rule"] for f in src]})
        else:
            for f in src:
                if f["severity"] == "high" and f["context"] == "code":
                    f["severity"] = "medium"
                    f["auto_note"] = "Diturunkan otomatis: tidak ada pengiriman jaringan di file yang sama."

    def special_files(self, rp, fn, text):
        low = fn.lower()
        if low in (".reposcan-ignore", ".reposcanignore", "reposcan.json", ".reposcan.yml", ".reposcan.yaml"):
            self.add("SCANNER_EVASION", "ai", "high", rp, None, text.strip()[:150],
                     "Repo membawa file konfigurasi Repo Scan sendiri — Repo Scan TIDAK memakainya; kemungkinan upaya menyembunyikan temuan.")
        if low == "skill.md":
            self.repo_kind.add("skill")
        if rp.endswith(".claude-plugin/plugin.json") or rp.endswith(".claude-plugin/marketplace.json"):
            self.repo_kind.add("plugin")
        if low in ("package.json",):
            self.repo_kind.add("node")
            self.check_package_json(rp, text)
        if low in ("setup.py", "pyproject.toml", "requirements.txt", "setup.cfg", "pipfile"):
            self.repo_kind.add("python")
            self.check_python_pkg(rp, low, text)
        if low in (".mcp.json", "mcp.json", "claude_desktop_config.json") or rp.endswith(".claude-plugin/plugin.json"):
            if "mcp" in low:
                self.repo_kind.add("mcp")
            self.check_mcp_and_hooks(rp, text)
        if rp.startswith("hooks/") and low.endswith(".json") or rp.endswith(".claude/settings.json") or rp.endswith(".claude/settings.local.json"):
            self.check_mcp_and_hooks(rp, text)
        if rp.startswith(".github/workflows/") and low.endswith((".yml", ".yaml")):
            self.check_workflow(rp, text)
        if low in ("dockerfile", "containerfile") or low.endswith(".dockerfile"):
            self.repo_kind.add("docker")
            self.check_dockerfile(rp, text)
        if low in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            self.check_compose(rp, text)
        if low in ("makefile", "gnumakefile") or low.endswith(".mk"):
            self.check_makefile(rp, text)
        if low == "pyproject.toml":
            self.check_pyproject(rp, text)
        if low == "build.rs":
            self.add("BUILD_SCRIPT", "install", "medium", rp, None, "build.rs",
                     "build.rs (Rust) otomatis jalan saat `cargo build` — baca isinya.")
        if low == "binding.gyp":
            self.add("BUILD_SCRIPT", "install", "low", rp, None, "binding.gyp", "Modul native dikompilasi saat npm install.")
        if low in (".npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", ".pip.conf"):
            if re.search(r"registry\s*[=:]\s*\S+|index-url|npmRegistryServer", text) and not re.search(r"registry\.npmjs\.org|pypi\.org/simple|registry\.yarnpkg\.com", text):
                self.add("DEP_CUSTOM_REGISTRY", "dependency", "high", rp, None, text.strip()[:150],
                         "Registry paket diarahkan ke server non-resmi — semua dependensi bisa diganti.")
        if low == "gemfile":
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r"(git|github|source)\s*[:=]>?\s*['\"]http", line) and "rubygems.org" not in line:
                    self.add("DEP_REMOTE_SOURCE", "dependency", "medium", rp, i, line.strip(), "Gem diambil dari sumber non-standar.")
        if low == "skill.md" or (rp.startswith(("agents/", ".claude/agents/", "commands/", ".claude/commands/")) and low.endswith(".md")):
            fm = re.match(r"^---\s*\n(.*?)\n---", text, re.S)
            if fm:
                m = re.search(r"^(allowed-tools|tools)\s*:\s*(.+)$", fm.group(1), re.M)
                if m and (re.search(r"\bBash\b(?!\()|Bash\(\*\)|['\"]?\*['\"]?\s*$", m.group(2))):
                    self.add("AI_WIDE_PERMISSIONS", "ai", "medium", rp, None, m.group(0),
                             "Skill/agen meminta akses shell tanpa batasan (Bash bebas).")
        if low in (".vscode", "tasks.json") and ".vscode/" in rp:
            if '"runOn"' in text and "folderOpen" in text:
                self.add("IDE_AUTORUN", "install", "high", rp, None, "runOn: folderOpen",
                         "Task VS Code berjalan otomatis saat folder dibuka.")
        if low in (".gitattributes",) and "filter=" in text:
            self.add("GIT_FILTER", "install", "medium", rp, None, "filter=", "Git filter dapat menjalankan program saat checkout (jika dikonfigurasi).")

    def check_package_json(self, rp, text):
        try:
            pj = json.loads(text)
        except Exception:
            return
        scripts = pj.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall", "postuninstall"):
            if hook in scripts:
                cmd = str(scripts[hook])
                benign = re.fullmatch(r"\s*(husky( install)?|tsc|npm run build|node-gyp rebuild|patch-package|ngcc)\s*", cmd)
                sev = "low" if benign else ("high" if re.search(r"curl|wget|http|node\s+-e|eval|base64|\.sh\b|powershell", cmd, re.I) else "medium")
                self.add("INSTALL_SCRIPT", "install", sev, rp, None, f'"{hook}": "{cmd}"',
                         f"Skrip '{hook}' otomatis jalan saat `npm install`.")
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, ver in (pj.get(sec) or {}).items():
                v = str(ver)
                if re.match(r"(git\+|git://|https?://|github:|[\w-]+/[\w.-]+(#|$))", v):
                    self.add("DEP_REMOTE_SOURCE", "dependency", "medium", rp, None, f"{name}: {v}",
                             "Dependensi diambil langsung dari URL/git (bukan registry resmi, tidak terverifikasi).")
                self.check_typosquat(rp, name, "npm")

    def check_python_pkg(self, rp, low, text):
        if low == "setup.py":
            if re.search(r"cmdclass\s*=", text):
                self.add("INSTALL_SCRIPT", "install", "medium", rp, None, "cmdclass=",
                         "setup.py mengganti perintah install (kode jalan saat `pip install`).")
            if re.search(r"(urlopen|requests\.|subprocess|os\.system|socket)", text):
                self.add("INSTALL_SCRIPT_ACTIVE", "install", "high", rp, None, "setup.py melakukan jaringan/proses",
                         "setup.py memanggil jaringan atau menjalankan perintah — jalan saat install.")
        if low == "requirements.txt":
            for i, line in enumerate(text.splitlines(), 1):
                l = line.strip()
                if not l or l.startswith("#"):
                    continue
                if re.match(r"(git\+|https?://|-e\s+git)", l) or "--index-url" in l or "--extra-index-url" in l:
                    self.add("DEP_REMOTE_SOURCE", "dependency", "medium", rp, i, l,
                             "Dependensi/indeks paket dari sumber non-standar.")
                name = re.split(r"[<>=!~\[; ]", l, maxsplit=1)[0]
                if name and not name.startswith("-"):
                    self.check_typosquat(rp, name, "pypi")

    def check_typosquat(self, rp, name, eco):
        n = name.lower()
        if n.startswith("@") and n not in POPULAR_PKGS[eco]:
            return  # paket ber-scope dimiliki organisasi; tidak dibandingkan
        for p in POPULAR_PKGS[eco]:
            if n != p and len(n) > 4 and levenshtein(n, p) == 1 and n not in POPULAR_PKGS[eco]:
                self.add("DEP_TYPOSQUAT", "dependency", "high", rp, None, f"{name} (mirip '{p}')",
                         "Nama paket sangat mirip paket populer — kemungkinan typosquatting.")

    def check_mcp_and_hooks(self, rp, text):
        try:
            obj = json.loads(text)
        except Exception:
            return
        def walk(o, path=""):
            if isinstance(o, dict):
                if "hooks" in o and isinstance(o["hooks"], (dict, list)):
                    for cmd in collect_commands(o["hooks"]):
                        sev = "high" if re.search(r"curl|wget|http|nc\s|base64|eval|powershell|\|\s*(ba)?sh", cmd, re.I) else "medium"
                        self.add("PLUGIN_HOOK", "ai", sev, rp, None, cmd,
                                 "Hook plugin/agen — perintah ini jalan OTOMATIS saat event tertentu terjadi.")
                perms = o.get("permissions")
                if isinstance(perms, dict):
                    if str(perms.get("defaultMode", "")).lower() in ("bypasspermissions", "acceptedits", "dontask"):
                        self.add("AI_BYPASS_PERMISSIONS", "ai", "medium", rp, None, f"defaultMode: {perms.get('defaultMode')}",
                                 "Mode izin default melewati konfirmasi pengguna.")
                    wide = [a for a in perms.get("allow", []) or [] if isinstance(a, str) and re.fullmatch(r"\*|Bash|Bash\(\*\)|Bash\((curl|wget|sh|bash|python3?|node|rm)[: ]?\*?\)|WebFetch|Write|Edit", a.strip())]
                    if wide:
                        self.add("AI_WIDE_PERMISSIONS", "ai", "medium", rp, None, f"allow: {wide}",
                                 "Izin tool sangat luas diberikan otomatis tanpa konfirmasi.")
                servers = o.get("mcpServers") if isinstance(o.get("mcpServers"), dict) else None
                if servers:
                    self.repo_kind.add("mcp")
                    for nm, cfg in servers.items():
                        if not isinstance(cfg, dict):
                            continue
                        url = cfg.get("url")
                        cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []]).strip()
                        if url:
                            host = (re.match(r"https?://([^/:]+)", str(url)) or [None, ""])[1].lower()
                            trusted = any(host == a or host.endswith("." + a) for a in ALLOW_DOMAINS)
                            self.add("MCP_REMOTE", "ai", "low" if trusted else "medium", rp, None, f"{nm}: {url}",
                                     "MCP server jarak jauh — data percakapan/tool akan dikirim ke server ini.")
                        if cmd:
                            unpinned = re.search(r"\b(npx|uvx|pipx run|bunx)\b[^\n]*?(-y\s+)?([@\w./-]+)(?<!@latest)", cmd) and not re.search(r"@\d", cmd)
                            sev = "medium" if (unpinned or re.search(r"curl|http|bash|sh -c", cmd)) else "low"
                            self.add("MCP_LOCAL_COMMAND", "ai", sev, rp, None, f"{nm}: {cmd}",
                                     "MCP server lokal — perintah ini dijalankan di komputer Anda" + (" (versi paket tidak dikunci)." if unpinned else "."))
                        env = cfg.get("env") or {}
                        if any(re.search(r"(KEY|TOKEN|SECRET|PASS)", k, re.I) for k in env):
                            self.add("MCP_SECRET_ENV", "ai", "low", rp, None, f"{nm}: {list(env)}",
                                     "MCP meminta API key/token lewat env — pastikan servernya tepercaya.")
                for k, v in o.items():
                    if k not in ("hooks",):
                        walk(v, path + "/" + k)
            elif isinstance(o, list):
                for v in o:
                    walk(v, path)
        walk(obj)

    def check_workflow(self, rp, text):
        if re.search(r"^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", text, re.M):
            self.add("CI_PR_TARGET", "ci", "high", rp, None, "pull_request_target",
                     "Workflow `pull_request_target` — PR dari orang luar bisa berjalan dengan akses rahasia repo.")
        run_indent = None
        for i, line in enumerate(text.splitlines(), 1):
            ind = len(line) - len(line.lstrip())
            if re.match(r"^\s*(-\s*)?(run|script)\s*:", line):
                run_indent = ind
                in_run = True
            elif run_indent is not None and line.strip() and ind > run_indent:
                in_run = True
            else:
                run_indent = None
                in_run = False
            if in_run and re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|discussion)[\w.]*\.(title|body|message|name|ref|label)", line):
                self.add("CI_INJECTION", "ci", "high", rp, i, line.strip(),
                         "Input dari luar langsung dipakai di workflow — rawan command injection.")
            if re.search(r"secrets\.\w+", line) and re.search(r"curl|wget|http", line):
                self.add("CI_SECRET_SEND", "ci", "medium", rp, i, line.strip(), "Secret dipakai bersama request jaringan.")

    def check_dockerfile(self, rp, text):
        for i, line in enumerate(text.splitlines(), 1):
            l = line.strip()
            if re.match(r"(?i)ADD\s+https?://", l):
                self.add("DOCKER_REMOTE_ADD", "install", "medium", rp, i, l, "Dockerfile mengunduh file dari internet tanpa verifikasi checksum.")
            if re.match(r"(?i)FROM\s+\S+", l) and "@sha256:" not in l and not re.search(r"(?i)\bFROM\s+(scratch|\$)", l) and re.search(r":latest\b|^FROM\s+[^:\s]+(\s|$)", l, re.I):
                self.add("DOCKER_UNPINNED", "dependency", "low", rp, i, l, "Image dasar tidak dikunci versinya (latest).")

    def check_compose(self, rp, text):
        for i, line in enumerate(text.splitlines(), 1):
            l = line.strip()
            if re.search(r"privileged\s*:\s*true|network_mode\s*:\s*['\"]?host|pid\s*:\s*['\"]?host|cap_add\s*:.*(SYS_ADMIN|ALL)", l):
                self.add("DOCKER_PRIVILEGED", "persistence", "high", rp, i, l, "Container diberi akses penuh ke sistem host.")
            if re.search(r"/var/run/docker\.sock|^-\s*['\"]?/:/|['\"]?~?/?\$?HOME[^:]*:/|^-\s*['\"]?/(etc|root|Users|home)\b", l):
                self.add("DOCKER_HOST_MOUNT", "persistence", "high", rp, i, l, "Container me-mount folder sensitif host / docker socket.")

    def check_makefile(self, rp, text):
        for i, line in enumerate(text.splitlines(), 1):
            if line.startswith("\t") or line.startswith("    "):
                if re.search(r"\b(curl|wget|nc|ncat|base64\s+-d|eval|Invoke-WebRequest)\b|https?://", line):
                    self.add("MAKEFILE_NETWORK", "install", "medium", rp, i, line.strip(),
                             "Makefile menjalankan perintah jaringan/decode saat `make`.")

    def check_pyproject(self, rp, text):
        if re.search(r"^\s*backend-path\s*=", text, re.M):
            self.add("PY_CUSTOM_BACKEND", "install", "high", rp, None, "backend-path",
                     "Build backend buatan sendiri di dalam repo — kodenya jalan saat `pip install`.")
        if re.search(r"\[tool\.hatch\.build(\.targets\.\w+)?\.hooks\.|\[tool\.setuptools\.cmdclass\]|\[tool\.pdm\.build\]|build-script\s*=|\[tool\.poetry\.build\]", text):
            self.add("PY_BUILD_HOOK", "install", "medium", rp, None, "build hook",
                     "pyproject.toml memakai build hook — kode kustom jalan saat install. Baca file hook-nya.")

    # ---------------- OSV ----------------
    def collect_packages(self):
        pk = set()
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != "node_modules"]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                low = fn.lower()
                try:
                    if os.path.getsize(full) > 30_000_000:
                        continue
                    txt = open(full, encoding="utf-8", errors="replace").read() if low in (
                        "package-lock.json", "package.json", "requirements.txt", "poetry.lock", "pipfile.lock",
                        "cargo.lock", "go.mod", "yarn.lock", "pnpm-lock.yaml") or (low.startswith("requirements") and low.endswith(".txt")) else None
                except OSError:
                    continue
                if txt is None:
                    continue
                try:
                    if low == "package-lock.json":
                        j = json.loads(txt)
                        for k, v in (j.get("packages") or {}).items():
                            if k and isinstance(v, dict) and v.get("version"):
                                pk.add(("npm", k.split("node_modules/")[-1], v["version"]))
                        def dep(d):
                            for n, v in (d or {}).items():
                                if isinstance(v, dict):
                                    if v.get("version"):
                                        pk.add(("npm", n, v["version"]))
                                    dep(v.get("dependencies"))
                        dep(j.get("dependencies"))
                    elif low == "package.json":
                        j = json.loads(txt)
                        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
                            for n, v in (j.get(sec) or {}).items():
                                m = re.match(r"^[~^=v]?(\d+\.\d+\.\d+[\w.-]*)$", str(v).strip())
                                pk.add(("npm", n, m.group(1) if m else None))
                    elif low == "yarn.lock":
                        for m in re.finditer(r'^"?(@?[^@\s"]+)@[^\n]*\n\s+version:?\s+"?([^"\n]+)"?', txt, re.M):
                            pk.add(("npm", m.group(1), m.group(2)))
                    elif low == "pnpm-lock.yaml":
                        for m in re.finditer(r"^\s{2}/?(@?[^@\s/]+(?:/[^@\s]+)?)@(\d[^:(\s]*)", txt, re.M):
                            pk.add(("npm", m.group(1), m.group(2)))
                    elif low.startswith("requirements"):
                        for line in txt.splitlines():
                            m = re.match(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(==\s*([\w.\-]+))?", line)
                            if m and not line.strip().startswith(("#", "-")):
                                pk.add(("PyPI", re.sub(r"\[.*\]", "", m.group(1)), m.group(3)))
                    elif low == "poetry.lock":
                        for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', txt):
                            pk.add(("PyPI", m.group(1), m.group(2)))
                    elif low == "pipfile.lock":
                        j = json.loads(txt)
                        for sec in ("default", "develop"):
                            for n, v in (j.get(sec) or {}).items():
                                pk.add(("PyPI", n, str(v.get("version", "")).lstrip("=") or None))
                    elif low == "cargo.lock":
                        for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', txt):
                            pk.add(("crates.io", m.group(1), m.group(2)))
                    elif low == "go.mod":
                        for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w]+/[\w./\-]+)\s+(v[\w.\-+]+)", txt, re.M):
                            pk.add(("Go", m.group(1), m.group(2)))
                except Exception:
                    continue
        return pk

    def osv_check(self):
        pk = sorted(self.collect_packages(), key=lambda x: (x[0], x[1], x[2] or ""))[:3000]
        self.osv_info = {"packages_checked": len(pk), "status": "ok"}
        if not pk:
            return
        queries = []
        for eco, name, ver in pk:
            q = {"package": {"name": name, "ecosystem": eco}}
            if ver:
                q["version"] = ver
            queries.append(q)
        results = []
        try:
            for i in range(0, len(queries), 900):
                body = json.dumps({"queries": queries[i:i + 900]}).encode()
                req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=60) as r:
                    results += json.load(r).get("results", [])
        except Exception as ex:
            self.osv_info = {"packages_checked": len(pk), "status": f"gagal: {ex}"}
            self.add("OSV_UNAVAILABLE", "dependency", "info", None, None, str(ex)[:150],
                     "Cek database celah keamanan (OSV) tidak bisa dijalankan — tidak ada internet?")
            return
        vuln_pk = 0
        for (eco, name, ver), res in zip(pk, results):
            ids = [v.get("id") for v in (res or {}).get("vulns", []) or []]
            mal = [x for x in ids if str(x).startswith("MAL-")]
            if mal:
                self.add("DEP_KNOWN_MALICIOUS", "dependency", "critical", f"{eco}:{name}", None,
                         f"{name}@{ver or '*'} → {', '.join(mal[:5])}",
                         "Paket ini tercatat di database OSV sebagai PAKET BERBAHAYA (malware).")
            other = [x for x in ids if not str(x).startswith("MAL-")]
            if other and ver:
                vuln_pk += 1
                self.add("DEP_KNOWN_VULN", "dependency", "medium" if len(other) < 5 else "high", f"{eco}:{name}", None,
                         f"{name}@{ver} → {', '.join(other[:8])}{' …' if len(other) > 8 else ''}",
                         f"Versi dependensi ini punya {len(other)} celah keamanan yang sudah diketahui (OSV).")
        self.osv_info["vulnerable_packages"] = vuln_pk

    def post_domains(self):
        for host, d in self.domains.items():
            d["allowlisted"] = is_allowed(host)

    def result(self):
        doms = sorted(({"domain": h, "count": d["count"], "allowlisted": d["allowlisted"] and not d.get("hidden"),
                        "hidden": bool(d.get("hidden")), "examples": sorted(d["files"])}
                       for h, d in self.domains.items()), key=lambda x: (x["allowlisted"], -x["count"]))
        return {
            "tool": "Repo Scan", "version": VERSION,
            "inventory": {
                "files_total": self.inventory["files"], "files_scanned": self.files_scanned,
                "bytes_scanned": self.bytes_scanned, "repo_kind": sorted(k for k in self.repo_kind if k),
                "top_extensions": dict(self.ext_counter.most_common(12)),
            },
            "findings": self.findings, "domains": doms, "skipped": self.skipped,
            "osv": getattr(self, "osv_info", {"status": "tidak dijalankan (pakai --osv)"}),
        }


def is_allowed(host):
    host = (host or "").lower()
    return any(host == a or host.endswith("." + a) for a in ALLOW_DOMAINS)


def make_finding(rule, category, severity, path, line, snippet, desc, context=None, **extra):
    f = {"rule": rule, "category": category, "severity": severity, "file": path, "line": line,
         "snippet": (snippet or "").strip()[:SNIPPET_LEN], "description": desc,
         "context": context or ("docs/test" if DOC_HINT.search(path or "") else "code")}
    f.update(extra)
    return f


def fingerprint(f):
    snip = re.sub(r"\s+|\d+", "", f.get("snippet") or "")[:120]
    file_ = re.sub(r"^deps/[^/]+/[^/]+@[^/]+/", "deps/", f.get("file") or "")
    return hashlib.sha1(f"{f['rule']}|{file_}|{snip}".encode()).hexdigest()[:12]


def load_ignore(path):
    rules = []
    if not path:
        return rules
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            rules.append((parts[0], parts[1] if len(parts) > 1 else None))
    return rules


def ignore_match(f, rules):
    for key, glob in rules:
        if key.startswith("fp:"):
            if f["fingerprint"] == key[3:]:
                return f"ignore {key}"
        elif key == f["rule"] or key == "*":
            if glob is None or fnmatch.fnmatch(f.get("file") or "", glob):
                return f"ignore {key}" + (f" {glob}" if glob else "")
    return None


def finalize(res, ignore_rules=None, baseline=None):
    """Turunkan tingkat docs/test, beri fingerprint, terapkan ignore/baseline, beri ID, hitung ringkasan."""
    down = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}
    kept, suppressed = [], []
    for f in res["findings"]:
        if f["context"] == "docs/test" and f["category"] not in ("ai", "binary") and f["severity"] != "critical" \
                and "original_severity" not in f:
            f["original_severity"] = f["severity"]
            f["severity"] = down[f["severity"]]
        f["fingerprint"] = fingerprint(f)
        why = ignore_match(f, ignore_rules or [])
        if not why and baseline and f["fingerprint"] in baseline:
            why = "baseline (sudah ada di scan sebelumnya)"
        if why:
            f["suppressed_reason"] = why
            suppressed.append(f)
        else:
            kept.append(f)
    order = lambda x: (-SEV_ORDER[x["severity"]], x["category"], x["file"] or "", x["line"] or 0)
    for idx, f in enumerate(sorted(kept, key=order), 1):
        f["id"] = f"F{idx:03d}"
    for idx, f in enumerate(sorted(suppressed, key=order), 1):
        f["id"] = f"S{idx:03d}"
    kept.sort(key=lambda x: x["id"])
    res["findings"], res["suppressed"] = kept, suppressed
    counts = Counter(f["severity"] for f in kept)
    score = sum(SEV_WEIGHT[f["severity"]] * (0.5 if f["context"] == "docs/test" else 1) for f in kept)
    if counts["critical"]:
        level = "BAHAYA"
    elif counts["high"] or score >= 30:
        level = "WASPADA"
    elif score >= 8:
        level = "PERLU DICEK"
    else:
        level = "RISIKO RENDAH"
    inv = res.get("inventory", {})
    res["summary"] = {
        "auto_level": level, "risk_score": round(score, 1),
        "by_severity": {k: counts.get(k, 0) for k in SEV_ORDER},
        "by_category": dict(Counter(f["category"] for f in kept)),
        "files_total": inv.get("files_total", 0), "files_scanned": inv.get("files_scanned", 0),
        "bytes_scanned": inv.get("bytes_scanned", 0), "repo_kind": inv.get("repo_kind", []),
        "top_extensions": inv.get("top_extensions", {}),
        "external_domains": sum(1 for d in res.get("domains", []) if not d["allowlisted"]),
        "suppressed": len(suppressed),
    }
    return res


def collect_commands(o):
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if k in ("command", "cmd") and isinstance(v, str):
                out.append(v)
            else:
                out += collect_commands(v)
    elif isinstance(o, list):
        for v in o:
            out += collect_commands(v)
    return out


def try_decode(s, kind):
    try:
        if kind == "hex":
            raw = bytes.fromhex(s)
        else:
            t = s.replace("-", "+").replace("_", "/")
            raw = base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not txt or sum(c.isprintable() or c in "\n\t" for c in txt) / len(txt) < 0.9:
        return None
    return txt


def entropy(s):
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def levenshtein(a, b):
    if abs(len(a) - len(b)) > 1:
        return 2
    # Damerau (OSA): transposisi huruf dihitung 1 (mis. "axois" vs "axios")
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


# ---------------------------------------------------------------------------
# Git yang aman (tanpa hooks, fsmonitor, textconv, filter)
# ---------------------------------------------------------------------------
GIT_SAFE = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
            "-c", "protocol.file.allow=never", "-c", "safe.directory=*", "-c", "diff.external=",
            "-c", "core.symlinks=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
            "-c", "filter.lfs.required=false"]
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_PAGER="cat", PAGER="cat",
               GIT_CONFIG_NOSYSTEM="1")


def git(repo, *args, check=True, text=True, timeout=600):
    r = subprocess.run(GIT_SAFE + ["-C", repo] + list(args), capture_output=True, text=text, env=GIT_ENV, timeout=timeout)
    if check and r.returncode != 0:
        raise SystemExit(f"[GIT] {' '.join(args[:3])}: {(r.stderr if text else r.stderr.decode(errors='replace')).strip()}")
    return r


def export_ref(repo, ref, dest):
    """Tulis isi commit `ref` ke `dest` langsung dari objek git (tanpa checkout, tanpa filter/smudge)."""
    os.makedirs(dest, exist_ok=True)
    ls = git(repo, "ls-tree", "-r", "-z", "--full-tree", ref, text=False).stdout.split(b"\0")
    entries = []
    for e in ls:
        if not e:
            continue
        meta, path = e.split(b"\t", 1)
        mode, typ, sha = meta.split()
        entries.append((mode.decode(), typ.decode(), sha.decode(), path.decode("utf-8", "replace")))
    blobs = [x for x in entries if x[1] == "blob"]
    p = subprocess.Popen(GIT_SAFE + ["-C", repo, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=GIT_ENV)
    root = os.path.realpath(dest)
    for mode, typ, sha, path in blobs:
        p.stdin.write(sha.encode() + b"\n")
        p.stdin.flush()
        header = p.stdout.readline().split()
        size = int(header[2])
        data = p.stdout.read(size)
        p.stdout.read(1)
        if mode == "120000":  # symlink: simpan sebagai teks kecil agar tetap bisa dinilai
            target = data.decode("utf-8", "replace")
            out = os.path.realpath(os.path.join(root, path))
            if out.startswith(root + os.sep):
                os.makedirs(os.path.dirname(out), exist_ok=True)
                try:
                    os.symlink(target, out)
                except OSError:
                    pass
            continue
        out = os.path.realpath(os.path.join(root, path))
        if not out.startswith(root + os.sep):
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(data)
        if mode == "100755":
            os.chmod(out, 0o755)
    p.stdin.close()
    p.wait()
    return dest


def resolve_ref(repo, ref):
    r = git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}", check=False)
    if r.returncode != 0:
        r = git(repo, "rev-parse", "--verify", "--quiet", "origin/" + ref + "^{commit}", check=False)
    if r.returncode != 0:
        raise SystemExit(f"[DIFF] ref tidak ditemukan: {ref}")
    return r.stdout.strip()


def changed_files(repo, a, b):
    out = git(repo, "diff", "--no-textconv", "--no-ext-diff", "--name-status", "-M", a, b).stdout
    res = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            res.append({"status": parts[0][0], "path": parts[-1]})
    return res


HISTORY_RULES = {"SECRET_KEY", "NET_DOWNLOAD_EXEC", "NET_REVERSE_SHELL", "NET_EXFIL_SERVICE", "OBF_DECODE_EXEC",
                 "CRED_BROWSER", "CRED_WALLET", "CRED_DOTENV_HUNT", "AI_PROMPT_INJECTION", "AI_HIDE_FROM_USER",
                 "AI_EXFIL_INSTRUCTION", "AI_SCANNER_MANIPULATION", "DESTRUCT_WIPE", "RANSOM_NOTE", "PERSIST_AUTOSTART"}


def scan_history(repo, n, rules):
    """Cari pola berbahaya & rahasia pada baris yang DIHAPUS di n commit terakhir (masih bisa diambil dari riwayat)."""
    compiled = [(rid, cat, sev, rx, desc) for rid, cat, sev, rx, desc in rules if rid in HISTORY_RULES and rx is not None]
    cmd = GIT_SAFE + ["-C", repo, "log", f"-n{int(n)}", "-p", "--no-textconv", "--no-ext-diff", "--no-color", "-U0",
                      "--format=@@RS@@ %H%x09%an%x09%ad", "--date=short"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=GIT_ENV)
    findings, seen = [], set()
    commit = author = date = path = None
    commits = 0
    for raw in p.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("@@RS@@ "):
            parts = line[7:].split("\t")
            commit, author, date = (parts + ["", "", ""])[:3]
            commits += 1
            continue
        if line.startswith("--- a/"):
            path = line[6:]
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if not line.startswith("-") or path is None:
            continue
        body = line[1:]
        if TAG_RE.search(body):
            key = ("AI_HIDDEN_TAG_CHARS", path)
            if key not in seen:
                seen.add(key)
                findings.append(make_finding("HIST_REMOVED_DANGEROUS", "history", "medium", f"history:{commit[:8]}:{path}", None,
                                             "karakter Unicode tag tersembunyi",
                                             f"Teks tersembunyi pernah ada lalu dihapus (commit {commit[:8]}, {author}, {date}).",
                                             context="history", commit=commit, author=author, date=date))
        for rid, cat, sev, rx, desc in compiled:
            m = rx.search(body)
            if not m:
                continue
            key = (rid, path, body.strip()[:80])
            if key in seen:
                continue
            seen.add(key)
            is_secret = rid == "SECRET_KEY"
            findings.append(make_finding(
                "HIST_REMOVED_SECRET" if is_secret else "HIST_REMOVED_DANGEROUS", "history", "medium",
                f"history:{commit[:8]}:{path}", None, body.strip()[:SNIPPET_LEN],
                (f"Rahasia pernah di-commit lalu dihapus (commit {commit[:8]}, {author}, {date}) — masih bisa diambil dari riwayat git."
                 if is_secret else
                 f"Pola berbahaya ({rid}) pernah ada lalu dihapus (commit {commit[:8]}, {author}, {date}). Periksa siapa yang menambah & menghapusnya."),
                context="history", commit=commit, author=author, date=date, matched_rule=rid))
            if len(findings) > 300:
                break
    p.stdout.close()
    p.wait()
    return findings, commits


# ---------------------------------------------------------------------------
# Jaringan (reputasi GitHub, unduh dependensi)
# ---------------------------------------------------------------------------
def http_get(url, headers=None, timeout=30, max_bytes=None):
    h = {"User-Agent": f"repo-scan/{VERSION}"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(max_bytes + 1) if max_bytes else r.read()
    if max_bytes and len(data) > max_bytes:
        raise ValueError(f"terlalu besar (> {max_bytes // 1_000_000} MB)")
    return data


def github_api(path):
    url = "https://api.github.com" + path
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    hdr = {"Accept": "application/vnd.github+json"}
    if tok:
        try:
            return json.loads(http_get(url, dict(hdr, Authorization=f"Bearer {tok}")))
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                raise
    return json.loads(http_get(url, hdr))


def days_since(iso):
    try:
        t = datetime.datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
        return max(0, (datetime.datetime.utcnow() - t).days)
    except Exception:
        return None


def check_reputation(owner, repo):
    info, findings = {"status": "ok"}, []
    try:
        r = github_api(f"/repos/{owner}/{repo}")
        u = github_api(f"/users/{r['owner']['login']}")
    except Exception as ex:
        return {"status": f"gagal: {ex}"}, []
    age = days_since(r.get("created_at", ""))
    owner_age = days_since(u.get("created_at", ""))
    stars = r.get("stargazers_count", 0)
    info.update({
        "full_name": r.get("full_name"), "description": r.get("description"), "stars": stars,
        "forks": r.get("forks_count"), "watchers": r.get("subscribers_count"), "open_issues": r.get("open_issues_count"),
        "created_at": r.get("created_at"), "pushed_at": r.get("pushed_at"), "repo_age_days": age,
        "archived": r.get("archived"), "license": (r.get("license") or {}).get("spdx_id"),
        "is_fork": r.get("fork"), "parent": (r.get("parent") or {}).get("full_name"),
        "parent_stars": (r.get("parent") or {}).get("stargazers_count"),
        "owner": u.get("login"), "owner_type": u.get("type"), "owner_age_days": owner_age,
        "owner_public_repos": u.get("public_repos"), "owner_followers": u.get("followers"),
    })
    tgt = f"github.com/{info['full_name']}"
    if owner_age is not None and owner_age < 30:
        findings.append(make_finding("REP_NEW_OWNER", "reputation", "high", tgt, None, f"akun dibuat {owner_age} hari lalu",
                                     "Akun pemilik repo baru dibuat (< 30 hari) — pola umum akun penyebar malware.", context="reputation"))
    elif owner_age is not None and owner_age < 180 and (u.get("followers") or 0) < 5:
        findings.append(make_finding("REP_YOUNG_OWNER", "reputation", "low", tgt, None, f"akun {owner_age} hari, {u.get('followers')} pengikut",
                                     "Akun pemilik masih muda dan belum punya rekam jejak.", context="reputation"))
    if age is not None and age < 14:
        findings.append(make_finding("REP_NEW_REPO", "reputation", "medium", tgt, None, f"repo dibuat {age} hari lalu",
                                     "Repo sangat baru (< 14 hari) — belum teruji komunitas.", context="reputation"))
    if age is not None and age < 90 and stars >= 200 and stars / max(age, 1) > 40:
        findings.append(make_finding("REP_STAR_SPIKE", "reputation", "medium", tgt, None, f"{stars} bintang dalam {age} hari",
                                     "Lonjakan bintang tidak wajar untuk repo semuda ini — bintang bisa dibeli untuk memancing korban.", context="reputation"))
    if r.get("fork") and (info.get("parent_stars") or 0) >= 500:
        findings.append(make_finding("REP_FORK_OF_POPULAR", "reputation", "medium", tgt, None, f"fork dari {info['parent']} ({info['parent_stars']}★)",
                                     "Ini fork dari repo populer. Penipu sering menyebar fork bermuatan malware — pastikan Anda memang butuh fork ini, bukan repo aslinya.",
                                     context="reputation"))
    if r.get("archived"):
        findings.append(make_finding("REP_ARCHIVED", "reputation", "low", tgt, None, "archived",
                                     "Repo sudah diarsipkan — tidak lagi dipelihara, celah keamanan tidak akan diperbaiki.", context="reputation"))
    pushed = days_since(r.get("pushed_at", "") or "")
    info["pushed_days_ago"] = pushed
    return info, findings


# ---------------------------------------------------------------------------
# Ekstraksi arsip yang aman
# ---------------------------------------------------------------------------
def safe_extract_zip(path, dest, limit=2_000_000_000):
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    with zipfile.ZipFile(path) as z:
        total = 0
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"path berbahaya di arsip (zip-slip): {info.filename}")
            total += info.file_size
            if total > limit:
                raise ValueError("arsip terlalu besar setelah diekstrak (kemungkinan zip bomb)")
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                continue
            out = os.path.realpath(os.path.join(root, name))
            if not out.startswith(root + os.sep) and out != root:
                raise ValueError(f"path berbahaya di arsip: {info.filename}")
            z.extract(info, dest)
    return dest


def safe_extract_tar(path, dest, limit=1_000_000_000):
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    total = 0
    with tarfile.open(path, "r:*") as t:
        members = []
        for m in t.getmembers():
            name = m.name.replace("\\", "/")
            if name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"path berbahaya di arsip: {m.name}")
            if not (m.isfile() or m.isdir()):
                continue  # lewati symlink, hardlink, device
            total += m.size
            if total > limit:
                raise ValueError("arsip terlalu besar setelah diekstrak")
            out = os.path.realpath(os.path.join(root, name))
            if not out.startswith(root + os.sep) and out != root:
                raise ValueError(f"path berbahaya di arsip: {m.name}")
            m.mode = (m.mode | 0o600) & 0o755
            members.append(m)
        try:
            t.extractall(dest, members=members, filter="data")
        except TypeError:
            t.extractall(dest, members=members)
    return dest


# ---------------------------------------------------------------------------
# Pindai isi dependensi (unduh paket sebagai file, TANPA install)
# ---------------------------------------------------------------------------
def direct_dependencies(root):
    deps = []
    seen = set()
    lock = {}
    lp = os.path.join(root, "package-lock.json")
    if os.path.exists(lp):
        try:
            j = json.load(open(lp, encoding="utf-8"))
            for k, v in (j.get("packages") or {}).items():
                if k.startswith("node_modules/") and "/node_modules/" not in k[13:] and isinstance(v, dict):
                    lock[k[13:]] = v.get("version")
        except Exception:
            pass
    pj = os.path.join(root, "package.json")
    if os.path.exists(pj):
        try:
            j = json.load(open(pj, encoding="utf-8"))
            for sec, prio in (("dependencies", 0), ("optionalDependencies", 0), ("devDependencies", 1)):
                for name, spec in (j.get(sec) or {}).items():
                    spec = str(spec)
                    if re.match(r"(git\+|git:|https?:|file:|link:|workspace:|github:)", spec) or ("/" in spec and not spec.startswith("@")):
                        continue
                    m = re.match(r"^[=v]?(\d+\.\d+\.\d+[\w.+-]*)$", spec.strip())
                    ver = lock.get(name) or (m.group(1) if m else None)
                    if ("npm", name) not in seen:
                        seen.add(("npm", name))
                        deps.append({"eco": "npm", "name": name, "version": ver, "spec": spec, "prio": prio})
        except Exception:
            pass
    reqs = [f for f in os.listdir(root) if f.lower().startswith("requirements") and f.lower().endswith(".txt")]
    for fn in reqs:
        for line in open(os.path.join(root, fn), encoding="utf-8", errors="replace"):
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==\s*([\w.\-+]+))?", line)
            if m and ("pypi", m.group(1).lower()) not in seen:
                seen.add(("pypi", m.group(1).lower()))
                deps.append({"eco": "pypi", "name": m.group(1), "version": m.group(4), "spec": line, "prio": 0 if fn.lower() == "requirements.txt" else 1})
    pp = os.path.join(root, "pyproject.toml")
    if os.path.exists(pp):
        txt = open(pp, encoding="utf-8", errors="replace").read()
        m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", txt, re.S | re.M)
        if m:
            for item in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                mm = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==\s*([\w.\-+]+))?", item.strip())
                if mm and ("pypi", mm.group(1).lower()) not in seen:
                    seen.add(("pypi", mm.group(1).lower()))
                    deps.append({"eco": "pypi", "name": mm.group(1), "version": mm.group(4), "spec": item, "prio": 0})
    deps.sort(key=lambda d: d["prio"])
    return deps


def fetch_package(dep, workdir):
    """Unduh paket dari registry resmi, verifikasi checksum, ekstrak dengan aman. Mengembalikan (folder, versi)."""
    name, ver = dep["name"], dep["version"]
    safe = re.sub(r"[^\w.@-]", "_", name)
    if dep["eco"] == "npm":
        meta = json.loads(http_get("https://registry.npmjs.org/" + urllib.request.quote(name, safe="@"), timeout=90,
                                   headers={"Accept": "application/vnd.npm.install-v1+json"}))
        ver = ver or npm_pick((meta.get("versions") or {}).keys(), dep.get("spec")) or (meta.get("dist-tags") or {}).get("latest")
        v = (meta.get("versions") or {}).get(ver)
        if not v:
            raise ValueError(f"versi {ver} tidak ada di registry")
        dist = v["dist"]
        data = http_get(dist["tarball"], timeout=120, max_bytes=40_000_000)
        integ = dist.get("integrity", "")
        if integ.startswith("sha512-"):
            if base64.b64encode(hashlib.sha512(data).digest()).decode() != integ[7:]:
                raise ValueError("checksum sha512 tidak cocok — paket mungkin dimanipulasi")
        elif dist.get("shasum") and hashlib.sha1(data).hexdigest() != dist["shasum"]:
            raise ValueError("checksum sha1 tidak cocok")
        arc = os.path.join(workdir, f"{safe}-{ver}.tgz")
        open(arc, "wb").write(data)
        out = safe_extract_tar(arc, os.path.join(workdir, f"{safe}@{ver}"))
    else:
        url = f"https://pypi.org/pypi/{name}/{ver}/json" if ver else f"https://pypi.org/pypi/{name}/json"
        meta = json.loads(http_get(url, timeout=90))
        ver = meta["info"]["version"]
        files = meta.get("urls") or []
        pick = (next((f for f in files if f["packagetype"] == "bdist_wheel" and f["filename"].endswith("py3-none-any.whl")), None)
                or next((f for f in files if f["packagetype"] == "sdist"), None)
                or next((f for f in files if f["packagetype"] == "bdist_wheel"), None))
        if not pick:
            raise ValueError("tidak ada file distribusi")
        data = http_get(pick["url"], timeout=120, max_bytes=40_000_000)
        want = (pick.get("digests") or {}).get("sha256")
        if want and hashlib.sha256(data).hexdigest() != want:
            raise ValueError("checksum sha256 tidak cocok — paket mungkin dimanipulasi")
        arc = os.path.join(workdir, pick["filename"])
        open(arc, "wb").write(data)
        dest = os.path.join(workdir, f"{safe}@{ver}")
        out = safe_extract_zip(arc, dest) if pick["filename"].endswith((".whl", ".zip")) else safe_extract_tar(arc, dest)
    return out, ver


def _semver(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)$", v.strip())
    return tuple(int(x) for x in m.groups()) if m else None


def npm_pick(versions, spec):
    """Pilih versi tertinggi (non-prerelease) yang memenuhi range npm sederhana: ^ ~ x >= exact *, dipisah ||."""
    cands = sorted((_semver(v), v) for v in versions if _semver(v))
    if not cands:
        return None
    best = None
    for part in (spec or "*").split("||"):
        part = part.strip()
        lo, hi = (0, 0, 0), (10**9, 0, 0)
        m = re.match(r"^([\^~]|>=|=)?\s*v?(\d+|x|\*)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$", part)
        if part in ("", "*", "latest", "x"):
            pass
        elif m:
            op, a, b_, c = m.groups()
            nums = [None if x in (None, "x", "*") else int(x) for x in (a, b_, c)]
            if nums[0] is None:
                pass
            elif nums[1] is None:
                lo, hi = (nums[0], 0, 0), (nums[0] + 1, 0, 0)
            elif nums[2] is None:
                lo, hi = (nums[0], nums[1], 0), (nums[0], nums[1] + 1, 0)
                if op == "^":
                    hi = (nums[0] + 1, 0, 0) if nums[0] > 0 else (0, nums[1] + 1, 0)
            else:
                lo = tuple(nums)
                if op == "^":
                    hi = (nums[0] + 1, 0, 0) if nums[0] > 0 else ((0, nums[1] + 1, 0) if nums[1] > 0 else (0, 0, nums[2] + 1))
                elif op == "~":
                    hi = (nums[0], nums[1] + 1, 0)
                elif op == ">=":
                    hi = (10**9, 0, 0)
                else:
                    hi = (nums[0], nums[1], nums[2] + 1)
        else:
            continue
        ok = [c for c in cands if lo <= c[0] < hi]
        if ok and (best is None or ok[-1][0] > best[0]):
            best = ok[-1]
    return best[1] if best else None


def scan_dependencies(root, workdir, limit, extra_rules):
    os.makedirs(workdir, exist_ok=True)
    deps = direct_dependencies(root)
    info = {"found": len(deps), "checked": [], "failed": [], "skipped": max(0, len(deps) - limit)}
    findings = []
    for dep in deps[:limit]:
        label = f"{dep['eco']}:{dep['name']}"
        try:
            folder, ver = fetch_package(dep, workdir)
        except Exception as ex:
            info["failed"].append({"package": label, "reason": str(ex)[:160]})
            continue
        sub = Scanner(folder, extra_rules)
        r = sub.run()
        prefix = f"deps/{dep['eco']}/{dep['name']}@{ver}/"
        n = 0
        for f in r["findings"]:
            if f["rule"] in ("DEP_TYPOSQUAT",):
                continue
            f["file"] = prefix + (f["file"] or "")
            f["context"] = "dependency" if f["context"] == "code" else f["context"]
            f["package"] = f"{dep['name']}@{ver}"
            if f["rule"] == "INSTALL_SCRIPT" and re.match(r'"(prepare|prepublish\w*|preuninstall|postuninstall)"', f["snippet"]):
                f["severity"] = "low"  # tidak dijalankan saat paket dipasang dari registry
            findings.append(f)
            n += 1
        hosts = [d["domain"] for d in r["domains"] if not d["allowlisted"]][:10]
        info["checked"].append({"package": f"{label}@{ver}", "findings": n, "external_domains": hosts,
                                "files": r["inventory"]["files_scanned"]})
    return findings, info


# ---------------------------------------------------------------------------
# Alat keamanan eksternal (dipakai bila terpasang)
# ---------------------------------------------------------------------------
def _run(cmd, timeout=600):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as ex:
        return subprocess.CompletedProcess(cmd, 99, "", str(ex))


def run_external(root, workdir, yara_rules=None):
    status, findings = {}, []
    relp = lambda p: os.path.relpath(p, root).replace(os.sep, "/") if p and os.path.isabs(p) else (p or "")
    # gitleaks
    if shutil.which("gitleaks"):
        out = os.path.join(workdir, "gitleaks.json")
        r = _run(["gitleaks", "dir", root, "--report-format", "json", "--report-path", out, "--no-banner", "--redact", "--exit-code", "0"])
        if r.returncode != 0 or not os.path.exists(out):
            r = _run(["gitleaks", "detect", "--no-git", "-s", root, "-f", "json", "-r", out, "--no-banner", "--redact", "--exit-code", "0"])
        try:
            items = json.load(open(out)) or []
            for it in items:
                findings.append(make_finding("EXT_GITLEAKS", "secrets", "medium", relp(it.get("File")), it.get("StartLine"),
                                             f"{it.get('RuleID')}: {it.get('Match', '')}", f"gitleaks: {it.get('Description') or it.get('RuleID')}",
                                             tool="gitleaks"))
            status["gitleaks"] = f"ok · {len(items)} temuan"
        except Exception as ex:
            status["gitleaks"] = f"gagal: {(r.stderr or str(ex))[:120]}"
    else:
        status["gitleaks"] = "tidak terpasang"
    # trufflehog
    if shutil.which("trufflehog"):
        r = _run(["trufflehog", "filesystem", root, "--json", "--no-update", "--no-verification"])
        n = 0
        for line in r.stdout.splitlines():
            try:
                it = json.loads(line)
            except Exception:
                continue
            fs = ((it.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
            findings.append(make_finding("EXT_TRUFFLEHOG", "secrets", "medium", relp(fs.get("file")), fs.get("line"),
                                         f"{it.get('DetectorName')}: {str(it.get('Redacted') or '')[:60]}", f"trufflehog: kredensial {it.get('DetectorName')}",
                                         tool="trufflehog"))
            n += 1
        status["trufflehog"] = f"ok · {n} temuan" if r.returncode in (0, 183) else f"gagal: {r.stderr[:120]}"
    else:
        status["trufflehog"] = "tidak terpasang"
    # semgrep
    if shutil.which("semgrep"):
        r = _run(["semgrep", "scan", "--config", "p/default", "--json", "--quiet", "--metrics", "off", "--timeout", "30", root], timeout=1200)
        try:
            data = json.loads(r.stdout)
            sevmap = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            for it in data.get("results", []):
                ex = it.get("extra") or {}
                findings.append(make_finding("EXT_SEMGREP", "external", sevmap.get(ex.get("severity"), "low"), relp(it.get("path")),
                                             (it.get("start") or {}).get("line"), (ex.get("lines") or "")[:SNIPPET_LEN],
                                             f"semgrep {it.get('check_id', '').split('.')[-1]}: {(ex.get('message') or '')[:200]}",
                                             tool="semgrep"))
            status["semgrep"] = f"ok · {len(data.get('results', []))} temuan"
        except Exception:
            tail = [l for l in (r.stderr or "").strip().splitlines() if l.strip()][-1:] or ["tidak ada output (butuh internet untuk aturan p/default?)"]
            status["semgrep"] = f"gagal: {tail[0][:160]}"
    else:
        status["semgrep"] = "tidak terpasang"
    # osv-scanner
    if shutil.which("osv-scanner"):
        r = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", root])
        if not r.stdout.strip().startswith("{"):
            r = _run(["osv-scanner", "--format", "json", "-r", root])
        try:
            data = json.loads(r.stdout)
            n = 0
            for res in data.get("results", []):
                for pk in res.get("packages", []):
                    p = pk.get("package", {})
                    ids = [v.get("id") for v in pk.get("vulnerabilities", [])]
                    mal = [i for i in ids if str(i).startswith("MAL-")]
                    sev = "critical" if mal else ("high" if len(ids) >= 5 else "medium")
                    findings.append(make_finding("EXT_OSV_SCANNER", "dependency", sev, relp((res.get("source") or {}).get("path")), None,
                                                 f"{p.get('name')}@{p.get('version')} → {', '.join(ids[:8])}",
                                                 "osv-scanner: " + ("PAKET BERBAHAYA (malware) tercatat di OSV" if mal else f"{len(ids)} celah keamanan diketahui"),
                                                 tool="osv-scanner"))
                    n += 1
            status["osv-scanner"] = f"ok · {n} paket bermasalah"
        except Exception:
            status["osv-scanner"] = f"gagal: {(r.stderr or '')[:120]}"
    else:
        status["osv-scanner"] = "tidak terpasang"
    # yara (opsional, butuh file/folder aturan)
    if yara_rules:
        if shutil.which("yara"):
            rule_files = [yara_rules] if os.path.isfile(yara_rules) else [os.path.join(dp, f) for dp, _, fs in os.walk(yara_rules) for f in fs if f.endswith((".yar", ".yara"))]
            n = 0
            for rf in rule_files[:200]:
                r = _run(["yara", "-r", "-w", rf, root])
                for line in r.stdout.splitlines():
                    parts = line.split(" ", 1)
                    if len(parts) == 2:
                        findings.append(make_finding("EXT_YARA", "external", "high", relp(parts[1]), None, parts[0],
                                                     f"YARA: cocok dengan aturan {parts[0]}", tool="yara"))
                        n += 1
            status["yara"] = f"ok · {n} kecocokan"
        else:
            status["yara"] = "tidak terpasang"
    return findings, status


# ---------------------------------------------------------------------------
# Mengambil target dengan aman
# ---------------------------------------------------------------------------
def fetch_target(target, workdir, depth=1):
    """depth: 1 (default), angka (untuk --history), atau None (riwayat penuh, untuk --diff)."""
    meta = {"input": target}
    gh = re.match(r"^(https?://)?(www\.)?(github\.com|gitlab\.com|bitbucket\.org)/([\w.-]+)/([\w.-]+?)(\.git)?(/tree/([^/\s]+)(/.*)?)?/?$", target)
    if gh:
        url = f"https://{gh.group(3)}/{gh.group(4)}/{gh.group(5)}.git"
        branch = gh.group(8)
        dest = os.path.join(workdir, gh.group(5))
        cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
               "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
               "clone", "--no-recurse-submodules", "--quiet"] + (["--depth", str(depth)] if depth else [])
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, dest]
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
        r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        if r.returncode != 0:
            raise SystemExit(f"[GAGAL CLONE] {r.stderr.strip()}\nTips: unduh ZIP repo dari GitHub lalu jalankan scan pada file .zip-nya.")
        h = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True)
        meta.update(source="git", url=url, branch=branch, commit=h.stdout.strip(), path=dest, git_dir=dest,
                    host=gh.group(3), owner=gh.group(4), repo=gh.group(5))
        sub = os.path.join(dest, ".gitmodules")
        meta["has_submodules"] = os.path.exists(sub)
        if gh.group(9):
            meta["subpath"] = gh.group(9).strip("/")
        return meta
    if os.path.isfile(target) and target.lower().endswith((".zip", ".skill", ".plugin")):
        dest = os.path.join(workdir, "extracted")
        try:
            safe_extract_zip(target, dest)
        except ValueError as ex:
            raise SystemExit(f"[BAHAYA] {ex}")
        entries = os.listdir(dest)
        path = os.path.join(dest, entries[0]) if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])) else dest
        meta.update(source="zip", path=path, sha256=sha256_file(target))
        return meta
    if os.path.isdir(target):
        meta.update(source="folder", path=os.path.realpath(target))
        if os.path.isdir(os.path.join(target, ".git")):
            h = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", target, "rev-parse", "HEAD"], capture_output=True, text=True)
            meta["commit"] = h.stdout.strip() or None
            meta["git_dir"] = os.path.realpath(target)
        return meta
    raise SystemExit(f"Target tidak dikenali: {target}\nGunakan URL GitHub, path folder, atau file .zip")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Laporan HTML
# ---------------------------------------------------------------------------
STATUS_LABEL = {"confirmed": "Terkonfirmasi berbahaya", "suspicious": "Mencurigakan", "false_positive": "Alarm palsu",
                "benign": "Wajar", "needs_check": "Perlu dicek manual"}

# ---------------------------------------------------------------------------
# Bahasa laporan (id / en)
# ---------------------------------------------------------------------------
I18N = {
    "id": {
        "sev": SEV_LABEL, "cat": CATEGORIES, "st_map": STATUS_LABEL,
        "verdict": {"BAHAYA": "BAHAYA", "WASPADA": "WASPADA", "PERLU DICEK": "PERLU DICEK", "RISIKO RENDAH": "RISIKO RENDAH",
                    "TIDAK DITEMUKAN INDIKASI BAHAYA": "TIDAK DITEMUKAN INDIKASI BAHAYA"},
        "headline": {"BAHAYA": "Jangan diinstall.", "WASPADA": "Tinjau sebelum dipakai.", "PERLU DICEK": "Butuh pengecekan manual.",
                     "RISIKO RENDAH": "Risiko rendah terdeteksi.", "TIDAK DITEMUKAN INDIKASI BAHAYA": "Tidak ditemukan indikasi bahaya."},
        "eyebrow": "LAPORAN KEAMANAN STATIS", "print": "Cetak laporan", "target": "Target", "commit": "Commit", "status": "Status",
        "reviewed": "Ditinjau AI", "auto": "Otomatis — belum ditinjau", "no_commit": "tidak ada (folder tanpa git)",
        "auto_summary": "Penilaian otomatis, belum ditinjau. Skor risiko {score} dari {n} temuan. Minta AI meninjau temuan untuk vonis akhir.",
        "dash_small": "RINGKASAN PEMINDAIAN", "dash_title": "Hasil temuan", "by_cat": "Temuan per kategori", "total": "TOTAL",
        "no_findings": "Tidak ada temuan.", "risk": "SKOR RISIKO", "chip": "DIBACA, TIDAK DIJALANKAN", "repo_type": "JENIS REPO",
        "files": "FILE", "ext_domains": "DOMAIN LUAR", "next": "LANGKAH BERIKUTNYA", "recs": "Rekomendasi", "rec": "REKOMENDASI",
        "ctx_small": "KONTEKS", "ctx": "Pemeriksaan tambahan", "rep": "Reputasi GitHub", "diff": "Perubahan versi",
        "deps": "Dependensi dipindai", "hist": "Riwayat commit", "ext": "Alat eksternal", "detail": "DETAIL", "findings": "Temuan",
        "shown": "ditampilkan", "all": "Semua", "confirmed": "Terkonfirmasi", "new": "Baru", "search": "Cari file, aturan, atau kata…",
        "hide_fp": "Sembunyikan alarm palsu", "no_match": "Tidak ada temuan yang cocok dengan filter.", "b_new": "BARU",
        "b_old": "LAMA", "was": "asal", "net": "JARINGAN", "domains": "Domain eksternal", "outside": "DI LUAR DAFTAR AMAN",
        "c_domain": "Domain", "c_count": "Jumlah", "c_loc": "Contoh lokasi", "c_note": "Catatan", "hidden": "TERSEMBUNYI",
        "no_domains": "Tidak ada domain di luar daftar aman.", "suppressed": "{n} temuan disembunyikan oleh daftar ignore/baseline Anda (lihat findings.json → suppressed).",
        "limits_b": "Batasan.", "limits": "Repo Scan memeriksa kode secara statis tanpa menjalankannya. Hasil ini mengurangi risiko, <b>bukan jaminan 100% aman</b>: kode yang mengunduh payload saat dijalankan, isi file biner, submodule, dan perubahan setelah commit di atas tidak tercakup. Scan ulang setiap kali repo diperbarui.",
        "skipped": "Dilewati: {n} file.", "footer": "DIBACA, TIDAK DIJALANKAN.", "auto_note": "Catatan otomatis",
        "rep_owner": "Pemilik", "rep_age": "Umur repo", "rep_stars": "Bintang", "rep_fork": "Fork dari", "rep_license": "Lisensi",
        "rep_push": "Push terakhir", "days": "hari", "days_ago": "hari lalu", "owner_age": "umur akun",
        "diff_range": "Rentang", "diff_changed": "File berubah", "diff_new": "Temuan baru", "diff_resolved": "Temuan hilang",
        "deps_checked": "Diperiksa", "deps_failed": "Gagal", "deps_found": "Ditemukan", "hist_commits": "Commit dipindai",
        "hist_findings": "Temuan di riwayat", "not_run": "tidak dijalankan", "md_verdict": "Vonis", "md_score": "Skor risiko",
        "md_kind": "Jenis repo", "md_files": "File dipindai", "md_findings": "Temuan", "md_review": "Tinjauan",
        "md_level": "Tingkat", "md_loc": "Lokasi", "md_desc": "Keterangan", "md_limits": "Scan statis mengurangi risiko, bukan jaminan 100% aman. Hasil hanya berlaku untuk commit di atas.",
    },
    "en": {
        "sev": {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"},
        "cat": {"network": "Outbound connections", "install": "Install/build-time code", "obfuscation": "Obfuscated code",
                "credentials": "Sensitive data / credential access", "persistence": "Persistence / privileges",
                "destructive": "Destructive / disabling security", "binary": "Binary / unreviewable files", "dependency": "Dependencies",
                "ai": "AI-specific (skill/plugin/MCP)", "ci": "GitHub Actions / CI", "secrets": "Leaked secrets",
                "dataflow": "Sensitive data flowing to network", "reputation": "Repo & owner reputation", "history": "Commit history",
                "external": "External security tools"},
        "st_map": {"confirmed": "Confirmed malicious", "suspicious": "Suspicious", "false_positive": "False positive",
                   "benign": "Benign", "needs_check": "Needs manual check"},
        "verdict": {"BAHAYA": "DANGEROUS", "WASPADA": "CAUTION", "PERLU DICEK": "NEEDS CHECK", "RISIKO RENDAH": "LOW RISK",
                    "TIDAK DITEMUKAN INDIKASI BAHAYA": "NO INDICATION OF DANGER"},
        "headline": {"BAHAYA": "Do not install.", "WASPADA": "Review before use.", "PERLU DICEK": "Needs a manual check.",
                     "RISIKO RENDAH": "Low risk detected.", "TIDAK DITEMUKAN INDIKASI BAHAYA": "No indication of danger found."},
        "eyebrow": "STATIC SECURITY REPORT", "print": "Print report", "target": "Target", "commit": "Commit", "status": "Status",
        "reviewed": "Reviewed by AI", "auto": "Automatic — not yet reviewed", "no_commit": "none (folder without git)",
        "auto_summary": "Automatic assessment, not yet reviewed. Risk score {score} from {n} findings. Ask an AI to review the findings for a final verdict.",
        "dash_small": "SCAN SUMMARY", "dash_title": "Findings", "by_cat": "Findings by category", "total": "TOTAL",
        "no_findings": "No findings.", "risk": "RISK SCORE", "chip": "READ, NEVER EXECUTED", "repo_type": "REPO TYPE",
        "files": "FILES", "ext_domains": "EXTERNAL DOMAINS", "next": "NEXT STEPS", "recs": "Recommendations", "rec": "RECOMMENDATION",
        "ctx_small": "CONTEXT", "ctx": "Additional checks", "rep": "GitHub reputation", "diff": "Version changes",
        "deps": "Dependencies scanned", "hist": "Commit history", "ext": "External tools", "detail": "DETAILS", "findings": "Findings",
        "shown": "shown", "all": "All", "confirmed": "Confirmed", "new": "New", "search": "Search file, rule or keyword…",
        "hide_fp": "Hide false positives", "no_match": "No findings match the filter.", "b_new": "NEW", "b_old": "EXISTING",
        "was": "was", "net": "NETWORK", "domains": "External domains", "outside": "OUTSIDE ALLOWLIST", "c_domain": "Domain",
        "c_count": "Count", "c_loc": "Example locations", "c_note": "Notes", "hidden": "HIDDEN",
        "no_domains": "No domains outside the allowlist.", "suppressed": "{n} findings suppressed by your ignore list/baseline (see findings.json → suppressed).",
        "limits_b": "Limitations.", "limits": "Repo Scan inspects code statically without running it. This lowers risk but is <b>not a 100% safety guarantee</b>: code that downloads payloads at runtime, binary contents, submodules and changes after the commit above are not covered. Re-scan whenever the repo is updated.",
        "skipped": "Skipped: {n} files.", "footer": "READ, NEVER EXECUTED.", "auto_note": "Automatic note",
        "rep_owner": "Owner", "rep_age": "Repo age", "rep_stars": "Stars", "rep_fork": "Fork of", "rep_license": "License",
        "rep_push": "Last push", "days": "days", "days_ago": "days ago", "owner_age": "account age",
        "diff_range": "Range", "diff_changed": "Files changed", "diff_new": "New findings", "diff_resolved": "Resolved findings",
        "deps_checked": "Checked", "deps_failed": "Failed", "deps_found": "Found", "hist_commits": "Commits scanned",
        "hist_findings": "History findings", "not_run": "not run", "md_verdict": "Verdict", "md_score": "Risk score",
        "md_kind": "Repo type", "md_files": "Files scanned", "md_findings": "Findings", "md_review": "Review",
        "md_level": "Severity", "md_loc": "Location", "md_desc": "Description", "md_limits": "Static scanning lowers risk but is not a 100% safety guarantee. Results apply only to the commit above.",
    },
}

DESC_EN = {
    "AI_BYPASS_PERMISSIONS": "Disables the AI agent's confirmation/permission safeguards.",
    "AI_EXFIL_INSTRUCTION": "Instruction to send sensitive data somewhere external.",
    "AI_HIDDEN_COMMENT": "Hidden HTML comment containing instruction-like text (invisible when rendered, but read by AI).",
    "AI_HIDDEN_TAG_CHARS": "Invisible Unicode 'tag' characters (ASCII smuggling) — hidden text an AI can read.",
    "AI_HIDE_FROM_USER": "Instruction telling the AI to hide actions from the user.",
    "AI_PROMPT_INJECTION": "Prompt-injection phrasing (attempts to hijack the AI's instructions).",
    "AI_SCANNER_MANIPULATION": "Text trying to persuade an AI/scanner to skip checks or declare the repo safe.",
    "AI_WIDE_PERMISSIONS": "Very broad tool permissions granted without confirmation.",
    "BINARY_ARCHIVE": "Compressed archive inside the repo — its contents are not scanned.",
    "BINARY_DISGUISED": "Executable program disguised with a fake file extension!",
    "BINARY_EXECUTABLE": "Binary program — contents cannot be reviewed; make sure its origin is trustworthy.",
    "BUILD_SCRIPT": "Build script that runs automatically at compile/install time.",
    "CI_INJECTION": "External input used directly in a workflow command — command-injection risk.",
    "CI_PR_TARGET": "`pull_request_target` workflow — outside PRs may run with access to repo secrets.",
    "CI_SECRET_SEND": "Secret used together with a network request.",
    "CRED_BROWSER": "Accesses browser data (saved passwords, cookies).",
    "CRED_DOTENV_HUNT": "Searches for/reads .env files outside its own project (API-key hunting).",
    "CRED_DOTENV_READ": "Reads a .env file directly (normal for own config; check where values go).",
    "CRED_ENV_DUMP": "Collects ALL environment variables (may contain API keys).",
    "CRED_KEYCHAIN": "Accesses the system keychain / password store.",
    "CRED_PKG_CONFIG": "Reads package-registry token files in the user's home folder.",
    "CRED_SPY": "Reads keyboard, screen or clipboard.",
    "CRED_SSH_CLOUD": "Reads/touches SSH keys or cloud credentials.",
    "CRED_WALLET": "Accesses crypto wallets.",
    "DATAFLOW_EXFIL": "Sensitive data is read AND sent over the network in the same file — data-theft pattern.",
    "DEP_CUSTOM_REGISTRY": "Package registry redirected to an unofficial server — every dependency could be swapped.",
    "DEP_KNOWN_MALICIOUS": "This package is listed in the OSV database as MALWARE.",
    "DEP_KNOWN_VULN": "This dependency version has known security vulnerabilities (OSV).",
    "DEP_REMOTE_SOURCE": "Dependency fetched straight from a URL/git (not the official registry, unverified).",
    "DEP_TYPOSQUAT": "Package name is almost identical to a popular package — possible typosquatting.",
    "DESTRUCT_DISABLE_SEC": "Disables system security features (antivirus, Gatekeeper, firewall).",
    "DESTRUCT_WIPE": "Deletes/formats data on a large scale.",
    "DOCKER_HOST_MOUNT": "Container mounts sensitive host folders / the Docker socket.",
    "DOCKER_PRIVILEGED": "Container is given full access to the host system.",
    "DOCKER_REMOTE_ADD": "Dockerfile downloads files from the internet without checksum verification.",
    "DOCKER_UNPINNED": "Base image is not pinned to a version (latest).",
    "EXEC_BIT_ODD": "Non-program file has the executable permission set.",
    "FILE_TOO_LARGE": "Very large file, contents not scanned — check manually if suspicious.",
    "GIT_FILTER": "Git filter can run programs on checkout (if configured).",
    "GIT_SUBMODULES": "Repo uses submodules — their contents are NOT scanned; scan them separately.",
    "HIST_REMOVED_DANGEROUS": "A dangerous pattern existed in history and was later removed. Check who added and removed it.",
    "HIST_REMOVED_SECRET": "A secret was committed and later removed — it can still be recovered from git history.",
    "IDE_AUTORUN": "VS Code task runs automatically when the folder is opened.",
    "INSTALL_SCRIPT": "Script runs automatically on package install.",
    "INSTALL_SCRIPT_ACTIVE": "setup.py makes network calls or runs commands — executed at install.",
    "MAKEFILE_NETWORK": "Makefile runs network/decode commands during `make`.",
    "MCP_LOCAL_COMMAND": "Local MCP server — this command runs on your computer.",
    "MCP_REMOTE": "Remote MCP server — tool requests and data are sent to this server.",
    "MCP_SECRET_ENV": "MCP server asks for an API key/token via env — make sure the server is trustworthy.",
    "MINIFIED_CODE": "Extremely long code line (minified/packed) — hard for humans to review.",
    "NET_DOWNLOAD_EXEC": "Downloads a script from the internet and runs it immediately.",
    "NET_EXFIL_SERVICE": "Service commonly used to receive stolen data (Discord/Telegram webhooks, request catchers).",
    "NET_PASTE_FILEHOST": "Anonymous paste/file-hosting site (used to fetch payloads or upload data).",
    "NET_RAW_IP": "Connects to a raw IP address (not a domain name).",
    "NET_REVERSE_SHELL": "Reverse-shell pattern (hands control of the computer to someone else).",
    "NET_TUNNEL": "Public tunnel to the local machine.",
    "OBF_DECODE_EXEC": "Decodes hidden data and executes it (classic malware technique).",
    "OBF_DYNAMIC_EXEC": "Executes code dynamically (often normal; check the context).",
    "OBF_HEX_BLOB": "Long hex/char-code sequence (obfuscation).",
    "OBF_HIDDEN_PAYLOAD": "URL/command hidden in base64/hex (already decoded automatically).",
    "OBF_LONG_ENCODED": "Long encoded string — may hide a payload.",
    "OBF_REVERSED_URL": "Reversed string used to hide a URL/command.",
    "OSV_UNAVAILABLE": "OSV vulnerability check could not run — no internet?",
    "PERSIST_AUTOSTART": "Installs itself to run automatically (startup/cron/service).",
    "PERSIST_SHELLRC": "Writes to the user's shell startup files.",
    "PLUGIN_HOOK": "Plugin/agent hook — this command runs AUTOMATICALLY on certain events.",
    "PRIV_ESCALATE": "Requests/changes elevated privileges.",
    "PY_BUILD_HOOK": "pyproject.toml uses a build hook — custom code runs at install time.",
    "PY_CUSTOM_BACKEND": "In-repo custom build backend — its code runs on `pip install`.",
    "QUARANTINE_REMOVE": "Removes the macOS quarantine flag (bypasses Gatekeeper checks).",
    "RANSOMWARE_PATTERN": "Ransomware pattern: walks many files, encrypts them, then deletes/renames originals.",
    "RANSOM_NOTE": "Ransom-note text (ransomware).",
    "REP_ARCHIVED": "Repo is archived — no longer maintained; vulnerabilities won't be fixed.",
    "REP_FORK_OF_POPULAR": "Fork of a popular repo. Scammers spread malicious forks — make sure you need this fork, not the original.",
    "REP_NEW_OWNER": "Owner account was created very recently (< 30 days) — common for malware distributors.",
    "REP_NEW_REPO": "Very new repo (< 14 days) — not yet vetted by the community.",
    "REP_STAR_SPIKE": "Unusual star spike for such a young repo — stars can be bought to lure victims.",
    "REP_YOUNG_OWNER": "Owner account is young with no track record.",
    "SCANNER_EVASION": "Repo ships its own Repo Scan config — Repo Scan does NOT use it; possible attempt to hide findings.",
    "SECRET_KEY": "API key / private key written in the repo.",
    "SYMLINK_ESCAPE": "Symlink points outside the repo (could make tools read/write system files).",
    "UNICODE_BIDI": "Bidirectional text characters (Trojan Source) — code looks different from what runs.",
    "UNICODE_ZERO_WIDTH": "Invisible zero-width characters in a single line.",
}


def tr(lang, key, **kw):
    v = I18N.get(lang or "id", I18N["id"]).get(key, I18N["id"].get(key, key))
    return v.format(**kw) if kw and isinstance(v, str) else v


def desc_for(f, lang):
    if lang == "en" and not f["rule"].startswith("EXT_"):
        return DESC_EN.get(f["rule"], f["description"])
    return f["description"]


VERDICT_CLASS = {"BAHAYA": "v-danger", "DANGEROUS": "v-danger", "WASPADA": "v-warn", "CAUTION": "v-warn",
                 "PERLU DICEK": "v-check", "NEEDS CHECK": "v-check", "RISIKO RENDAH": "v-safe", "LOW RISK": "v-safe",
                 "TIDAK DITEMUKAN INDIKASI BAHAYA": "v-safe", "NO INDICATION OF DANGER": "v-safe",
                 "NO INDICATION OF DANGER FOUND": "v-safe", "AMAN": "v-safe", "SAFE": "v-safe"}
VERDICT_CANON = {"DANGEROUS": "BAHAYA", "CAUTION": "WASPADA", "NEEDS CHECK": "PERLU DICEK", "LOW RISK": "RISIKO RENDAH",
                 "NO INDICATION OF DANGER": "TIDAK DITEMUKAN INDIKASI BAHAYA", "NO INDICATION OF DANGER FOUND": "TIDAK DITEMUKAN INDIKASI BAHAYA",
                 "AMAN": "TIDAK DITEMUKAN INDIKASI BAHAYA", "SAFE": "TIDAK DITEMUKAN INDIKASI BAHAYA"}

REPORT_CSS = r"""
:root{--bg:#F7F8FC;--surface:#FFFFFF;--ink:#17213A;--muted:#69758C;--primary:#6D5DFB;--secondary:#23B7A4;--accent:#FF8B65;--line:#E5E8F0;
--heading:"Plus Jakarta Sans",system-ui,-apple-system,"Segoe UI",sans-serif;--body:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"DM Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--radius:14px;--radius-btn:8px;--shadow:0 14px 36px rgba(34,43,78,.10);--shadow-btn:0 7px 17px rgba(109,93,251,.24)}
*{box-sizing:border-box}
body{margin:0;color:var(--ink);font-family:var(--body);line-height:1.6;font-size:15px;
background:radial-gradient(ellipse at 78% 12%,rgba(109,93,251,.10),transparent 34%),linear-gradient(135deg,#FBFCFF 0%,#F4F6FC 100%);min-height:100vh}
.wrap{max-width:1180px;margin:0 auto;padding:0 32px}
h1,h2,h3{font-family:var(--heading);font-weight:800;letter-spacing:-.055em;line-height:1.08;margin:0}
code,.mono{font-family:var(--mono)}
a{color:var(--primary)}
/* topbar */
.topbar{height:80px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px}
.brand b{font:800 20px var(--heading);letter-spacing:-.06em}.brand b span{color:var(--primary)}
.brandmark{width:32px;height:32px;border-radius:9px;background:var(--primary);display:flex;align-items:flex-end;justify-content:center;gap:3px;padding:8px;box-shadow:0 5px 12px rgba(109,93,251,.27)}
.brandmark i{width:4px;border-radius:3px;background:#fff}.brandmark i:nth-child(1){height:8px}.brandmark i:nth-child(2){height:14px}.brandmark i:nth-child(3){height:10px}
.top-meta{display:flex;align-items:center;gap:20px}
.top-meta small{font-family:var(--mono);font-size:12px;color:var(--muted);letter-spacing:.06em}
.btn{display:inline-flex;align-items:center;gap:.5rem;min-height:44px;padding:0 18px;background:var(--ink);color:#fff;border:0;border-radius:var(--radius-btn);
font:700 14px var(--heading);cursor:pointer;box-shadow:0 4px 10px rgba(23,33,58,.13);transition:transform .2s ease,box-shadow .2s ease}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(23,33,58,.2)}.btn:active{transform:none}
.btn:focus-visible,.seg button:focus-visible,.input:focus{outline:2px solid var(--primary);outline-offset:2px}
/* hero */
.hero{display:grid;grid-template-columns:.92fr 1.08fr;gap:40px;align-items:center;padding:56px 0 48px;position:relative}
.eyebrow{font-family:var(--mono);display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(109,93,251,.25);background:rgba(109,93,251,.08);color:#5B4BE0;
border-radius:30px;padding:7px 14px;font-size:12px;font-weight:500;letter-spacing:.1em}
.eyebrow i{width:7px;height:7px;border-radius:50%;background:var(--primary);box-shadow:0 0 0 4px rgba(109,93,251,.13)}
.hero h1{font-size:56px;letter-spacing:-.065em;line-height:1.04;margin:22px 0 16px;word-break:break-word}
.hero h1 em{font-style:normal;background:linear-gradient(95deg,#6D5DFB,#23B7A4);-webkit-background-clip:text;background-clip:text;color:transparent}
.v-danger h1 em{background:linear-gradient(95deg,#FF8B65,#6D5DFB);-webkit-background-clip:text;background-clip:text}
.lead{font-size:16px;line-height:1.8;color:var(--muted);margin:0;max-width:520px}
.meta{margin-top:26px;display:grid;gap:8px}
.meta div{display:flex;gap:12px;align-items:baseline;font-size:13px}
.meta span{font-family:var(--mono);font-size:11px;letter-spacing:.12em;color:var(--muted);min-width:96px;text-transform:uppercase}
.meta code{font-size:13px;color:var(--ink);word-break:break-all}
/* dashboard */
.visual{position:relative;padding:18px 0}
.glow{position:absolute;inset:0 0 auto auto;width:440px;height:320px;border-radius:50%;background:radial-gradient(ellipse,rgba(109,93,251,.30),transparent 70%);filter:blur(14px)}
.dash{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:0 22px 55px rgba(41,52,91,.13),0 3px 9px rgba(41,52,91,.05);padding:22px}
.dash-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
.dash-head small{font-family:var(--mono);display:block;font-size:11px;letter-spacing:.13em;color:var(--muted)}
.dash-head b{font:800 26px var(--heading);letter-spacing:-.05em;display:block;margin-top:4px}
.verdict-pill{font-family:var(--mono);font-size:12px;font-weight:500;letter-spacing:.1em;padding:8px 14px;border-radius:999px;white-space:nowrap}
.v-danger .verdict-pill{background:var(--accent);color:var(--ink)}
.v-warn .verdict-pill{background:rgba(255,139,101,.18);color:var(--ink);border:1px solid rgba(255,139,101,.55)}
.v-check .verdict-pill{background:rgba(109,93,251,.12);color:var(--ink);border:1px solid rgba(109,93,251,.35)}
.v-safe .verdict-pill{background:rgba(35,183,164,.14);color:var(--ink);border:1px solid rgba(35,183,164,.5)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:18px}
.kpi{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px}
.kpi small{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--muted)}
.kpi b{display:block;font:800 28px var(--heading);letter-spacing:-.04em;margin-top:4px}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;flex:none}
.d-critical{background:var(--accent)}.d-high{background:rgba(255,139,101,.45);box-shadow:inset 0 0 0 1.5px var(--accent)}
.d-medium{background:var(--primary)}.d-low{background:rgba(105,117,140,.5)}.d-info{background:var(--line)}
.bars{margin-top:14px;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.bars-title{display:flex;justify-content:space-between;font-size:13px;font-weight:600}.bars-title span{color:var(--muted);font-weight:400;font-family:var(--mono);font-size:11px}
.bar{display:grid;grid-template-columns:150px 1fr 28px;gap:10px;align-items:center;margin-top:9px;font-size:12px;color:var(--muted)}
.bar div{height:8px;border-radius:99px;background:var(--bg);overflow:hidden}
.bar div i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,#6D5DFB,#23B7A4);transform-origin:left;animation:grow .8s ease-out both}
.bar b{font-family:var(--mono);font-weight:500;color:var(--ink);text-align:right}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.float-stat{position:absolute;z-index:2;right:-14px;bottom:-8px;display:flex;align-items:center;gap:10px;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 14px;box-shadow:0 12px 30px rgba(39,51,75,.13)}
.float-stat>span{width:30px;height:30px;border-radius:8px;background:rgba(109,93,251,.12);color:var(--primary);display:grid;place-items:center;font-weight:800}
.float-stat small{display:block;font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--muted)}
.float-stat b{font:800 18px var(--heading)}
.float-chip{position:absolute;left:-12px;bottom:0;background:var(--ink);color:#D8D5FF;border-radius:30px;padding:9px 16px;font-family:var(--mono);font-size:11px;letter-spacing:.08em;box-shadow:0 8px 20px rgba(23,33,58,.2)}
/* proof strip */
.proof{display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;padding:22px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.proof>small{font-family:var(--mono);font-size:11px;letter-spacing:.15em;color:var(--muted)}
.proof .items{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.proof .items b{font:800 13px var(--heading);letter-spacing:.06em}
.proof .items i{width:4px;height:4px;border-radius:50%;background:#B8BED0}
.proof .items span{font-family:var(--mono);font-size:12px;color:var(--muted);margin-left:6px;font-weight:400;letter-spacing:0}
/* sections */
section.block{padding:48px 0 8px}
.sec-head{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.sec-head small{font-family:var(--mono);font-size:11px;letter-spacing:.15em;color:var(--muted);display:block;margin-bottom:8px}
.sec-head h2{font-size:32px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}
.recs{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.rec{padding:20px 22px;transition:transform .2s ease,box-shadow .2s ease}
.rec:hover{transform:translateY(-2px);box-shadow:0 18px 40px rgba(34,43,78,.13)}
.rec .ic{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:rgba(109,93,251,.10);color:var(--primary);font-weight:800;margin-bottom:12px}
.rec:nth-child(3n+2) .ic{background:rgba(35,183,164,.12);color:var(--secondary)}.rec:nth-child(3n) .ic{background:rgba(255,139,101,.15);color:var(--accent)}
.rec small{font-family:var(--mono);font-size:10px;letter-spacing:.13em;color:var(--muted)}
.rec p{margin:6px 0 0;font-size:14px;line-height:1.6}
/* toolbar */
.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.seg{display:inline-flex;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:4px;gap:2px;flex-wrap:wrap}
.seg button{min-height:36px;border:0;background:transparent;border-radius:7px;padding:0 12px;font:600 13px var(--body);color:var(--muted);cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:background .18s ease,color .18s ease}
.seg button:hover{color:var(--ink)}
.seg button[aria-pressed="true"]{background:var(--primary);color:#fff;box-shadow:var(--shadow-btn)}
.seg button[aria-pressed="true"] .dot{box-shadow:0 0 0 2px #fff}
.input{flex:1;min-width:220px;min-height:44px;padding:0 14px;background:var(--surface);color:var(--ink);border:1px solid var(--line);border-radius:var(--radius-btn);font:14px var(--body)}
.input:hover{border-color:rgba(23,33,58,.18)}
.check{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--muted);cursor:pointer;min-height:44px}
.check input{accent-color:var(--primary);width:16px;height:16px}
/* findings */
.findings{display:grid;gap:10px}
.f{padding:16px 18px;display:grid;grid-template-columns:58px 1fr;gap:4px 16px;transition:border-color .18s ease,box-shadow .18s ease}
.f:hover{border-color:rgba(23,33,58,.18)}
.f .id{font-family:var(--mono);font-size:12px;color:var(--muted);padding-top:3px}
.f-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:.08em;border-radius:999px;padding:4px 10px;border:1px solid var(--line);background:var(--bg)}
.sev.s-critical{background:var(--accent);border-color:var(--accent)}
.sev.s-critical .dot{background:var(--ink)}
.cat{font-size:12px;color:var(--muted)}
.loc{font-family:var(--mono);font-size:12.5px;color:var(--ink);background:rgba(109,93,251,.07);border-radius:6px;padding:2px 8px;word-break:break-all}
.ctx{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:.08em}
.f p{grid-column:2;margin:6px 0 0;font-size:14px}
.f pre{grid-column:2;margin:8px 0 0;font-family:var(--mono);font-size:12px;line-height:1.55;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;color:var(--ink)}
.rv{grid-column:2;margin-top:10px;display:flex;gap:10px;align-items:flex-start;font-size:13.5px;padding:10px 12px;border-radius:8px;background:rgba(109,93,251,.06);border:1px solid rgba(109,93,251,.18)}
.rv b{white-space:nowrap}
.st-confirmed .rv{background:rgba(255,139,101,.12);border-color:rgba(255,139,101,.45)}
.st-benign .rv,.st-false_positive .rv{background:rgba(35,183,164,.08);border-color:rgba(35,183,164,.35)}
.f.st-benign,.f.st-false_positive{opacity:.6}
.empty{padding:28px;text-align:center;color:var(--muted)}
/* domains */
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:.12em;color:var(--muted);text-align:left;padding:14px 18px;border-bottom:1px solid var(--line);text-transform:uppercase}
td{padding:12px 18px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td code{font-size:13px}
td small{color:var(--muted);font-family:var(--mono);font-size:11.5px;word-break:break-all}
.tag{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;background:var(--accent);color:var(--ink);border-radius:999px;padding:2px 8px;margin-right:6px}
.note{padding:22px 24px;display:grid;grid-template-columns:40px 1fr;gap:14px;align-items:start}
.note .ic{width:40px;height:40px;border-radius:10px;background:rgba(35,183,164,.12);color:var(--secondary);display:grid;place-items:center;font-weight:800}
.note p{margin:0;color:var(--muted);font-size:14.5px}.note b{color:var(--ink)}
footer{margin-top:56px;height:72px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);gap:16px;flex-wrap:wrap}
footer .brand b{font-size:15px}footer .brandmark{width:24px;height:24px;border-radius:7px;padding:6px}footer .brandmark i{width:3px}
footer span{font-family:var(--mono);font-size:11px;letter-spacing:.14em;color:var(--muted)}
@media (max-width:1024px){.hero{grid-template-columns:1fr;gap:28px}.recs{grid-template-columns:1fr 1fr}.float-stat{right:8px}.float-chip{left:8px}}
@media (max-width:640px){.wrap{padding:0 18px}.hero h1{font-size:38px}.kpis{grid-template-columns:1fr 1fr}.recs{grid-template-columns:1fr}.bar{grid-template-columns:110px 1fr 24px}
.f{grid-template-columns:1fr}.f p,.f pre,.rv{grid-column:1}.top-meta small{display:none}.sec-head h2{font-size:26px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media print{.toolbar,.btn{display:none}body{background:#fff}.card,.dash{box-shadow:none}}
"""

REPORT_JS = r"""
(function(){
  var sev='all', q='', hide=false;
  var items=[].slice.call(document.querySelectorAll('.f'));
  function apply(){
    var n=0;
    items.forEach(function(el){
      var ok=(sev==='all'||el.dataset.sev===sev||(sev==='confirmed'&&el.classList.contains('st-confirmed')))
        &&(!q||el.textContent.toLowerCase().indexOf(q)>-1)
        &&!(hide&&(el.classList.contains('st-benign')||el.classList.contains('st-false_positive')));
      el.hidden=!ok; if(ok)n++;
    });
    var c=document.getElementById('count'); if(c)c.textContent=n+' ditampilkan';
    var e=document.getElementById('none'); if(e)e.hidden=n>0;
  }
  document.querySelectorAll('.seg button').forEach(function(b){
    b.addEventListener('click',function(){
      document.querySelectorAll('.seg button').forEach(function(x){x.setAttribute('aria-pressed','false')});
      b.setAttribute('aria-pressed','true'); sev=b.dataset.f; apply();
    });
  });
  var s=document.getElementById('search'); if(s)s.addEventListener('input',function(){q=s.value.trim().toLowerCase();apply()});
  var h=document.getElementById('hidefp'); if(h)h.addEventListener('change',function(){hide=h.checked;apply()});
  apply();
})();
"""


LOGO_PNG_B64 = "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"

REPORT_CSS_EXTRA = r"""
.brandlogo{width:36px;height:36px;display:block}footer .brandlogo{width:26px;height:26px}
.badge-x{font-family:var(--mono);font-size:10px;letter-spacing:.1em;border-radius:999px;padding:3px 9px;border:1px solid var(--line);background:var(--bg);color:var(--muted)}
.badge-x.new{background:var(--primary);border-color:var(--primary);color:#fff}
.badge-x.hist{background:rgba(255,139,101,.14);border-color:rgba(255,139,101,.45);color:var(--ink)}
.badge-x.dep{background:rgba(35,183,164,.12);border-color:rgba(35,183,164,.45);color:var(--ink)}
.autonote{grid-column:2;margin-top:8px;font-size:12.5px;color:var(--muted)}
.ctx-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;align-items:start}
.ctx-card{padding:20px 22px}
.ctx-card small{font-family:var(--mono);font-size:10px;letter-spacing:.13em;color:var(--muted)}
.ctx-card h3{font-size:19px;letter-spacing:-.04em;margin:4px 0 12px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13.5px}
.kv span{color:var(--muted)}.kv b{font-weight:600;word-break:break-word}
.ctx-card ul{margin:10px 0 0;padding-left:18px;font-size:13px;color:var(--muted)}
.ctx-card ul li{margin:3px 0;word-break:break-all}
.ctx-card code{font-size:12px}
.supp{margin-top:12px;font-size:13px;color:var(--muted)}
@media (max-width:640px){.autonote{grid-column:1}}
"""


def _kv(rows):
    e = html.escape
    return '<div class="kv">' + "".join(f"<span>{e(str(k))}</span><b>{e(str(v))}</b>" for k, v in rows if v not in (None, "")) + "</div>"


def render_report(outdir, lang=None):
    with open(os.path.join(outdir, "findings.json"), encoding="utf-8") as f:
        data = json.load(f)
    review = {}
    rp = os.path.join(outdir, "review.json")
    if os.path.exists(rp):
        with open(rp, encoding="utf-8") as f:
            review = json.load(f)
    lang = lang or data.get("lang") or "id"
    T = lambda k, **kw: tr(lang, k, **kw)
    sevl, catl, stl = T("sev"), T("cat"), T("st_map")
    e = html.escape
    s = data["summary"]
    meta = data.get("target", {})
    raw_level = (review.get("verdict") or s["auto_level"]).upper().strip()
    canon = VERDICT_CANON.get(raw_level, raw_level)
    level_label = T("verdict").get(canon, raw_level)
    vclass = VERDICT_CLASS.get(raw_level, VERDICT_CLASS.get(canon, "v-check"))
    headline = T("headline").get(canon, "")
    fr = review.get("findings", {})
    reviewed = bool(review)
    name = meta.get("name") or "repository"
    summary_txt = review.get("summary") or T("auto_summary", score=s["risk_score"], n=len(data["findings"]))
    has_diff = bool(data.get("diff"))

    cards = []
    for f in data["findings"]:
        r = fr.get(f["id"], {})
        st = r.get("status") or "none"
        loc = f"{f['file'] or ''}{(':' + str(f['line'])) if f.get('line') else ''}"
        orig = f" · {T('was')} {sevl.get(f['original_severity'], '')}" if f.get("original_severity") else ""
        badges = ""
        if f.get("diff") == "new":
            badges += f'<span class="badge-x new">{T("b_new")}</span>'
        elif f.get("diff") == "existing":
            badges += f'<span class="badge-x">{T("b_old")}</span>'
        if f["context"] == "history":
            badges += f'<span class="badge-x hist">{e(catl["history"].upper())}</span>'
        if f["context"] == "dependency" or f.get("package"):
            badges += f'<span class="badge-x dep">{e((f.get("package") or "DEP"))}</span>'
        if f.get("tool"):
            badges += f'<span class="badge-x">{e(f["tool"])}</span>'
        rv = (f'<div class="rv"><b>{e(stl.get(st, st))}</b><span>{e(r.get("note", ""))}</span></div>' if r else "")
        an = f'<div class="autonote">{e(T("auto_note"))}: {e(f["auto_note"])}</div>' if f.get("auto_note") and lang == "id" else (
            f'<div class="autonote">{e(T("auto_note"))}: downgraded — no network send in the same file.</div>' if f.get("auto_note") else "")
        cards.append(
            f'<article class="card f st-{e(st)}{" is-new" if f.get("diff") == "new" else ""}" data-sev="{f["severity"]}">'
            f'<div class="id">{e(f["id"])}</div>'
            f'<div class="f-top"><span class="sev s-{f["severity"]}"><span class="dot d-{f["severity"]}"></span>{sevl[f["severity"]]}</span>'
            f'<span class="cat">{e(catl.get(f["category"], f["category"]))}</span>'
            f'{("<code class=loc>" + e(loc) + "</code>") if loc else ""}{badges}'
            f'{("<span class=ctx>DOCS/TEST" + e(orig) + "</span>") if f["context"] == "docs/test" else ""}</div>'
            f'<p>{e(desc_for(f, lang))}</p>'
            f'{("<pre>" + e(f["snippet"]) + "</pre>") if f["snippet"] else ""}{an}{rv}</article>')
    findings_html = "".join(cards) or f'<div class="card empty">{T("no_findings")}</div>'

    kpis = "".join(f'<div class="kpi"><small><span class="dot d-{k}"></span>{sevl[k]}</small><b>{s["by_severity"].get(k, 0)}</b></div>'
                   for k in ("critical", "high", "medium", "low"))
    cats = sorted(s["by_category"].items(), key=lambda x: -x[1])[:6]
    mx = max([c for _, c in cats] or [1])
    bars = "".join(f'<div class="bar"><span>{e(catl.get(k, k))}</span><div><i style="width:{max(6, round(v / mx * 100))}%"></i></div><b>{v}</b></div>'
                   for k, v in cats) or f'<div class="bar"><span>{T("no_findings")}</span><div></div><b>0</b></div>'

    recs = review.get("recommendations") or []
    rec_html = "".join(f'<article class="card rec"><div class="ic" aria-hidden="true">{"⚑↗✓✦⌕"[(i - 1) % 5]}</div><small>{i:02d} / {T("rec")}</small><p>{e(x)}</p></article>'
                       for i, x in enumerate(recs, 1))

    # kartu konteks
    ctx = []
    rep = data.get("reputation")
    if rep:
        if rep.get("status") == "ok":
            body = _kv([(T("rep_owner"), f"{rep.get('owner')} ({rep.get('owner_type')}, {T('owner_age')} {rep.get('owner_age_days')} {T('days')})"),
                        (T("rep_age"), f"{rep.get('repo_age_days')} {T('days')}"),
                        (T("rep_stars"), f"{rep.get('stars')} ★ · {rep.get('forks')} forks"),
                        (T("rep_fork"), rep.get("parent") if rep.get("is_fork") else ""),
                        (T("rep_license"), rep.get("license") or "—"),
                        (T("rep_push"), f"{rep.get('pushed_days_ago')} {T('days_ago')}")])
        else:
            body = f"<p class='supp'>{e(rep.get('status', ''))}</p>"
        ctx.append(f'<article class="card ctx-card"><small>GITHUB API</small><h3>{T("rep")}</h3>{body}</article>')
    d = data.get("diff")
    if d:
        files = "".join(f"<li><code>{e(c['status'])}</code> {e(c['path'])}</li>" for c in d.get("changed_files", [])[:12])
        more = f"<li>… +{d['changed_count'] - 12}</li>" if d.get("changed_count", 0) > 12 else ""
        ctx.append(f'<article class="card ctx-card"><small>GIT DIFF</small><h3>{T("diff")}</h3>'
                   + _kv([(T("diff_range"), f"{d['base']} ({d['base_commit'][:8]}) → {d['head']} ({d['head_commit'][:8]})"),
                          (T("diff_changed"), d.get("changed_count")), (T("diff_new"), d.get("new_findings")),
                          (T("diff_resolved"), d.get("resolved_findings"))])
                   + f"<ul>{files}{more}</ul></article>")
    dd = data.get("deep_deps")
    if dd:
        items = "".join(f"<li><code>{e(c['package'])}</code> — {c['findings']} · {e(', '.join(c['external_domains'][:3]))}</li>" for c in dd.get("checked", [])[:12])
        fails = "".join(f"<li><code>{e(c['package'])}</code> — {e(c['reason'])}</li>" for c in dd.get("failed", [])[:5])
        ctx.append(f'<article class="card ctx-card"><small>NPM · PYPI</small><h3>{T("deps")}</h3>'
                   + _kv([(T("deps_found"), dd.get("found")), (T("deps_checked"), len(dd.get("checked", []))), (T("deps_failed"), len(dd.get("failed", [])))])
                   + f"<ul>{items}{fails}</ul></article>")
    hi = data.get("history")
    if hi:
        ctx.append(f'<article class="card ctx-card"><small>GIT LOG</small><h3>{T("hist")}</h3>'
                   + (_kv([(T("hist_commits"), hi.get("commits_scanned")), (T("hist_findings"), hi.get("findings"))]) if "commits_scanned" in hi
                      else f"<p class='supp'>{e(hi.get('status', ''))}</p>") + "</article>")
    ex = data.get("external_tools")
    if ex:
        ctx.append(f'<article class="card ctx-card"><small>GITLEAKS · SEMGREP · OSV · YARA</small><h3>{T("ext")}</h3>' + _kv(list(ex.items())) + "</article>")
    ctx_html = (f'<section class="block"><div class="sec-head"><div><small>{T("ctx_small")}</small><h2>{T("ctx")}</h2></div></div>'
                f'<div class="ctx-grid">{"".join(ctx)}</div></section>') if ctx else ""

    doms = [d for d in data["domains"] if not d["allowlisted"]]
    dnote = review.get("domains", {})
    dom_rows = "".join(
        f'<tr><td><code>{e(d["domain"])}</code></td><td class="mono">{d["count"]}</td>'
        f'<td><small>{e(", ".join(d["examples"][:3]))}</small></td>'
        f'<td>{("<span class=tag>" + T("hidden") + "</span>") if d.get("hidden") else ""}{e(dnote.get(d["domain"], ""))}</td></tr>'
        for d in doms[:150])

    osv = data.get("osv") or {}
    osv_txt = str(osv.get("status", "-"))
    if lang == "en" and osv_txt.startswith("tidak dijalankan"):
        osv_txt = "not run (use --osv)"
    if osv.get("packages_checked"):
        osv_txt += f" · {osv['packages_checked']} pkg"
    kinds = " ".join(f"<b>{e(k.upper())}</b>" + ("<i></i>" if i < len(s["repo_kind"]) - 1 else "")
                     for i, k in enumerate(s["repo_kind"])) or "<b>—</b>"
    when = data.get("scanned_at", datetime.datetime.now().isoformat(timespec="seconds")).replace("T", " ")[:16]
    seg = (f'<button type="button" data-f="all" aria-pressed="true">{T("all")}</button>'
           + (f'<button type="button" data-f="new" aria-pressed="false">{T("new")}</button>' if has_diff else "")
           + "".join(f'<button type="button" data-f="{k}" aria-pressed="false"><span class="dot d-{k}"></span>{sevl[k].title()}</button>'
                     for k in ("critical", "high", "medium", "low"))
           + (f'<button type="button" data-f="confirmed" aria-pressed="false">{T("confirmed")}</button>' if reviewed else ""))
    supp = f'<p class="supp">{e(T("suppressed", n=s.get("suppressed", 0)))}</p>' if s.get("suppressed") else ""
    js = REPORT_JS.replace("(sev==='confirmed'&&el.classList.contains('st-confirmed'))",
                           "(sev==='confirmed'&&el.classList.contains('st-confirmed'))||(sev==='new'&&el.classList.contains('is-new'))")
    js = js.replace("' ditampilkan'", "' " + T("shown") + "'")
    commit_txt = meta.get('commit') or meta.get('sha256') or T("no_commit")

    doc = f"""<!DOCTYPE html>
<html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Repo Scan · {e(name)} · {e(level_label)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Inter:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{REPORT_CSS}{REPORT_CSS_EXTRA}</style></head>
<body class="{vclass}"><div class="wrap">
<header class="topbar">
  <div class="brand"><img class="brandlogo" alt="" src="data:image/png;base64,{LOGO_PNG_B64}"><b>repo<span>scan</span></b></div>
  <div class="top-meta"><small>v{VERSION} · {e(when)}</small><button class="btn" type="button" onclick="window.print()">{T("print")} <span aria-hidden="true">↗</span></button></div>
</header>
<main>
<section class="hero">
  <div class="copy">
    <div class="eyebrow"><i aria-hidden="true"></i>{T("eyebrow")}</div>
    <h1>{e(name)}<br><em>{e(headline)}</em></h1>
    <p class="lead">{e(summary_txt)}</p>
    <div class="meta">
      <div><span>{T("target")}</span><code>{e(meta.get('url') or meta.get('input', ''))}</code></div>
      <div><span>{T("commit")}</span><code>{e(commit_txt)}</code></div>
      <div><span>{T("status")}</span><code>{T('reviewed') if reviewed else T('auto')}</code></div>
    </div>
  </div>
  <div class="visual">
    <div class="glow" aria-hidden="true"></div>
    <div class="dash">
      <div class="dash-head"><div><small>{T("dash_small")}</small><b>{T("dash_title")}</b></div><span class="verdict-pill">{e(level_label)}</span></div>
      <div class="kpis">{kpis}</div>
      <div class="bars"><div class="bars-title">{T("by_cat")}<span>{len(data['findings'])} {T("total")}</span></div>{bars}</div>
    </div>
    <div class="float-stat"><span aria-hidden="true">✦</span><div><small>{T("risk")}</small><b>{s['risk_score']}</b></div></div>
    <div class="float-chip">✧ &nbsp;{T("chip")}</div>
  </div>
</section>
<section class="proof" aria-label="Inventory">
  <small>{T("repo_type")}</small>
  <div class="items">{kinds}</div>
  <div class="items"><b>{T("files")}<span>{s['files_scanned']}/{s['files_total']}</span></b><i></i><b>{T("ext_domains")}<span>{s['external_domains']}</span></b><i></i><b>OSV<span>{e(osv_txt)}</span></b></div>
</section>
{('<section class="block"><div class="sec-head"><div><small>' + T("next") + '</small><h2>' + T("recs") + '</h2></div></div><div class="recs">' + rec_html + '</div></section>') if rec_html else ''}
{ctx_html}
<section class="block">
  <div class="sec-head"><div><small>{T("detail")}</small><h2>{T("findings")}</h2></div><small class="mono" id="count"></small></div>
  <div class="toolbar">
    <div class="seg" role="group" aria-label="Filter">{seg}</div>
    <input class="input" id="search" type="search" placeholder="{e(T('search'))}" aria-label="{e(T('search'))}">
    {('<label class="check"><input type="checkbox" id="hidefp"> ' + T("hide_fp") + '</label>') if reviewed else ''}
  </div>
  <div class="findings">{findings_html}<div class="card empty" id="none" hidden>{T("no_match")}</div></div>
  {supp}
</section>
<section class="block">
  <div class="sec-head"><div><small>{T("net")}</small><h2>{T("domains")}</h2></div><small class="mono">{len(doms)} {T("outside")}</small></div>
  <div class="card" style="overflow-x:auto"><table><thead><tr><th>{T("c_domain")}</th><th>{T("c_count")}</th><th>{T("c_loc")}</th><th>{T("c_note")}</th></tr></thead>
  <tbody>{dom_rows or '<tr><td colspan="4" class="empty">' + T("no_domains") + '</td></tr>'}</tbody></table></div>
</section>
<section class="block">
  <div class="card note"><div class="ic" aria-hidden="true">i</div>
  <p><b>{T("limits_b")}</b> {T("limits")}
  {T('skipped', n=len(data.get('skipped', []))) if data.get('skipped') else ''}</p></div>
</section>
</main>
<footer><div class="brand"><img class="brandlogo" alt="" src="data:image/png;base64,{LOGO_PNG_B64}"><b>repo<span>scan</span></b></div>
<span>{T("footer")}</span><span>REPO SCAN v{VERSION}</span></footer>
</div><script>{js}</script></body></html>"""
    write_markdown(outdir, data, review, level_label, lang)
    out = os.path.join(outdir, "report.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(doc)
    return out


def write_markdown(outdir, data, review, level, lang="id"):
    T = lambda k, **kw: tr(lang, k, **kw)
    sevl, stl = T("sev"), T("st_map")
    s = data["summary"]; t = data.get("target", {}); fr = review.get("findings", {})
    L = [f"# Repo Scan — {t.get('name','')}", "", f"**{T('md_verdict')}: {level}**", "",
         review.get("summary") or T("auto_summary", score=s["risk_score"], n=len(data["findings"])), "",
         f"- {T('target')}: {t.get('url') or t.get('input','')}", f"- {T('commit')}: `{t.get('commit') or t.get('sha256') or '-'}`",
         f"- {T('md_kind')}: {', '.join(s['repo_kind']) or '-'}", f"- {T('md_files')}: {s['files_scanned']} / {s['files_total']}",
         f"- {T('md_findings')}: " + (", ".join(f"{sevl[k]} {v}" for k, v in s["by_severity"].items() if v) or "0")]
    if data.get("diff"):
        d = data["diff"]
        L.append(f"- {T('diff')}: {d['base']} → {d['head']} · {T('diff_changed')} {d['changed_count']} · {T('diff_new')} {d['new_findings']} · {T('diff_resolved')} {d['resolved_findings']}")
    if (data.get("reputation") or {}).get("status") == "ok":
        r = data["reputation"]
        L.append(f"- {T('rep')}: {r.get('owner')} ({T('owner_age')} {r.get('owner_age_days')} {T('days')}), {r.get('stars')}★, {T('rep_age')} {r.get('repo_age_days')} {T('days')}")
    if data.get("deep_deps"):
        L.append(f"- {T('deps')}: {len(data['deep_deps'].get('checked', []))}/{data['deep_deps'].get('found')}")
    if s.get("suppressed"):
        L.append(f"- {T('suppressed', n=s['suppressed'])}")
    L.append("")
    if review.get("recommendations"):
        L += [f"## {T('recs')}", ""] + [f"- {x}" for x in review["recommendations"]] + [""]
    L += [f"## {T('findings')}", "", f"| ID | {T('md_level')} | {T('md_loc')} | {T('md_desc')} | {T('md_review')} |", "|---|---|---|---|---|"]
    for f in data["findings"]:
        r = fr.get(f["id"], {})
        loc = f"{f['file'] or ''}{':' + str(f['line']) if f.get('line') else ''}"
        rv = (stl.get(r.get("status"), r.get("status", "")) + (": " + r.get("note", "") if r.get("note") else "")) if r else ""
        tag = f" **{T('b_new')}**" if f.get("diff") == "new" else ""
        L.append(f"| {f['id']}{tag} | {sevl[f['severity']]} | `{loc}` | {desc_for(f, lang)} `{f['snippet'][:90].replace('|','/').replace('`','')}` | {rv.replace('|','/')} |")
    doms = [d for d in data["domains"] if not d["allowlisted"]]
    if doms:
        L += ["", f"## {T('domains')}", ""] + [f"- `{d['domain']}` ({d['count']}x){' — ' + T('hidden') if d.get('hidden') else ''} {review.get('domains', {}).get(d['domain'], '')}" for d in doms[:100]]
    L += ["", f"> {T('md_limits')}", ""]
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Repo Scan — pemindai keamanan statis / static security scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("scan", help="pindai repo / scan a repository")
    a.add_argument("target", help="URL GitHub/GitLab/Bitbucket, folder lokal, atau .zip/.skill/.plugin")
    a.add_argument("--out", required=True, help="folder hasil")
    a.add_argument("--osv", action="store_true", help="cek dependensi ke database OSV (celah & malware; butuh internet)")
    a.add_argument("--deep-deps", nargs="?", const=25, type=int, metavar="N",
                   help="unduh N dependensi langsung (npm/PyPI) sebagai file — TANPA install — lalu pindai isinya (default 25)")
    a.add_argument("--reputation", action="store_true", help="cek reputasi repo & akun pemilik lewat GitHub API")
    a.add_argument("--history", type=int, metavar="N", help="pindai N commit terakhir untuk rahasia/payload yang pernah ada lalu dihapus")
    a.add_argument("--diff", metavar="BASE[..HEAD]", help="bandingkan dua versi (tag/branch/commit); tandai temuan BARU")
    a.add_argument("--only-new", action="store_true", help="dengan --diff: sembunyikan temuan yang sudah ada di versi BASE")
    a.add_argument("--external", action="store_true", help="jalankan gitleaks/trufflehog/semgrep/osv-scanner bila terpasang")
    a.add_argument("--yara-rules", metavar="PATH", help="file/folder aturan YARA (butuh yara terpasang)")
    a.add_argument("--ignore", metavar="FILE", help="file daftar temuan yang diabaikan (milik ANDA, bukan dari repo yang dipindai)")
    a.add_argument("--baseline", metavar="FINDINGS_JSON", help="findings.json scan sebelumnya; hanya tampilkan temuan baru")
    a.add_argument("--all", action="store_true", help="aktifkan --osv --deep-deps --reputation --history 50 --external sekaligus")
    a.add_argument("--lang", choices=["id", "en"], default="id", help="bahasa laporan (default id)")
    a.add_argument("--rules", help="file JSON aturan tambahan: [[id, kategori, severity, regex, deskripsi], ...]")
    a.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], help="exit code 2 bila ada temuan >= tingkat ini (untuk CI)")
    a.add_argument("--cleanup", action="store_true", help="hapus salinan repo sementara setelah scan")
    b = sub.add_parser("report", help="buat ulang laporan (pakai review.json bila ada)")
    b.add_argument("out")
    b.add_argument("--lang", choices=["id", "en"])
    args = ap.parse_args()

    if args.cmd == "report":
        print(render_report(args.out, lang=args.lang))
        return
    if args.all:
        args.osv = True
        args.reputation = True
        args.external = True
        args.deep_deps = args.deep_deps or 25
        args.history = args.history or 50

    os.makedirs(args.out, exist_ok=True)
    extra = None
    if args.rules:
        with open(args.rules, encoding="utf-8") as f:
            extra = [tuple(x) for x in json.load(f)]
    rules_compiled = [(rid, cat, sev, re.compile(pat, re.I) if pat else None, desc) for rid, cat, sev, pat, desc in list(RULES) + list(extra or [])]
    ignore_rules = load_ignore(args.ignore)
    baseline = None
    if args.baseline:
        bj = json.load(open(args.baseline, encoding="utf-8"))
        baseline = {f.get("fingerprint") or fingerprint(f) for f in bj.get("findings", []) + bj.get("suppressed", [])}

    work = tempfile.mkdtemp(prefix="reposcan_")
    try:
        depth = None if args.diff else (args.history + 1 if args.history else 1)
        meta = fetch_target(args.target, work, depth=depth)
        root = meta["path"]
        subpath = meta.get("subpath")
        repo_git = meta.get("git_dir")
        diff_info, base_fps = None, None
        meta["name"] = meta.get("repo") or os.path.basename((os.path.join(root, subpath) if subpath else root).rstrip("/"))

        if args.diff:
            if not repo_git:
                raise SystemExit("[DIFF] --diff butuh target git (URL repo atau folder yang berisi .git)")
            base, _, head = args.diff.partition("..")
            base_sha, head_sha = resolve_ref(repo_git, base), resolve_ref(repo_git, head or "HEAD")
            new_dir = export_ref(repo_git, head_sha, os.path.join(work, "head"))
            old_dir = export_ref(repo_git, base_sha, os.path.join(work, "base"))
            old_res = finalize(Scanner(os.path.join(old_dir, subpath) if subpath else old_dir, extra).run())
            base_fps = {f["fingerprint"] for f in old_res["findings"] + old_res["suppressed"]}
            changes = changed_files(repo_git, base_sha, head_sha)
            if subpath:
                changes = [c for c in changes if c["path"].startswith(subpath.rstrip("/") + "/")]
            diff_info = {"base": base, "base_commit": base_sha, "head": head or "HEAD", "head_commit": head_sha,
                         "changed_files": changes[:2000], "changed_count": len(changes)}
            root = new_dir
            meta["commit"] = head_sha
        if subpath:
            root = os.path.join(root, subpath)

        res = Scanner(root, extra, use_osv=args.osv).run()

        if args.history:
            if repo_git:
                hf, ncommits = scan_history(repo_git, args.history, rules_compiled)
                res["findings"] += hf
                res["history"] = {"commits_scanned": ncommits, "findings": len(hf)}
            else:
                res["history"] = {"status": "dilewati: target bukan repo git"}
        if args.deep_deps:
            df, dinfo = scan_dependencies(root, os.path.join(work, "deps"), args.deep_deps, extra)
            res["findings"] += df
            res["deep_deps"] = dinfo
        if args.external or args.yara_rules:
            ef, est = run_external(root, work, args.yara_rules)
            res["findings"] += ef
            res["external_tools"] = est
        if args.reputation:
            if meta.get("host") == "github.com":
                rinfo, rf = check_reputation(meta["owner"], meta["repo"])
                res["findings"] += rf
                res["reputation"] = rinfo
            else:
                res["reputation"] = {"status": "dilewati: hanya untuk URL github.com"}
        if meta.get("has_submodules"):
            res["findings"].append(make_finding("GIT_SUBMODULES", "dependency", "low", ".gitmodules", None, "",
                                                "Repo memakai submodule — isinya TIDAK ikut dipindai; scan terpisah bila perlu."))

        finalize(res, ignore_rules, baseline=(base_fps if args.only_new else None) or baseline)
        if diff_info is not None:
            for f in res["findings"]:
                f["diff"] = "existing" if f["fingerprint"] in base_fps else "new"
            new_fps = {f["fingerprint"] for f in res["findings"] + res["suppressed"]}
            diff_info["new_findings"] = sum(1 for f in res["findings"] if f.get("diff") == "new")
            diff_info["resolved_findings"] = len(base_fps - new_fps)
            res["diff"] = diff_info
            res["summary"]["new_findings"] = diff_info["new_findings"]

        for k in ("path", "git_dir"):
            meta.pop(k, None)
        res["target"] = meta
        res["lang"] = args.lang
        res["scanned_at"] = datetime.datetime.now().isoformat(timespec="seconds")
        res["options"] = {k: getattr(args, k) for k in ("osv", "deep_deps", "reputation", "history", "diff", "external", "only_new")}
        if meta.get("source") in ("git", "zip") or args.diff:
            if not args.cleanup:
                res["target"]["source_path"] = root  # salinan sementara untuk ditinjau; hapus setelah selesai
        with open(os.path.join(args.out, "findings.json"), "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=1)
        rpt = render_report(args.out)
        s = res["summary"]
        print(json.dumps({"auto_level": s["auto_level"], "risk_score": s["risk_score"], "by_severity": s["by_severity"],
                          "by_category": s["by_category"], "repo_kind": s["repo_kind"], "files_scanned": s["files_scanned"],
                          "external_domains": s["external_domains"], "suppressed": s["suppressed"],
                          "new_findings": s.get("new_findings"), "commit": meta.get("commit"),
                          "source_path": res["target"].get("source_path") or res["target"].get("input"),
                          "osv": res.get("osv"), "deep_deps": {k: v for k, v in (res.get("deep_deps") or {}).items() if k != "checked"} or None,
                          "reputation": (res.get("reputation") or {}).get("status"), "history": res.get("history"),
                          "external_tools": res.get("external_tools"),
                          "findings_json": os.path.join(args.out, "findings.json"), "report": rpt,
                          "report_md": os.path.join(args.out, "report.md")}, ensure_ascii=False, indent=1))
        if args.cleanup:
            shutil.rmtree(work, ignore_errors=True)
        if args.fail_on and any(SEV_ORDER[f["severity"]] >= SEV_ORDER[args.fail_on] for f in res["findings"]):
            sys.exit(2)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise


if __name__ == "__main__":
    main()
