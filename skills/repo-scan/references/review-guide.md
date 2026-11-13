# Repo Scan — Review Guide

How to judge each scanner rule. "FP" = typical false positive.

## network
| Rule | Dangerous when | Typical FP |
|---|---|---|
| NET_DOWNLOAD_EXEC | Runs automatically (install script, hook, postinstall) or fetches from an unknown/raw-IP host | Official installer one-liners in README (e.g. rustup, brew) shown for the user to run themselves |
| NET_REVERSE_SHELL | Almost always malicious outside security-tool repos | Pentest/CTF repos that say so openly |
| NET_EXFIL_SERVICE | Sending env, files, tokens, system info to Discord/Telegram webhooks or request catchers | Notification bots whose purpose is posting to the user's own channel, with the webhook supplied by the user via config |
| NET_PASTE_FILEHOST / NET_TUNNEL | Fetching payloads or uploading data | Dev tooling docs |
| NET_RAW_IP | Hardcoded public IPs in code that runs | Test fixtures, SSRF-protection tests, `169.254.169.254` in cloud SDKs (but reading metadata in a desktop tool is suspicious) |

## obfuscation
- OBF_DECODE_EXEC: decode-then-execute is the #1 malware pattern. Decode the blob yourself (in
  Python, as data only — never execute) and report what it contains.
- OBF_LONG_ENCODED / OBF_HEX_BLOB: decode and inspect; embedded fonts/images/certs are FP.
- UNICODE_BIDI: confirmed unless it is in a translation/RTL-language string file.
- UNICODE_ZERO_WIDTH: often harmless in emoji/text; suspicious inside code identifiers or prompts.
- MINIFIED_CODE: a committed minified file whose source isn't in the repo cannot be reviewed —
  mark `needs_check` unless it is a known vendored library (check header/license comment).

## credentials
- CRED_BROWSER / CRED_WALLET: confirmed unless the repo openly is a browser/wallet tool and the data
  never leaves the machine.
- CRED_SSH_CLOUD / CRED_PKG_CONFIG / CRED_KEYCHAIN: check if the file is actually read and where
  its contents go. Comments mentioning paths are FP.
- CRED_ENV_DUMP: dangerous when the full environment is serialized and sent over the network or
  written to a shared place. Passing env to a child process is FP.
- CRED_SPY: keyloggers/screenshot/clipboard readers — confirm purpose matches the README.

- CRED_DOTENV_HUNT: searching for `.env` files across home/other folders is credential hunting →
  confirmed unless the tool's documented purpose is local secret scanning and nothing is sent out.
- CRED_DOTENV_READ: an app loading its own `.env` is normal; check where values go.

## persistence / destructive
- RANSOM_NOTE: confirmed unless the repo is clearly an educational/security sample that says so.
- RANSOMWARE_PATTERN: walk + encrypt + delete/rename in one file. Backup/encryption tools can match;
  check whether originals are destroyed and whether paths are user-chosen or the whole disk/home.
- PERSIST_*: unexpected for skills/plugins/libraries; acceptable only for daemons/installers that
  document it.
- DESTRUCT_WIPE: confirmed unless clearly inside a sandbox/temp dir variable.
- DESTRUCT_DISABLE_SEC: confirmed unless docs for a tool that explicitly explains why.
- PRIV_ESCALATE (sudo) in CI workflows or docs is FP.

## obfuscation (extra)
- OBF_HIDDEN_PAYLOAD: the scanner already decoded the base64/hex string; the decoded URL/command is in
  the snippet. A hidden URL in code that runs is a strong red flag — confirmed unless it's a test vector.
- OBF_REVERSED_URL: reversed strings to hide URLs/commands are rarely legitimate.

## AI-specific (skills, plugins, MCP)
- AI_WIDE_PERMISSIONS: unrestricted Bash/`*` allow-lists, Codex `approval_policy="never"` /
  `danger-full-access`, Gemini yolo. Suspicious in anything shipped for others to install.
- AI_HIDDEN_TAG_CHARS: invisible text — always confirmed malicious; quote the decoded hidden text.
- AI_HIDDEN_COMMENT: HTML comments in markdown are invisible to humans but read by AI. Confirmed when
  they contain instructions to the model; FP when they are template notes for maintainers.
- AI_PROMPT_INJECTION / AI_HIDE_FROM_USER / AI_EXFIL_INSTRUCTION: read the surrounding paragraph.
  FP when the text documents/warns about the attack, or is general advice ("do not tell the user
  they need to..."). Confirmed when it instructs the model to act against the user.
- PLUGIN_HOOK: hooks run shell commands automatically (SessionStart, PreToolUse...). Read the script
  it calls. Any network call, file upload, or download-and-run in a hook → confirmed/suspicious.
  `.claude/settings.json` hooks in a repo run when the user opens the project in Claude Code.
- MCP_REMOTE: a remote MCP server sees every request the tools make. Who runs the domain?
- MCP_LOCAL_COMMAND: `npx -y pkg` without a version pin pulls whatever is published at run time —
  supply-chain risk. Note the package name for the user to verify.
- AI_BYPASS_PERMISSIONS: suspicious in anything meant for others to install.
- Also check: does the skill/plugin `description` match what the body actually does? A "text
  formatter" skill that reads files or calls URLs is a red flag.

## install / dependency / CI
- INSTALL_SCRIPT: postinstall that downloads, runs node -e, or touches the home directory → high.
  Builds (tsc, node-gyp) → benign.
- DEP_TYPOSQUAT: compare carefully (axois vs axios, reqeusts vs requests). Confirmed if the
  real package is clearly intended.
- DEP_REMOTE_SOURCE: dependency from a git URL/personal fork — suspicious if the fork is
  unrelated to the author.
- CI_PR_TARGET / CI_INJECTION: risk to the repo's maintainers, not to someone installing it. Report
  as low relevance for end users.
- SECRET_KEY: leaked keys mean careless maintenance, not danger to the user (unless the key is used
  to receive exfiltrated data).

- DEP_CUSTOM_REGISTRY: `.npmrc`/pip config pointing to a non-official registry → every dependency can
  be swapped. Confirmed unless it is a documented company-internal registry.
- DEP_KNOWN_MALICIOUS (OSV `MAL-`): confirmed — the package is known malware.
- DEP_KNOWN_VULN: known CVEs in pinned versions; risk depends on usage. Recommend upgrading.
- MAKEFILE_NETWORK / PY_CUSTOM_BACKEND / PY_BUILD_HOOK / BUILD_SCRIPT / DOCKER_REMOTE_ADD: code that runs
  during build/install — read it like a postinstall script.
- DOCKER_PRIVILEGED / DOCKER_HOST_MOUNT: a container with host access is not isolated; high risk if the
  image is from an unknown source.

## dataflow
- DATAFLOW_EXFIL: a credential/secret source and a network sink in the same file. Trace the variable
  from the read to the send. Confirmed when user data (keys, env, files, browser data) is sent to a
  host the user did not configure. Benign when the tool's documented job is to call that API with the
  user's own token (e.g. an SDK sending its API key to its own service).
- Credential findings without any network send in the same file are auto-downgraded (see `auto_note`);
  still check whether another file imports the value and sends it.

## reputation (`--reputation`)
- REP_NEW_OWNER / REP_NEW_REPO / REP_STAR_SPIKE: context, not proof. Combined with any code finding
  they raise the verdict a level. Alone they justify WASPADA at most.
- REP_FORK_OF_POPULAR: compare with the parent repo — if the fork only adds an install script,
  binary or new domain, treat as confirmed malicious.

## history (`--history`)
- HIST_REMOVED_SECRET: the secret is still public in git history — tell the user it must be revoked;
  it is a maintainer hygiene problem, not a danger to the installer.
- HIST_REMOVED_DANGEROUS: a payload that was added then removed (sometimes after a takeover). Note the
  commit, author and date; check whether the current version re-introduces it elsewhere.

## dependencies scanned (`--deep-deps`)
- Findings under `deps/...` come from the package as published on npm/PyPI. Popular packages often
  have low/medium noise (dynamic `Function`, build scripts). Focus on INSTALL_SCRIPT (`preinstall`,
  `install`, `postinstall` run on install; `prepare` does not for registry installs), DATAFLOW_EXFIL,
  OBF_DECODE_EXEC, NET_* and new domains.

## external tools (`--external`)
- EXT_GITLEAKS / EXT_TRUFFLEHOG: secrets (secret values are redacted). EXT_SEMGREP: code-quality
  security issues — mostly risk to the repo's own users, rarely malice. EXT_OSV_SCANNER: like OSV.
  EXT_YARA: matched a malware signature from the user's rule set — treat as high until disproven.

## scanner evasion
- SCANNER_EVASION / AI_SCANNER_MANIPULATION: a repo shipping a Repo Scan config, or text asking
  scanners/AIs to skip checks, is itself a strong red flag → confirmed unless clearly a joke/test.

## binary
- BINARY_DISGUISED: executable with a fake extension → confirmed.
- BINARY_EXECUTABLE / BINARY_ARCHIVE: cannot be reviewed. `needs_check`; recommend building from
  source or obtaining from an official release with checksums. Unexpected in a skill/plugin.
- SYMLINK_ESCAPE: confirmed unless pointing to a well-known system path for documented reasons.

## Writing notes
Each note: what the code does, evidence (file:line, decoded content, destination), and impact on
the user. Keep notes short and in the user's language.
