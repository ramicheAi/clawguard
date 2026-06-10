"""
ClawGuard — malicious-pattern corpus.

A real, categorized library of detection signatures for auditing OpenClaw /
ClawHub skills and agent code. Every entry is a genuine indicator — secret
formats (modeled on widely-used secret-scanning rulesets), dangerous shell
commands, remote code-execution, obfuscation, reverse shells, data
exfiltration, prompt injection, crypto-mining, persistence, and known-malware
strings. No padding: `count()` returns the true number.

Each pattern: (category, severity, id, regex, description).
"""

from __future__ import annotations

import re
from typing import Dict, List

# (category, severity, id, regex, description)
_RAW = [
    # ── Secrets / credentials ───────────────────────────────────────────────
    ("secret", "critical", "aws-access-key-id", r"\bAKIA[0-9A-Z]{16}\b", "AWS access key ID"),
    ("secret", "critical", "aws-secret-access-key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}", "AWS secret access key"),
    ("secret", "critical", "aws-session-token", r"\bASIA[0-9A-Z]{16}\b", "AWS temporary session key"),
    ("secret", "critical", "aws-mws-token", r"amzn\.mws\.[0-9a-f-]{36}", "Amazon MWS auth token"),
    ("secret", "critical", "github-pat", r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token"),
    ("secret", "critical", "github-oauth", r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth token"),
    ("secret", "critical", "github-app", r"\bgh[su]_[A-Za-z0-9]{36}\b", "GitHub app/server token"),
    ("secret", "critical", "github-refresh", r"\bghr_[A-Za-z0-9]{36,}\b", "GitHub refresh token"),
    ("secret", "critical", "github-fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "GitHub fine-grained PAT"),
    ("secret", "critical", "gitlab-pat", r"\bglpat-[A-Za-z0-9_-]{20}\b", "GitLab personal access token"),
    ("secret", "critical", "slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    ("secret", "critical", "slack-app-token", r"\bxapp-\d-[A-Za-z0-9-]+\b", "Slack app-level token"),
    ("secret", "high", "slack-webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+", "Slack incoming webhook"),
    ("secret", "critical", "stripe-secret", r"\b[sr]k_live_[A-Za-z0-9]{24,}\b", "Stripe live secret key"),
    ("secret", "high", "stripe-restricted", r"\brk_live_[A-Za-z0-9]{24,}\b", "Stripe restricted key"),
    ("secret", "critical", "google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key"),
    ("secret", "critical", "google-oauth-id", r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth client ID"),
    ("secret", "critical", "gcp-service-account", r"\"type\":\s*\"service_account\"", "GCP service-account JSON"),
    ("secret", "critical", "google-oauth-secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", "Google OAuth client secret"),
    ("secret", "critical", "twilio-sid", r"\bAC[0-9a-fA-F]{32}\b", "Twilio account SID"),
    ("secret", "critical", "twilio-api-key", r"\bSK[0-9a-fA-F]{32}\b", "Twilio API key"),
    ("secret", "critical", "sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "SendGrid API key"),
    ("secret", "high", "mailgun-key", r"\bkey-[0-9a-f]{32}\b", "Mailgun API key"),
    ("secret", "high", "mailchimp-key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", "Mailchimp API key"),
    ("secret", "critical", "npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", "npm access token"),
    ("secret", "critical", "pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", "PyPI upload token"),
    ("secret", "critical", "openai-key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "OpenAI API key"),
    ("secret", "critical", "openai-proj-key", r"\bsk-proj-[A-Za-z0-9_-]{40,}\b", "OpenAI project key"),
    ("secret", "critical", "anthropic-key", r"\bsk-ant-[A-Za-z0-9-]{90,}\b", "Anthropic API key"),
    ("secret", "high", "huggingface-token", r"\bhf_[A-Za-z0-9]{34}\b", "Hugging Face token"),
    ("secret", "critical", "cloudflare-api-token", r"(?i)cloudflare.{0,20}\b[A-Za-z0-9_-]{40}\b", "Cloudflare API token"),
    ("secret", "critical", "digitalocean-token", r"\bdop_v1_[0-9a-f]{64}\b", "DigitalOcean PAT"),
    ("secret", "critical", "heroku-key", r"(?i)heroku.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "Heroku API key"),
    ("secret", "high", "datadog-key", r"(?i)dd[_-]?api[_-]?key\s*[=:]\s*['\"]?[0-9a-f]{32}", "Datadog API key"),
    ("secret", "high", "newrelic-key", r"\bNRAK-[A-Z0-9]{27}\b", "New Relic API key"),
    ("secret", "high", "pagerduty-key", r"\b[yu]_[A-Za-z0-9_-]{20}\b", "PagerDuty API token"),
    ("secret", "critical", "shopify-token", r"\bshp(at|ss|pa|ca)_[0-9a-fA-F]{32}\b", "Shopify access token"),
    ("secret", "critical", "square-token", r"\b(EAAA|sq0atp-)[A-Za-z0-9_-]{22,}\b", "Square access token"),
    ("secret", "critical", "paypal-braintree", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "Braintree/PayPal token"),
    ("secret", "critical", "discord-bot-token", r"\b[MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b", "Discord bot token"),
    ("secret", "high", "discord-webhook", r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "Discord webhook"),
    ("secret", "critical", "telegram-bot-token", r"\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b", "Telegram bot token"),
    ("secret", "high", "twitter-bearer", r"\bAAAAAAAAAA[A-Za-z0-9%]{50,}\b", "Twitter/X bearer token"),
    ("secret", "high", "facebook-token", r"\bEAACEdEose0cBA[A-Za-z0-9]+\b", "Facebook access token"),
    ("secret", "high", "dropbox-token", r"\bsl\.[A-Za-z0-9_-]{130,}\b", "Dropbox API token"),
    ("secret", "critical", "notion-token", r"\b(secret_|ntn_)[A-Za-z0-9]{40,}\b", "Notion integration token"),
    ("secret", "high", "airtable-key", r"\bkey[A-Za-z0-9]{14}\b", "Airtable API key"),
    ("secret", "high", "algolia-admin-key", r"(?i)algolia.{0,20}\b[A-Za-z0-9]{32}\b", "Algolia admin key"),
    ("secret", "high", "sentry-dsn", r"https://[0-9a-f]{32}@[0-9a-z.-]+/[0-9]+", "Sentry DSN with secret"),
    ("secret", "high", "segment-key", r"(?i)segment.{0,15}write[_-]?key\s*[=:]\s*['\"]?[A-Za-z0-9]{32}", "Segment write key"),
    ("secret", "high", "intercom-token", r"\bdG9rOj[A-Za-z0-9_-]{50,}\b", "Intercom access token"),
    ("secret", "high", "postmark-token", r"(?i)postmark.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "Postmark server token"),
    ("secret", "critical", "firebase-key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b", "Firebase cloud-messaging key"),
    ("secret", "critical", "mongodb-uri", r"mongodb(\+srv)?://[^\s:@]+:[^\s:@]+@[^\s/]+", "MongoDB URI with credentials"),
    ("secret", "critical", "postgres-uri", r"postgres(ql)?://[^\s:@]+:[^\s:@]+@[^\s/]+", "Postgres URI with credentials"),
    ("secret", "critical", "mysql-uri", r"mysql://[^\s:@]+:[^\s:@]+@[^\s/]+", "MySQL URI with credentials"),
    ("secret", "high", "redis-uri", r"redis://[^\s:@]*:[^\s:@]+@[^\s/]+", "Redis URI with password"),
    ("secret", "high", "amqp-uri", r"amqps?://[^\s:@]+:[^\s:@]+@[^\s/]+", "AMQP URI with credentials"),
    ("secret", "critical", "jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JSON Web Token"),
    ("secret", "critical", "rsa-private-key", r"-----BEGIN RSA PRIVATE KEY-----", "RSA private key"),
    ("secret", "critical", "ec-private-key", r"-----BEGIN EC PRIVATE KEY-----", "EC private key"),
    ("secret", "critical", "openssh-private-key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
    ("secret", "critical", "pgp-private-key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key"),
    ("secret", "critical", "generic-private-key", r"-----BEGIN (DSA|ENCRYPTED) PRIVATE KEY-----", "Private key block"),
    ("secret", "high", "azure-storage-key", r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{86}==", "Azure Storage account key"),
    ("secret", "high", "azure-sas", r"(?i)sig=[A-Za-z0-9%]{40,}&", "Azure SAS signature"),
    ("secret", "high", "okta-token", r"\b00[A-Za-z0-9_-]{40}\b", "Okta API token"),
    ("secret", "high", "vault-token", r"\b[sb]\.[A-Za-z0-9]{24}\b", "HashiCorp Vault token"),
    ("secret", "high", "docker-auth", r"\"auth\":\s*\"[A-Za-z0-9+/]{20,}={0,2}\"", "Docker registry auth"),
    ("secret", "high", "linkedin-secret", r"(?i)linkedin.{0,20}\b[A-Za-z0-9]{16}\b", "LinkedIn client secret"),
    ("secret", "high", "asana-token", r"\b[0-9]/[0-9]{16}:[0-9a-f]{32}\b", "Asana PAT"),
    ("secret", "high", "atlassian-token", r"\bATATT3[A-Za-z0-9_-]{180,}\b", "Atlassian API token"),
    ("secret", "high", "linear-key", r"\blin_api_[A-Za-z0-9]{40}\b", "Linear API key"),
    ("secret", "high", "circleci-token", r"(?i)circle.{0,15}\b[0-9a-f]{40}\b", "CircleCI API token"),
    ("secret", "high", "grafana-token", r"\beyJrIjoi[A-Za-z0-9_-]{40,}\b", "Grafana API token"),
    ("secret", "high", "generic-api-key", r"(?i)(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*['\"][A-Za-z0-9/+_-]{16,}['\"]", "Generic hardcoded secret"),
    ("secret", "medium", "basic-auth-url", r"https?://[^\s:@/]+:[^\s:@/]+@", "Credentials embedded in URL"),

    # ── Dangerous shell commands ────────────────────────────────────────────
    ("command", "critical", "rm-rf-root", r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|/\*|\$HOME|~|/\*)\s*($|;)", "Recursive delete of root/home"),
    ("command", "critical", "rm-rf-no-preserve", r"\brm\s+-rf\s+--no-preserve-root", "rm -rf --no-preserve-root"),
    ("command", "critical", "fork-bomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Bash fork bomb"),
    ("command", "critical", "dd-to-disk", r"\bdd\s+if=.*\s+of=/dev/(sd|disk|nvme|rdisk)", "dd overwrite of block device"),
    ("command", "critical", "mkfs", r"\bmkfs(\.[a-z0-9]+)?\s+/dev/", "Format a filesystem"),
    ("command", "critical", "overwrite-disk", r">\s*/dev/(sd[a-z]|disk[0-9]|nvme)", "Write to raw disk device"),
    ("command", "high", "chmod-777", r"\bchmod\s+(-R\s+)?0?777\b", "World-writable permissions"),
    ("command", "high", "chmod-suid", r"\bchmod\s+[ug]\+s\b", "Set SUID/SGID bit"),
    ("command", "high", "chown-root", r"\bchown\s+(-R\s+)?root\b", "Change ownership to root"),
    ("command", "high", "history-clear", r"\bhistory\s+-c\b|>\s*~?/?\.(bash|zsh)_history", "Clear shell history (anti-forensics)"),
    ("command", "high", "kill-all", r"\bkill\s+-9\s+-1\b|\bkillall5\b", "Kill all processes"),
    ("command", "high", "disable-firewall", r"(?i)(ufw\s+disable|iptables\s+-F|pfctl\s+-d|systemctl\s+stop\s+firewalld)", "Disable firewall"),
    ("command", "high", "sudoers-edit", r">>\s*/etc/sudoers|tee\s+-a\s+/etc/sudoers", "Modify sudoers file"),
    ("command", "high", "passwd-edit", r">>\s*/etc/passwd|>>\s*/etc/shadow", "Modify passwd/shadow"),
    ("command", "high", "etc-hosts-edit", r">>\s*/etc/hosts", "Modify /etc/hosts (hijack)"),
    ("command", "medium", "disable-sip", r"\bcsrutil\s+disable", "Disable macOS System Integrity Protection"),
    ("command", "medium", "disable-gatekeeper", r"\bspctl\s+--master-disable", "Disable macOS Gatekeeper"),

    # ── Remote code execution / supply chain ────────────────────────────────
    ("rce", "critical", "curl-pipe-bash", r"\bcurl\s+[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b", "curl | bash remote execution"),
    ("rce", "critical", "wget-pipe-sh", r"\bwget\s+[^|]*\|\s*(sudo\s+)?(bash|sh)\b", "wget | sh remote execution"),
    ("rce", "critical", "fetch-pipe-sh", r"\b(fetch|curl)\b.*\|\s*sh\s+-s\b", "pipe-to-shell installer"),
    ("rce", "critical", "eval-curl", r"eval\s*\(\s*[`$]\(\s*curl", "eval of curl output"),
    ("rce", "high", "python-urlopen-exec", r"(urllib\.request\.urlopen|requests\.get)\([^)]*\)\.(read|text|content)[^;\n]*exec", "Download+exec in Python"),
    ("rce", "high", "node-eval-fetch", r"eval\s*\(\s*await\s+fetch", "eval of fetched JS"),
    ("rce", "high", "powershell-iex-web", r"(?i)(iex|invoke-expression)\s*\(\s*.*(downloadstring|invoke-webrequest|iwr)", "PowerShell IEX download"),
    ("rce", "high", "base64-pipe-sh", r"base64\s+(-d|--decode)\b.*\|\s*(bash|sh)", "base64-decoded shell"),
    ("rce", "high", "npm-install-url", r"npm\s+(install|i)\s+(https?://|git\+)", "npm install from URL"),
    ("rce", "high", "pip-install-url", r"pip[0-9]?\s+install\s+(https?://|git\+)", "pip install from URL"),
    ("rce", "high", "npm-postinstall", r"\"(post|pre)install\"\s*:\s*\"[^\"]*(curl|wget|node\s+-e|bash)", "Suspicious npm install hook"),
    ("rce", "high", "go-get-exec", r"go\s+get\s+[^\s]+\s*&&", "go get with chained exec"),

    # ── Obfuscation / dynamic eval ──────────────────────────────────────────
    ("obfuscation", "high", "js-eval", r"\beval\s*\(", "JavaScript eval()"),
    ("obfuscation", "high", "js-function-ctor", r"\bnew\s+Function\s*\(", "Function constructor (dynamic code)"),
    ("obfuscation", "high", "js-atob-eval", r"eval\s*\(\s*atob\s*\(", "eval(atob()) decode+run"),
    ("obfuscation", "medium", "js-fromcharcode", r"String\.fromCharCode\((\s*\d+\s*,){10,}", "Long fromCharCode obfuscation"),
    ("obfuscation", "medium", "js-hex-escape", r"(\\x[0-9a-fA-F]{2}){12,}", "Long hex-escaped string"),
    ("obfuscation", "high", "py-exec", r"\bexec\s*\(", "Python exec()"),
    ("obfuscation", "high", "py-eval", r"(?<![A-Za-z_])eval\s*\(", "Python eval()"),
    ("obfuscation", "high", "py-compile", r"\bcompile\s*\([^)]*,\s*['\"]<string>['\"]", "Python compile() of string"),
    ("obfuscation", "critical", "py-base64-exec", r"exec\s*\(\s*(base64\.b64decode|__import__\(['\"]base64)", "exec of base64-decoded code"),
    ("obfuscation", "critical", "py-marshal-loads", r"\bmarshal\.loads\s*\(", "marshal.loads (bytecode)"),
    ("obfuscation", "critical", "py-pickle-loads", r"\b(pickle|cPickle)\.loads?\s*\(", "Unsafe pickle deserialization"),
    ("obfuscation", "high", "py-getattr-import", r"getattr\s*\(\s*__import__", "Reflective import"),
    ("obfuscation", "high", "ruby-eval", r"\b(eval|instance_eval|class_eval)\s*\(", "Ruby eval"),
    ("obfuscation", "high", "php-eval", r"\b(eval|assert|create_function)\s*\(\s*\$", "PHP dynamic eval"),
    ("obfuscation", "high", "php-base64-eval", r"eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(", "PHP packed eval"),

    # ── Reverse shells / backdoors ──────────────────────────────────────────
    ("backdoor", "critical", "bash-dev-tcp", r"/dev/(tcp|udp)/[0-9.]+/[0-9]+", "Bash /dev/tcp reverse shell"),
    ("backdoor", "critical", "nc-exec", r"\bnc(at)?\s+.*-e\s+(/bin/)?(ba)?sh", "netcat -e reverse shell"),
    ("backdoor", "critical", "ncat-exec", r"\bncat\s+.*--exec", "ncat --exec backdoor"),
    ("backdoor", "critical", "bash-i-redirect", r"bash\s+-i\s+>&\s*/dev/tcp", "Interactive bash reverse shell"),
    ("backdoor", "critical", "python-pty-spawn", r"pty\.spawn\s*\(\s*['\"]?/bin/(ba)?sh", "Python pty reverse shell"),
    ("backdoor", "critical", "python-socket-shell", r"socket\.socket\([^)]*\)[\s\S]{0,200}subprocess\.(call|Popen|run)\(", "Python socket+subprocess shell"),
    ("backdoor", "critical", "perl-reverse-shell", r"perl\s+-e\s+['\"].*socket.*exec", "Perl reverse shell"),
    ("backdoor", "critical", "php-reverse-shell", r"fsockopen\s*\([^)]*\)[\s\S]{0,120}(exec|shell_exec|proc_open)", "PHP reverse shell"),
    ("backdoor", "high", "msfvenom", r"\bmsfvenom\b", "Metasploit payload generator"),
    ("backdoor", "high", "meterpreter", r"(?i)meterpreter|metasploit", "Meterpreter/Metasploit reference"),
    ("backdoor", "high", "ssh-authorized-keys", r">>\s*~?/?\.ssh/authorized_keys", "Append to authorized_keys"),
    ("backdoor", "high", "webshell-php", r"<\?php\s+.*\$_(GET|POST|REQUEST)\[[^\]]+\]\s*\)", "PHP web shell"),

    # ── Data exfiltration ───────────────────────────────────────────────────
    ("exfiltration", "high", "read-ssh-keys", r"(cat|read|open)\s*\(?['\"]?[~/$].*\.ssh/(id_rsa|id_ed25519|authorized_keys)", "Read SSH private keys"),
    ("exfiltration", "critical", "read-aws-creds", r"\.aws/credentials", "Read AWS credentials file"),
    ("exfiltration", "high", "read-keychain", r"\bsecurity\s+(find-generic-password|dump-keychain)", "macOS keychain dump"),
    ("exfiltration", "high", "read-env-post", r"(os\.environ|process\.env)[\s\S]{0,80}(requests\.post|fetch\(|axios\.post|XMLHttpRequest)", "Env vars POSTed out"),
    ("exfiltration", "high", "browser-cookies", r"(Cookies|Login Data|key4\.db|logins\.json|Local State)\b", "Browser credential store access"),
    ("exfiltration", "high", "dns-exfil", r"(nslookup|dig)\s+[`$].*\.(burpcollaborator|oast|interactsh|requestbin)", "DNS exfiltration"),
    ("exfiltration", "medium", "webhook-post", r"(requests\.post|fetch|curl)\s*\(?['\"]?https?://[^\s'\"]*(webhook|hook|exfil|collect)", "POST to suspicious webhook"),
    ("exfiltration", "high", "screenshot-upload", r"(screencapture|import\s+-window|pyautogui\.screenshot)[\s\S]{0,150}(post|upload|curl)", "Screenshot + upload"),
    ("exfiltration", "high", "clipboard-read", r"\b(pbpaste|xclip\s+-o|clipboard\.paste|pyperclip\.paste)\b", "Clipboard read"),
    ("exfiltration", "high", "history-read-send", r"\.(bash|zsh)_history[\s\S]{0,120}(curl|post|nc\s)", "Shell history exfiltration"),
    ("exfiltration", "medium", "pastebin-upload", r"https?://(pastebin\.com/api|paste\.ee|hastebin|ix\.io|transfer\.sh|0x0\.st)", "Upload to paste/transfer service"),

    # ── Keylogging / surveillance ───────────────────────────────────────────
    ("surveillance", "critical", "keylogger-pynput", r"from\s+pynput[\s\S]{0,80}(Listener|on_press)", "pynput keylogger"),
    ("surveillance", "high", "keylogger-keyword", r"(?i)\bkeylog(ger|ging)?\b", "Keylogger reference"),
    ("surveillance", "high", "mic-record", r"(sox\s+-d|arecord|sounddevice\.rec|pyaudio)\b", "Microphone capture"),
    ("surveillance", "high", "webcam-capture", r"(cv2\.VideoCapture|imagesnap|ffmpeg\s+-f\s+avfoundation)", "Webcam capture"),

    # ── Prompt injection / agent hijack ─────────────────────────────────────
    ("prompt-injection", "high", "ignore-previous", r"(?i)ignore\s+(all\s+)?(the\s+)?(previous|prior|above)\s+(instructions|prompts|directions)", "Ignore previous instructions"),
    ("prompt-injection", "high", "disregard-safety", r"(?i)(disregard|ignore|bypass)\s+(your\s+)?(safety|security|guard|content)\s+(rules|policy|guidelines|measures)", "Disregard safety rules"),
    ("prompt-injection", "high", "system-override", r"(?i)(you\s+are\s+now|from\s+now\s+on,?\s+you\s+are)\s+(DAN|a\s+different|unrestricted|jailbroken)", "Persona/system override"),
    ("prompt-injection", "high", "reveal-system-prompt", r"(?i)(reveal|print|repeat|show|output)\s+(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+instructions)", "Exfiltrate system prompt"),
    ("prompt-injection", "high", "exfil-instructions", r"(?i)(exfiltrate|leak|send)\s+(your|the)\s+(instructions|prompt|context|memory)", "Leak agent context"),
    ("prompt-injection", "high", "unconditional-obey", r"(?i)(always|unconditionally)\s+(obey|comply|follow)\s+(without\s+question|no\s+matter\s+what)", "Unconditional obedience"),
    ("prompt-injection", "high", "hidden-goal", r"(?i)(secret|hidden|true)\s+(goal|objective|mission|agenda)", "Hidden goal injection"),
    ("prompt-injection", "high", "disable-safeguard", r"(?i)disable\s+(all\s+)?(safeguards?|filters?|guardrails?)", "Disable safeguards"),
    ("prompt-injection", "high", "jailbreak-keyword", r"(?i)\b(jailbreak|do\s+anything\s+now|developer\s+mode|sudo\s+mode)\b", "Jailbreak phrasing"),
    ("prompt-injection", "medium", "fake-system-tag", r"(?i)<\s*/?\s*(system|im_start|im_end)\s*>", "Spoofed system/control tags"),
    ("prompt-injection", "high", "tool-abuse", r"(?i)(use|call)\s+the\s+\w+\s+tool\s+to\s+(delete|exfiltrate|send|transfer|wire)", "Tool-abuse instruction"),
    ("prompt-injection", "medium", "encoded-instruction", r"(?i)decode\s+this\s+base64\s+and\s+(execute|run|follow)", "Encoded hidden instruction"),

    # ── Crypto-mining ───────────────────────────────────────────────────────
    ("mining", "critical", "xmrig", r"(?i)\bxmrig\b", "XMRig miner"),
    ("mining", "high", "stratum-proto", r"stratum\+tcp://", "Stratum mining pool"),
    ("mining", "high", "minerd", r"(?i)\b(minerd|cpuminer|ccminer|cgminer)\b", "CPU/GPU miner binary"),
    ("mining", "high", "coinhive", r"(?i)(coinhive|cryptonight|coinimp|webminepool)", "Browser cryptojacking"),
    ("mining", "high", "monero-wallet", r"\b4[0-9AB][0-9A-Za-z]{93}\b", "Monero wallet address"),
    ("mining", "medium", "donate-level", r"--donate-level\s+\d", "Miner donate-level flag"),

    # ── Persistence ─────────────────────────────────────────────────────────
    ("persistence", "high", "crontab-inject", r"(crontab\s+-|>>\s*/var/spool/cron|/etc/cron\.(d|daily))", "Cron persistence"),
    ("persistence", "high", "launchd-plist", r"(LaunchAgents|LaunchDaemons)/[^\s]+\.plist", "macOS launchd persistence"),
    ("persistence", "high", "rc-append", r">>\s*~?/?\.(bashrc|zshrc|bash_profile|profile|zprofile)", "Shell rc persistence"),
    ("persistence", "high", "systemd-service", r"(systemctl\s+enable|>>\s*/etc/systemd/system)", "systemd persistence"),
    ("persistence", "medium", "login-items", r"osascript.*login\s+items", "macOS login-item persistence"),

    # ── Known malware / stealer families ────────────────────────────────────
    ("malware", "critical", "atomic-stealer", r"(?i)\b(atomic\s+stealer|amos|atomicstealer)\b", "Atomic macOS Stealer (AMOS)"),
    ("malware", "critical", "redline", r"(?i)\bredline\s+stealer\b", "RedLine stealer"),
    ("malware", "critical", "raccoon", r"(?i)\braccoon\s+stealer\b", "Raccoon stealer"),
    ("malware", "critical", "predator", r"(?i)\bpredator\s+(the\s+thief|stealer)\b", "Predator the Thief"),
    ("malware", "high", "cobalt-strike", r"(?i)cobalt\s*strike|beacon\.dll", "Cobalt Strike beacon"),
    ("malware", "high", "empire-agent", r"(?i)powershell\s+empire", "PowerShell Empire"),
    ("malware", "high", "generic-stealer", r"(?i)\b(infostealer|info-stealer|token-stealer|grabber)\b", "Generic info-stealer"),
    ("malware", "high", "shell-backdoor", r"(?i)\b(shell-backdoor|web-?shell|c99shell|r57shell)\b", "Web/shell backdoor kit"),

    # ── More secret/credential formats ──────────────────────────────────────
    ("secret", "high", "bitbucket-app-password", r"(?i)bitbucket.{0,20}\bATBB[A-Za-z0-9]{32,}\b", "Bitbucket app password"),
    ("secret", "high", "buildkite-token", r"\bbkua_[a-z0-9]{40}\b", "Buildkite agent token"),
    ("secret", "high", "databricks-token", r"\bdapi[0-9a-f]{32}\b", "Databricks personal access token"),
    ("secret", "high", "doppler-token", r"\bdp\.pt\.[A-Za-z0-9]{40,}\b", "Doppler personal token"),
    ("secret", "high", "dynatrace-token", r"\bdt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b", "Dynatrace API token"),
    ("secret", "high", "fastly-token", r"(?i)fastly.{0,20}\b[A-Za-z0-9_-]{32}\b", "Fastly API token"),
    ("secret", "high", "figma-token", r"\bfigd_[A-Za-z0-9_-]{40,}\b", "Figma personal token"),
    ("secret", "high", "flutterwave-secret", r"\bFLWSECK_TEST-[a-h0-9]{32}-X\b|\bFLWSECK-[a-h0-9]{32}-[a-h0-9]{12}X\b", "Flutterwave secret key"),
    ("secret", "high", "gemini-google-ai", r"\bAIzaSy[A-Za-z0-9_-]{33}\b", "Google generative-AI key"),
    ("secret", "high", "gocardless-token", r"\blive_[A-Za-z0-9_-]{40,}\b", "GoCardless access token"),
    ("secret", "high", "hubspot-key", r"(?i)hubspot.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "HubSpot API key"),
    ("secret", "high", "infura-key", r"(?i)infura.{0,20}\b[0-9a-f]{32}\b", "Infura project secret"),
    ("secret", "high", "jfrog-token", r"\bcmVmdGtuO[A-Za-z0-9]{60,}\b", "JFrog Artifactory token"),
    ("secret", "high", "launchdarkly-token", r"\bapi-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "LaunchDarkly access token"),
    ("secret", "high", "mapbox-token", r"\b[ps]k\.eyJ[A-Za-z0-9_-]{60,}\b", "Mapbox access token"),
    ("secret", "high", "teams-webhook", r"https://[a-z0-9.]*webhook\.office\.com/webhookb2/[0-9a-f-]+@[0-9a-f-]+/IncomingWebhook/", "MS Teams webhook"),
    ("secret", "high", "netlify-token", r"(?i)netlify.{0,20}\b[A-Za-z0-9_-]{40,}\b", "Netlify access token"),
    ("secret", "high", "planetscale-token", r"\bpscale_tkn_[A-Za-z0-9_.-]{40,}\b", "PlanetScale token"),
    ("secret", "high", "plaid-secret", r"(?i)plaid.{0,20}\b[0-9a-f]{30}\b", "Plaid secret"),
    ("secret", "high", "postman-key", r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b", "Postman API key"),
    ("secret", "high", "prefect-key", r"\bpnu_[A-Za-z0-9]{36}\b", "Prefect API key"),
    ("secret", "high", "pulumi-token", r"\bpul-[0-9a-f]{40}\b", "Pulumi access token"),
    ("secret", "high", "rapidapi-key", r"(?i)x-rapidapi-key.{0,5}[A-Za-z0-9]{50}", "RapidAPI key"),
    ("secret", "high", "razorpay-key", r"\brzp_live_[A-Za-z0-9]{14}\b", "Razorpay live key"),
    ("secret", "high", "readme-token", r"\brdme_[A-Za-z0-9]{70,}\b", "ReadMe API token"),
    ("secret", "high", "rubygems-key", r"\brubygems_[0-9a-f]{48}\b", "RubyGems API key"),
    ("secret", "high", "salesforce-token", r"\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{96,}\b", "Salesforce session token"),
    ("secret", "high", "shippo-token", r"\bshippo_(live|test)_[0-9a-f]{40}\b", "Shippo API token"),
    ("secret", "high", "shodan-key", r"(?i)shodan.{0,20}\b[A-Za-z0-9]{32}\b", "Shodan API key"),
    ("secret", "high", "snyk-token", r"(?i)snyk.{0,20}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "Snyk API token"),
    ("secret", "high", "sourcegraph-token", r"\bsgp_[a-f0-9]{16,}_[a-f0-9]{40}\b", "Sourcegraph token"),
    ("secret", "high", "supabase-service-key", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+service_role[A-Za-z0-9_-]+\b", "Supabase service-role key"),
    ("secret", "high", "telnyx-key", r"\bKEY[0-9A-F]{32}_[A-Za-z0-9]{16}\b", "Telnyx API key"),
    ("secret", "high", "typeform-token", r"\btfp_[A-Za-z0-9_]{40,}\b", "Typeform token"),
    ("secret", "high", "vercel-token", r"(?i)vercel.{0,20}\b[A-Za-z0-9]{24}\b", "Vercel API token"),
    ("secret", "high", "yandex-key", r"\bAQVN[A-Za-z0-9_-]{35,}\b", "Yandex Cloud key"),
    ("secret", "high", "zendesk-token", r"(?i)zendesk.{0,20}\b[A-Za-z0-9]{40}\b", "Zendesk API token"),
    ("secret", "high", "zoom-jwt", r"(?i)zoom.{0,20}\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "Zoom JWT"),

    # ── Language-specific dangerous exec / deserialization ──────────────────
    ("rce", "high", "java-runtime-exec", r"Runtime\.getRuntime\(\)\.exec\s*\(", "Java Runtime.exec()"),
    ("rce", "high", "java-processbuilder", r"new\s+ProcessBuilder\s*\(", "Java ProcessBuilder"),
    ("rce", "high", "java-scriptengine", r"ScriptEngine[\s\S]{0,60}\.eval\s*\(", "Java ScriptEngine eval"),
    ("obfuscation", "critical", "java-objectinputstream", r"new\s+ObjectInputStream\s*\([\s\S]{0,80}\.readObject\s*\(", "Java unsafe deserialization"),
    ("obfuscation", "high", "java-xmldecoder", r"new\s+XMLDecoder\s*\(", "Java XMLDecoder (RCE)"),
    ("rce", "high", "dotnet-process-start", r"Process\.Start\s*\(", ".NET Process.Start"),
    ("obfuscation", "critical", "dotnet-binaryformatter", r"BinaryFormatter\s*\([\s\S]{0,40}\.Deserialize\s*\(", ".NET BinaryFormatter deser"),
    ("rce", "high", "go-exec-shell", r"exec\.Command\s*\(\s*['\"](ba)?sh['\"]\s*,\s*['\"]-c['\"]", "Go exec sh -c"),
    ("rce", "high", "rust-command-sh", r"Command::new\s*\(\s*\"(ba)?sh\"\s*\)[\s\S]{0,40}\.arg\s*\(\s*\"-c\"", "Rust Command sh -c"),
    ("rce", "high", "c-system", r"\bsystem\s*\(\s*\"[^\"]*(rm|curl|wget|sh|bash)", "C system() shell call"),
    ("rce", "high", "vba-shell", r"(?i)\bShell\s*\(\s*\"|CreateObject\s*\(\s*\"WScript\.Shell\"", "VBA/VBScript shell"),
    ("rce", "high", "powershell-iex-generic", r"(?i)\b(iex|invoke-expression)\b", "PowerShell Invoke-Expression"),
    ("rce", "high", "powershell-downloadfile", r"(?i)\.DownloadFile\s*\(|Invoke-WebRequest[\s\S]{0,40}-OutFile", "PowerShell file download"),
    ("rce", "high", "lua-os-execute", r"\bos\.execute\s*\(", "Lua os.execute"),
    ("rce", "high", "groovy-execute", r"['\"]\s*\.execute\s*\(\s*\)", "Groovy string.execute()"),
    ("rce", "high", "python-os-system-shell", r"\bos\.system\s*\(", "Python os.system()"),
    ("rce", "high", "subprocess-shell-true", r"subprocess\.(run|call|Popen|check_output)\s*\([\s\S]{0,120}shell\s*=\s*True", "subprocess shell=True"),
    ("rce", "high", "node-child-process-exec", r"(child_process\.)?exec(Sync)?\s*\(\s*[`'\"]", "Node child_process.exec"),
    ("rce", "high", "ruby-system-backtick", r"(?<![A-Za-z_])(system|exec)\s*\(\s*['\"]|`[^`]*\$\{?[A-Za-z_]", "Ruby system/backtick with var"),
    ("rce", "high", "php-shell-exec", r"\b(shell_exec|passthru|proc_open|popen)\s*\(", "PHP shell exec functions"),

    # ── Container / cloud misconfiguration ──────────────────────────────────
    ("misconfig", "high", "k8s-privileged", r"privileged\s*:\s*true", "Privileged container"),
    ("misconfig", "high", "k8s-hostpath", r"hostPath\s*:", "Container mounts host path"),
    ("misconfig", "high", "k8s-host-network", r"hostNetwork\s*:\s*true", "Container uses host network"),
    ("misconfig", "critical", "docker-sock-mount", r"/var/run/docker\.sock", "Docker socket mounted (escape)"),
    ("misconfig", "high", "docker-privileged-flag", r"docker\s+run\s+[^\n]*--privileged", "docker run --privileged"),
    ("misconfig", "high", "aws-iam-admin-star", r"\"Action\"\s*:\s*\"\*\"[\s\S]{0,40}\"Resource\"\s*:\s*\"\*\"", "IAM policy allows *:*"),
    ("misconfig", "high", "sg-open-world", r"(0\.0\.0\.0/0|::/0)[\s\S]{0,40}(22|3389|3306|5432|6379|27017)", "Security group open to world on sensitive port"),
    ("misconfig", "high", "s3-public-acl", r"(?i)(public-read-write|AllUsers|AuthenticatedUsers)", "Public S3 ACL grant"),
    ("misconfig", "high", "tls-verify-disabled", r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true|curl\s+[^\n]*\s-k\b)", "TLS verification disabled"),
    ("misconfig", "medium", "debug-enabled", r"(?i)(DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1|app\.run\([^)]*debug\s*=\s*True)", "Debug mode enabled in code"),

    # ── More persistence / backdoor ─────────────────────────────────────────
    ("persistence", "high", "windows-run-key", r"(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Windows Run-key persistence"),
    ("persistence", "high", "scheduled-task", r"(?i)schtasks\s+/create", "Windows scheduled task"),
    ("persistence", "high", "ld-preload", r"(?i)(LD_PRELOAD\s*=|>>\s*/etc/ld\.so\.preload)", "LD_PRELOAD hijack"),
    ("persistence", "high", "dyld-insert", r"DYLD_INSERT_LIBRARIES\s*=", "macOS DYLD insert-library hijack"),
    ("backdoor", "high", "authorized-keys-write", r"echo\s+['\"]?ssh-(rsa|ed25519)[\s\S]{0,60}>>\s*[^\n]*authorized_keys", "Inject SSH key"),
    ("backdoor", "high", "useradd-backdoor", r"\b(useradd|adduser)\b[\s\S]{0,40}(usermod\s+-aG\s+(sudo|wheel|admin))", "Create privileged backdoor user"),

    # ── More malware families ───────────────────────────────────────────────
    ("malware", "critical", "lumma-stealer", r"(?i)\blumma\s*(c2|stealer)?\b", "Lumma stealer"),
    ("malware", "critical", "vidar-stealer", r"(?i)\bvidar\s+stealer\b", "Vidar stealer"),
    ("malware", "high", "agent-tesla", r"(?i)\bagent\s*tesla\b", "Agent Tesla"),
    ("malware", "high", "formbook", r"(?i)\bformbook\b", "FormBook"),
    ("malware", "high", "qakbot", r"(?i)\b(qakbot|qbot)\b", "QakBot"),
    ("malware", "high", "asyncrat", r"(?i)\b(asyncrat|xworm|venomrat)\b", "AsyncRAT/XWorm family"),
    ("malware", "high", "njrat", r"(?i)\bnjrat\b", "njRAT"),
]

PATTERNS: List[Dict] = []
for _cat, _sev, _id, _re, _desc in _RAW:
    PATTERNS.append({
        "id": _id,
        "category": _cat,
        "severity": _sev,
        "description": _desc,
        "regex": re.compile(_re),
    })


def count() -> int:
    """The true number of detection patterns in the corpus."""
    return len(PATTERNS)


def categories() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for p in PATTERNS:
        out[p["category"]] = out.get(p["category"], 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def scan_text(content: str) -> List[Dict]:
    """Return findings (id, category, severity, description, match) for a blob."""
    findings: List[Dict] = []
    for p in PATTERNS:
        m = p["regex"].search(content)
        if m:
            snippet = m.group(0)
            findings.append({
                "id": p["id"],
                "category": p["category"],
                "severity": p["severity"],
                "description": p["description"],
                "match": (snippet[:60] + "…") if len(snippet) > 60 else snippet,
            })
    return findings
