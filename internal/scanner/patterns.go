package scanner

// Check defines a security pattern to scan for
type Check struct {
	ID       string
	Category string
	Label    string
	Pattern  string
	Severity string
}

// AllChecks contains all security patterns to scan for
var AllChecks = []Check{
	// Network / exfiltration
	{
		ID:       "net_imports",
		Category: "Network / Exfiltration",
		Label:    "Network library imports",
		Pattern:  `^\s*(import|from)\s+(requests|urllib|http\.client|httpx|aiohttp|socket|websocket|grpc|xmlrpc|ftplib|smtplib|poplib|imaplib|telnetlib)\b`,
		Severity: "danger",
	},
	{
		ID:       "net_calls",
		Category: "Network / Exfiltration",
		Label:    "Network function calls",
		Pattern:  `\b(requests\.(get|post|put|patch|delete|head|session)|urllib\.request\.urlopen|http\.client\.HTTP|urlopen|httpx\.(get|post|AsyncClient)|aiohttp\.ClientSession)\b`,
		Severity: "danger",
	},
	{
		ID:       "curl_wget",
		Category: "Network / Exfiltration",
		Label:    "Shell network commands",
		Pattern:  `\b(curl|wget|nc|ncat|netcat)\s`,
		Severity: "danger",
	},
	// Code injection
	{
		ID:       "eval_exec",
		Category: "Code Injection",
		Label:    "eval / exec / compile calls",
		Pattern:  `\b(eval|exec|compile)\s*\(`,
		Severity: "danger",
	},
	{
		ID:       "base64_decode",
		Category: "Code Injection",
		Label:    "Base64 / encoding tricks",
		Pattern:  `\b(base64\.b64decode|base64\.decodebytes|codecs\.decode|rot13)\b`,
		Severity: "danger",
	},
	{
		ID:       "dunder_import",
		Category: "Code Injection",
		Label:    "Dynamic imports",
		Pattern:  `\b(__import__|importlib\.import_module)\s*\(`,
		Severity: "warn",
	},
	{
		ID:       "pickle",
		Category: "Code Injection",
		Label:    "Pickle deserialization (RCE vector)",
		Pattern:  `\b(pickle\.loads?|cPickle\.loads?|shelve\.open|dill\.loads?)\b`,
		Severity: "danger",
	},
	// Credential / secret access
	{
		ID:       "secret_paths",
		Category: "Credential Access",
		Label:    "Sensitive file path references",
		Pattern:  `(\.ssh[/\\]|\.aws[/\\]|\.gnupg[/\\]|\.npmrc|\.pypirc|\.netrc|\.docker[/\\]config|\.kube[/\\]config|id_rsa|id_ed25519)`,
		Severity: "danger",
	},
	{
		ID:       "secret_vars",
		Category: "Credential Access",
		Label:    "Secret / key variable patterns",
		Pattern:  `\b(api_key|apikey|api_secret|secret_key|access_key|private_key|auth_token|password|passwd)\s*[=:]`,
		Severity: "warn",
	},
	{
		ID:       "env_access",
		Category: "Credential Access",
		Label:    "Environment variable reads",
		Pattern:  `\b(os\.environ\[|os\.environ\.get|os\.getenv)\s*\(`,
		Severity: "warn",
	},
	// Subprocess / shell
	{
		ID:       "subprocess",
		Category: "Subprocess / Shell",
		Label:    "Subprocess and shell execution",
		Pattern:  `\b(subprocess\.(run|Popen|call|check_output|check_call)|os\.system|os\.popen|os\.exec[lv])\s*\(`,
		Severity: "warn",
	},
	{
		ID:       "shell_true",
		Category: "Subprocess / Shell",
		Label:    "shell=True (command injection risk)",
		Pattern:  `shell\s*=\s*True`,
		Severity: "danger",
	},
	// Suspicious file I/O
	{
		ID:       "sys_file_write",
		Category: "File I/O",
		Label:    "Writes to system / sensitive paths",
		Pattern:  `open\s*\(\s*['"](/etc/|/usr/|/var/|/tmp/|C:\\Windows).*['"],\s*['"]w`,
		Severity: "danger",
	},
	{
		ID:       "home_write",
		Category: "File I/O",
		Label:    "Writes to user home / dotfiles",
		Pattern:  `open\s*\(.*(\~|Path\.home|expanduser).*['"]w`,
		Severity: "warn",
	},
	// Install hooks
	{
		ID:       "setup_cmdclass",
		Category: "Install Hooks",
		Label:    "Custom setup.py install commands",
		Pattern:  `\bcmdclass\s*=|class\s+\w*(Install|Develop|BuildExt)\b`,
		Severity: "danger",
	},
	{
		ID:       "postinstall",
		Category: "Install Hooks",
		Label:    "Post-install / build scripts",
		Pattern:  `\b(post_install|pre_install|atexit\.register)\b`,
		Severity: "warn",
	},
}

// SetupPyPatterns are dangerous patterns specific to setup.py
var SetupPyPatterns = []struct {
	Pattern string
	Label   string
}{
	{`\bcmdclass\b`, "Custom install command class"},
	{`class\s+\w*Install\b`, "Custom Install command"},
	{`\bsubprocess\b`, "subprocess usage in setup.py"},
	{`\bos\.system\b`, "os.system in setup.py"},
	{`\burllib\b`, "Network call in setup.py"},
	{`\brequests\b`, "Network call in setup.py"},
	{`\bexec\s*\(`, "exec() in setup.py"},
	{`\beval\s*\(`, "eval() in setup.py"},
}
