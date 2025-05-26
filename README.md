# JS-secretfinder-h8


A fast, multi-threaded crawler to discover JavaScript/JSON files and detect exposed secrets (API keys, tokens, etc.). Ideal for bug bounty hunters and security pros.

⚙️ Features
🔁 Two-Phase Workflow: Discover files → Scan for secrets

🧠 15+ Patterns + Entropy Detection

🔍 Confidence Levels & Context Extraction

⚡ Multi-threading, Custom Headers, Proxy Support

**📄 JSON/YAML/TXT Reporting**

**📦 Install**
   ```bash
git clone https://github.com/raj80rk/JS-secretfinder-h8.git
cd js-secret-crawler
pip install -r requirements.txt
```
**🚀 Usage**

**🌐 Discover JS/JSON Files**
   ```bash
python crawler.py -l https://example.com -o urls.txt
```
**🔐 Scan for Secrets**

   ```bash
python crawler.py -il urls.txt --scan-secrets -o results.json

```
**🧠 All-in-One Scan**
   ```bash
python crawler.py -l https://example.com --scan-secrets --threads 10 -o report.yaml
```
**🛠️ Options**

- `-l `, `--list:` : URLs to scan

- `-il`, `--input`: Input file

- `--scan-secrets`: Enable secret scanning

-`--format`: Output format (json/yaml/txt)

-`--threads`: Number of threads (default: 5)

-`--timeout`: Request timeout

-`--proxy`, `--headers`, `--user-agent`: Advanced configs

**🧬 Detected Secrets**

Supports 15+ secret types:

AWS/GitHub/Stripe/Google API Keys

JWTs, Private Keys, DB URLs

Generic API Keys, Passwords, High-Entropy Strings

**🧑‍💻 Contributing**

Fork → Create Branch → Commit → PR

Add new regex patterns under AdvancedSecretScanner in crawler.py

Test & document your changes

**⚠️ Legal & Ethics**

Scan only with permission

Respect rate limits & robots.txt

Disclose responsibly
