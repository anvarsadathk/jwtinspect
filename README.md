# jwtinspect

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Category](https://img.shields.io/badge/web-jwt-red)

Decode and **audit JSON Web Tokens** in one command. Prints the header and payload, flags the classic weaknesses (`alg:none`, missing/long `exp`, `jku`/`x5u` key-injection headers, `kid` injection sinks), and optionally **brute-forces a weak HS256 secret** from a wordlist to prove full token forgery.

## Features
- Verify-free decode of header + payload
- Weakness analysis with severity labels
- HS256 secret cracking (`-w wordlist.txt`)
- `--json` output for pipelines
- Reads the token from an argument **or** stdin
- Zero dependencies

## Install
```bash
git clone https://github.com/anvarsadathk/jwtinspect.git
cd jwtinspect
python3 jwtinspect.py --help
```

## Usage
```bash
# Decode + analyze
python3 jwtinspect.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxxx

# Pipe it in
echo "$TOKEN" | python3 jwtinspect.py

# Try to crack a weak HMAC secret
python3 jwtinspect.py "$TOKEN" -w /usr/share/wordlists/rockyou.txt

# JSON for automation
python3 jwtinspect.py "$TOKEN" --json
```

## ⚠️ Responsible use
A cracked secret or an `alg:none` finding means tokens can be forged. Use this only on tokens from systems you own or are authorized to test, and report findings responsibly.

## License
MIT © Anvar Sadath K.
