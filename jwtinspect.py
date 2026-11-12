#!/usr/bin/env python3
"""
jwtinspect - JSON Web Token decoder and weakness analyzer.

Decodes a JWT without verifying it, prints header/payload, flags common
weaknesses (alg:none, HS256 where RS256 expected, missing exp, long-lived
tokens), and optionally brute-forces a weak HMAC secret from a wordlist.

Author: Anvar Sadath K.  |  License: MIT
Only test tokens from systems you own or are authorized to assess.
"""
import argparse
import base64
import hashlib
import hmac
import json
import sys
import time


def b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def split_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a well-formed JWT (expected 3 dot-separated parts)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts


def analyze(header: dict, payload: dict):
    issues = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        issues.append(("CRITICAL", "alg:none — signature not verified; forge any claim"))
    if alg.startswith("hs"):
        issues.append(("INFO", f"symmetric alg ({header.get('alg')}) — secret-crackable; try --wordlist"))
    if "exp" not in payload:
        issues.append(("MEDIUM", "no 'exp' claim — token never expires"))
    else:
        try:
            ttl = int(payload["exp"]) - int(time.time())
            if ttl > 86400 * 7:
                issues.append(("LOW", f"long-lived token (~{ttl // 86400} days remaining)"))
            elif ttl < 0:
                issues.append(("INFO", "token is already expired"))
        except Exception:
            pass
    if header.get("jku") or header.get("x5u"):
        issues.append(("HIGH", "jku/x5u header present — possible key-injection via attacker-controlled URL"))
    if header.get("kid"):
        issues.append(("INFO", "'kid' header present — review for path traversal / SQLi sinks"))
    return issues


def crack(parts, wordlist: str):
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig = b64url_decode(parts[2])
    except Exception:
        return None
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            secret = line.strip()
            if not secret:
                continue
            mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(mac, sig):
                return secret
    return None


def main():
    p = argparse.ArgumentParser(description="Decode and analyze a JWT.")
    p.add_argument("token", nargs="?", help="JWT string (or pipe via stdin)")
    p.add_argument("-w", "--wordlist", help="HS256 secret wordlist to brute-force")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = p.parse_args()

    token = args.token or sys.stdin.read().strip()
    if not token:
        p.error("provide a JWT as an argument or via stdin")

    try:
        header, payload, parts = split_jwt(token)
    except Exception as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    issues = analyze(header, payload)
    cracked = None
    if args.wordlist and str(header.get("alg", "")).lower().startswith("hs"):
        cracked = crack(parts, args.wordlist)
        if cracked:
            issues.append(("CRITICAL", f"HMAC secret cracked: '{cracked}' — full token forgery possible"))

    if args.json:
        print(json.dumps({"header": header, "payload": payload,
                          "issues": issues, "cracked_secret": cracked}, indent=2))
        return

    print("=== Header ===");  print(json.dumps(header, indent=2))
    print("=== Payload ==="); print(json.dumps(payload, indent=2))
    print("=== Analysis ===")
    if not issues:
        print("No obvious weaknesses flagged.")
    for sev, desc in issues:
        print(f"[{sev}] {desc}")


if __name__ == "__main__":
    main()
