import os
import re

SMALI_DIR = "output"

patterns = {
    # "URLs": r"https?://[^\s\"']+",
    # "API_KEYS": r"(?i)(api[_-]?key|token|secret)[\"'\s:=]+([A-Za-z0-9\-_]{8,})",
    # "PASSWORDS": r"(?i)(password|passwd)[\"'\s:=]+(.+)",
    # "AWS_KEYS": r"AKIA[0-9A-Z]{16}",
    # "PRIVATE_KEYS": r"-----BEGIN PRIVATE KEY-----",
    "GOOGLE_API_KEYS": r"AIza[0-9A-Za-z\\-_]{35}",
    "GOOGLE_MAPS_CONTEXT": r"(AIza[0-9A-Za-z\\-_]{35}).{0,50}(maps|google|geo)",
    

}

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()

            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append((name, matches))
    except:
        pass

    return findings

def scan_smali(directory):
    results = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".smali"):
                path = os.path.join(root, file)
                findings = scan_file(path)

                if findings:
                    results[path] = findings

    return results


if __name__ == "__main__":
    results = scan_smali(SMALI_DIR)

    for file, issues in results.items():
        print(f"\n[+] File: {file}")
        for issue, matches in issues:
            print(f"  - {issue}: {matches}")