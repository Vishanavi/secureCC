

VULNERABILITY_RULES = {


    "hardcoded_secret": [
        {"pattern": r'"\s*password\s*"',                   "severity": "HIGH",   "fix": "Do not hardcode passwords; use secure storage."},
        {"pattern": r'"\s*passwd\s*"',                     "severity": "HIGH",   "fix": "Use environment variables or a secrets manager."},
        {"pattern": r'"\s*api_key\s*"',                    "severity": "MEDIUM", "fix": "Store API keys in environment variables."},
        {"pattern": r'"\s*secret\s*"',                     "severity": "HIGH",   "fix": "Avoid hardcoding secrets in source code."},
        {"pattern": r'"\s*private_key\s*"',                "severity": "HIGH",   "fix": "Store private keys externally."},
        {"pattern": r"\bpassword\s*=\s*\"[^\"]+\"",        "severity": "HIGH",   "fix": "Do not hardcode credentials."},
        {"pattern": r"\bapi_key\s*=\s*\"[^\"]+\"",         "severity": "HIGH",   "fix": "Store API keys in env variables."},
    ],


    "insecure_permissions": [
        {"pattern": r"chmod\s*\(\s*[^,]+,\s*0?777\s*\)",  "severity": "HIGH",   "fix": "Avoid 0777 permissions; use least privilege."},
        {"pattern": r"chmod\s*\(\s*[^,]+,\s*0?666\s*\)",  "severity": "MEDIUM", "fix": "World-writable files are dangerous."},
        {"pattern": "chmod(",                               "severity": "LOW",    "fix": "Review file permissions carefully."},
    ],


    "env_exposure": [
        {"pattern": "getenv(",                              "severity": "LOW",    "fix": "Validate and sanitise environment variables before use."},
    ],


    "unsafe_file_handling": [
        {"pattern": "fopen(",                               "severity": "LOW",    "fix": "Validate file path and check return value for NULL."},
        {"pattern": "freopen(",                             "severity": "MEDIUM", "fix": "Validate file input."},
    ],


    "integer_overflow": [
        {"pattern": r"malloc\s*\(\s*\w+\s*\*\s*sizeof",    "severity": "MEDIUM", "fix": "Validate multiplication before malloc to prevent overflow."},
    ],


    "infinite_loop": [
        {"pattern": r"while\s*\(\s*1\s*\)",                "severity": "LOW",    "fix": "Ensure the loop has a proper termination condition."},
        {"pattern": r"for\s*\(\s*;\s*;\s*\)",              "severity": "LOW",    "fix": "Infinite for-loop detected; ensure break/return exists."},
    ],
}