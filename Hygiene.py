#!/usr/bin/env python3
"""
hygiene - give any git repo a security hygiene report card.

Usage:
    hygiene .
    hygiene /path/to/repo
    hygiene https://github.com/user/repo
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

# ---------------------------------------------------------------------------
# Colors (no external deps, plain ANSI, safely no-op'd if not a tty)
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"

    @staticmethod
    def disable():
        for attr in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN", "GRAY"):
            setattr(C, attr, "")


if not sys.stdout.isatty():
    C.disable()

# ---------------------------------------------------------------------------
# Secret detection patterns (public, well-known patterns used by defensive
# scanners like gitleaks / detect-secrets — not exploit code, just regex).
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API Key/Secret", re.compile(
        r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][0-9a-zA-Z\-_/+=]{16,60}['\"]")),
    ("Private Key Block", re.compile(
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,72}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{20,}")),
    ("Slack Webhook", re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
]

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mov", ".exe", ".dll", ".so",
    ".class", ".jar", ".bin", ".pyc",
}

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv", "__pycache__"}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB, skip huge files


def iter_tracked_files(repo_path):
    """Yield paths of files tracked/present in the repo, skipping noisy dirs."""
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            full = os.path.join(root, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in BINARY_EXTENSIONS:
                continue
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield full


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return ""


# ---------------------------------------------------------------------------
# Individual checks. Each returns (points_deducted, max_points, findings[])
# ---------------------------------------------------------------------------

def check_secrets_in_files(repo_path):
    max_points = 30
    findings = []
    for path in iter_tracked_files(repo_path):
        text = read_text(path)
        if not text:
            continue
        for name, pattern in SECRET_PATTERNS:
            m = pattern.search(text)
            if m:
                rel = os.path.relpath(path, repo_path)
                findings.append(f"{name} pattern matched in {rel}")
    deducted = min(max_points, len(findings) * 10)
    return deducted, max_points, findings


def check_env_committed(repo_path):
    max_points = 15
    findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f == ".env" or f.startswith(".env."):
                rel = os.path.relpath(os.path.join(root, f), repo_path)
                findings.append(f"Environment file present in repo: {rel}")
    deducted = max_points if findings else 0
    return deducted, max_points, findings


def check_git_history_secrets(repo_path, depth):
    max_points = 20
    findings = []
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.isdir(git_dir):
        return 0, max_points, ["Not a git repository — history scan skipped"]
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "log", f"-{depth}", "-p", "--all"],
            capture_output=True, text=True, timeout=60,
        )
        diff_text = result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return 0, max_points, ["Git history scan timed out or failed"]

    seen = set()
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(diff_text) and name not in seen:
            seen.add(name)
            findings.append(f"{name} pattern found in commit history (last {depth} commits)")
    deducted = min(max_points, len(findings) * 10)
    return deducted, max_points, findings


def check_dependency_pinning(repo_path):
    max_points = 15
    findings = []

    req_path = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(req_path):
        text = read_text(req_path)
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
        unpinned = [l for l in lines if "==" not in l and "@" not in l]
        if unpinned:
            findings.append(f"{len(unpinned)} unpinned dependency line(s) in requirements.txt")

    pkg_path = os.path.join(repo_path, "package.json")
    if os.path.isfile(pkg_path):
        has_lock = os.path.isfile(os.path.join(repo_path, "package-lock.json")) or \
            os.path.isfile(os.path.join(repo_path, "yarn.lock")) or \
            os.path.isfile(os.path.join(repo_path, "pnpm-lock.yaml"))
        if not has_lock:
            findings.append("package.json present with no lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)")

    deducted = min(max_points, len(findings) * 8)
    return deducted, max_points, findings


def check_ci_workflows(repo_path):
    max_points = 15
    findings = []
    workflows_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return 0, max_points, []

    for f in os.listdir(workflows_dir):
        if not (f.endswith(".yml") or f.endswith(".yaml")):
            continue
        text = read_text(os.path.join(workflows_dir, f))
        if "pull_request_target" in text and "checkout" in text.lower():
            findings.append(f"{f}: uses pull_request_target with a checkout step — "
                             f"can allow untrusted PR code to run with repo secrets")
        if re.search(r"permissions:\s*write-all", text):
            findings.append(f"{f}: workflow grants 'write-all' permissions")

    deducted = min(max_points, len(findings) * 8)
    return deducted, max_points, findings


def check_gitignore_hygiene(repo_path):
    max_points = 5
    gi_path = os.path.join(repo_path, ".gitignore")
    if not os.path.isfile(gi_path):
        return max_points, max_points, [".gitignore file is missing entirely"]

    text = read_text(gi_path)
    expected = [".env", "__pycache__", "node_modules", "*.log"]
    missing = [e for e in expected if e not in text]
    if len(missing) >= 3:
        return max_points, max_points, [".gitignore is missing most common entries (.env, __pycache__, node_modules, ...)"]
    return 0, max_points, []


CHECKS = [
    ("Hardcoded secrets in tracked files", check_secrets_in_files),
    ("Secrets in git commit history", check_git_history_secrets),
    (".env files committed", check_env_committed),
    ("Dependency pinning / lockfiles", check_dependency_pinning),
    ("Risky CI/CD workflow patterns", check_ci_workflows),
    (".gitignore hygiene", check_gitignore_hygiene),
]


def grade_for(score):
    if score >= 90:
        return "A", C.GREEN
    if score >= 80:
        return "B", C.GREEN
    if score >= 70:
        return "C", C.YELLOW
    if score >= 60:
        return "D", C.YELLOW
    return "F", C.RED


def clone_if_url(target, tmp_dir):
    if target.startswith("http://") or target.startswith("https://") or target.startswith("git@"):
        print(f"{C.GRAY}Cloning {target} ...{C.RESET}")
        dest = os.path.join(tmp_dir, "repo")
        subprocess.run(
            ["git", "clone", "--quiet", target, dest],
            check=True,
        )
        return dest
    return os.path.abspath(target)


def main():
    parser = argparse.ArgumentParser(
        prog="hygiene",
        description="Give any git repo a security hygiene report card.",
    )
    parser.add_argument("target", help="Local path or git URL of the repo to scan")
    parser.add_argument("--history-depth", type=int, default=200,
                         help="Number of recent commits to scan for leaked secrets (default: 200)")
    parser.add_argument("--fail-under", type=str, default=None,
                         help="Exit non-zero if grade is below this letter (e.g. --fail-under C). Useful in CI.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    tmp_dir = None
    try:
        if args.target.startswith(("http://", "https://", "git@")):
            tmp_dir = tempfile.mkdtemp(prefix="hygiene-")
            repo_path = clone_if_url(args.target, tmp_dir)
        else:
            repo_path = os.path.abspath(args.target)

        if not os.path.isdir(repo_path):
            print(f"{C.RED}Error: {repo_path} is not a valid directory{C.RESET}")
            sys.exit(2)

        print(f"\n{C.BOLD}hygiene{C.RESET} {C.GRAY}— scanning {repo_path}{C.RESET}\n")

        total_deducted = 0
        total_max = 0
        all_findings = []

        for label, fn in CHECKS:
            if fn is check_git_history_secrets:
                deducted, max_points, findings = fn(repo_path, args.history_depth)
            else:
                deducted, max_points, findings = fn(repo_path)

            total_deducted += deducted
            total_max += max_points

            status_icon = f"{C.GREEN}✓{C.RESET}" if deducted == 0 else f"{C.RED}✗{C.RESET}"
            print(f"  {status_icon} {label:<38} {C.GRAY}(-{deducted}/{max_points}){C.RESET}")
            for f in findings:
                all_findings.append((label, f))

        score = max(0, 100 - total_deducted)
        letter, color = grade_for(score)

        print(f"\n{C.BOLD}Score: {score}/100   Grade: {color}{letter}{C.RESET}\n")

        if all_findings:
            print(f"{C.BOLD}Findings:{C.RESET}")
            for label, f in all_findings:
                wrapped = textwrap.fill(f, width=90, subsequent_indent="      ")
                print(f"  {C.YELLOW}•{C.RESET} [{label}] {wrapped}")
            print()
        else:
            print(f"{C.GREEN}No issues found. Nicely kept repo.{C.RESET}\n")

        if args.fail_under:
            grades_order = ["F", "D", "C", "B", "A"]
            threshold = args.fail_under.upper()
            if threshold in grades_order and grades_order.index(letter) < grades_order.index(threshold):
                print(f"{C.RED}Grade {letter} is below required {threshold} — failing.{C.RESET}")
                sys.exit(1)

    except subprocess.CalledProcessError:
        print(f"{C.RED}Error: failed to clone repository. Check the URL and try again.{C.RESET}")
        sys.exit(2)
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()