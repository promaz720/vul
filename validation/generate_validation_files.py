#!/usr/bin/env python3
"""Generate per-finding validation files from a vulnerability report or by running the scanner.

Usage:
  python generate_validation_files.py --url https://example.com
  python generate_validation_files.py --report report.json

This script will create a timestamped folder under `validation_output/` containing
one markdown file per finding and simple PoC artifacts for XSS/CSRF/SQLi where applicable.
"""
import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

# allow importing the scanner module from parent folder
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from vul import vulnerability_scanner as vs_mod


def sanitize_filename(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in (' ', '-', '_')).rstrip().replace(' ', '_')


def write_markdown(out_dir: Path, finding: dict, index: int):
    title = finding.get('title', f'finding_{index}')
    filename = sanitize_filename(f"{index:02d}_{title}") + '.md'
    file_path = out_dir / filename

    with file_path.open('w', encoding='utf-8') as fh:
        fh.write(f"# {title}\n\n")
        fh.write(f"**Severity:** {finding.get('severity', 'info').upper()}\n\n")
        fh.write(f"**Category:** {finding.get('category','')}\n\n")
        fh.write("## Description\n\n")
        fh.write(f"{finding.get('description','')}\n\n")
        proof = finding.get('proof') or finding.get('poc') or finding.get('exploitation_method')
        if proof:
            fh.write("## Proof of Concept\n\n")
            fh.write("```\n")
            fh.write(str(proof))
            fh.write("\n```\n\n")

        fh.write("## Remediation\n\n")
        fh.write(f"{finding.get('remediation','')}\n")

    return file_path


def write_poc_artifacts(out_dir: Path, finding: dict, index: int):
    """Create simple PoC artifacts for common issues (XSS, CSRF, SQLi)."""
    artifacts = []
    sev = finding.get('severity', '').lower()
    title = sanitize_filename(f"{index:02d}_{finding.get('title','')}")

    # XSS/CSRF: generate simple HTML PoC page
    if finding.get('type') in ('xss',) or 'cross-site scripting' in finding.get('category','').lower() or 'csrf' in finding.get('title','').lower():
        html_name = out_dir / f"{title}.html"
        poc = finding.get('proof') or finding.get('poc') or finding.get('exploitation_method') or "<script>alert('POC')</script>"
        with html_name.open('w', encoding='utf-8') as fh:
            fh.write("<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>PoC</title></head><body>\n")
            # if proof appears to be a fenced block, strip fences
            if isinstance(poc, str) and poc.strip().startswith('```'):
                stripped = '\n'.join(line for line in poc.splitlines() if not line.strip().startswith('```'))
                fh.write(stripped)
            else:
                fh.write(str(poc))
            fh.write("\n</body></html>")
        artifacts.append(html_name)

    # SQLi: create a curl command file
    if finding.get('type') in ('sqli',) or 'sql injection' in finding.get('category','').lower():
        sh_name = out_dir / f"{title}_poc.sh"
        input_name = 'INPUT_NAME'
        # try to extract input name from description
        desc = finding.get('description','')
        m = None
        try:
            import re
            m = re.search(r"Input Name:\s*(\w+)", desc)
            if m:
                input_name = m.group(1)
        except Exception:
            pass

        cmd = f"curl -X POST \"TARGET_URL\" -d \"{input_name}=' OR '1'='1\""
        with sh_name.open('w', encoding='utf-8') as fh:
            fh.write('#!/bin/sh\n')
            fh.write('# Basic SQLi PoC (replace TARGET_URL)\n')
            fh.write(cmd + '\n')
        artifacts.append(sh_name)

    # For information leaks, dump example extracted data into a text file
    if finding.get('type') in ('info_leak',) or 'information disclosure' in finding.get('category','').lower():
        txt_name = out_dir / f"{title}_data.txt"
        # try to parse emails from description
        desc = finding.get('description','')
        with txt_name.open('w', encoding='utf-8') as fh:
            fh.write(desc + '\n')
        artifacts.append(txt_name)

    return artifacts


def generate_from_report(report: dict, out_base: Path):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_dir = out_base / f"validation_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = report.get('findings', [])
    created = []
    for i, f in enumerate(findings, 1):
        md = write_markdown(out_dir, f, i)
        arts = write_poc_artifacts(out_dir, f, i)
        created.append({'markdown': str(md), 'artifacts': [str(a) for a in arts]})

    # dump an index file
    index_path = out_dir / 'index.json'
    with index_path.open('w', encoding='utf-8') as fh:
        json.dump({'created': created, 'report_summary': {'title': report.get('title'), 'total': len(findings)}}, fh, indent=2)

    print(f"Validation files written to: {out_dir}")
    return out_dir


def main():
    parser = argparse.ArgumentParser(description='Generate validation files from scanner report or by running scanner')
    parser.add_argument('--url', help='Run scanner against URL and generate files')
    parser.add_argument('--report', help='Path to saved report JSON')
    parser.add_argument('--out', help='Output base directory', default=str(Path(__file__).resolve().parents[1] / 'validation_output'))

    args = parser.parse_args()

    out_base = Path(args.out)
    out_base.mkdir(parents=True, exist_ok=True)

    report = None
    if args.report:
        with open(args.report, 'r', encoding='utf-8') as fh:
            report = json.load(fh)
    elif args.url:
        scanner = vs_mod.WebsiteVulnerabilityScanner()
        # When running from CLI we don't have a Streamlit UI; silence Streamlit calls to avoid errors
        try:
            import streamlit as _st
            for fn in ('info', 'error', 'success', 'markdown', 'progress', 'empty', 'header', 'write'):
                if hasattr(_st, fn):
                    setattr(_st, fn, lambda *a, **k: None)
        except Exception:
            # if streamlit isn't available or monkey-patching fails, continue anyway
            pass

        print(f"Running scan for {args.url} (this may take a while...)")
        scanner.scan_website(args.url)
        report = scanner.generate_hackerone_report()
        # convert to pure serializable dict if needed
    else:
        parser.error('Either --url or --report must be provided')

    if not report:
        print('No report to process')
        return

    # ensure findings include 'proof' (in case it was generated externally)
    for f in report.get('findings', []):
        if 'proof' not in f:
            # try to extract using scanner helper
            try:
                f['proof'] = vs_mod.WebsiteVulnerabilityScanner()._extract_proof_from_finding(f)
            except Exception:
                f['proof'] = None

    generate_from_report(report, out_base)


if __name__ == '__main__':
    main()
