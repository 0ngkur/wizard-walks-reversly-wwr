import os
import sys
import json
import argparse
from datetime import datetime

# Add lib to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from lib.file_formats.pe_parser import PEParser
from lib.file_formats.elf_parser import ELFParser
from lib.protections.signatures import scan_binary
from tools.wwr_strings import extract_strings, find_interesting
from tools.wwr_entropy import calculate_entropy

class WWRAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.report = []

    def log(self, text):
        self.report.append(text)

    def analyze(self):
        if not os.path.exists(self.file_path):
            return f"Error: File {self.file_path} not found."

        filename = os.path.basename(self.file_path)
        self.log(f"# WWR Analysis Report: {filename}")
        self.log(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 1. Basic File Info & Format Detection
        self.log("## 1. Executive Summary")
        file_size = os.path.getsize(self.file_path)
        
        # Detection logic
        fmt = "Unknown"
        with open(self.file_path, 'rb') as f:
            header = f.read(4)
            if header.startswith(b'MZ'):
                fmt = "PE (Windows Executable)"
            elif header.startswith(b'\x7fELF'):
                fmt = "ELF (Linux Executable)"
            elif header.startswith(b'\xca\xfe\xba\xbe') or header.startswith(b'\xce\xfa\xed\xfe') or header.startswith(b'\xcf\xfa\xed\xfe'):
                fmt = "Mach-O (macOS Executable)"

        self.log(f"- **File Format**: {fmt}")
        self.log(f"- **Size**: {file_size} bytes")
        
        # Entropy
        with open(self.file_path, 'rb') as f:
            data = f.read()
            entropy = calculate_entropy(data)
        
        self.log(f"- **Overall Entropy**: {entropy:.4f}")
        if entropy > 7.0:
            self.log("- **Status**: > [!WARNING]\n> High entropy detected. File is likely PACKED or ENCRYPTED.")
        else:
            self.log("- **Status**: File appears consistent with standard code/data ratios.")

        # 2. Signature Scanning
        self.log("\n## 2. Protection & Compiler Analysis")
        sigs = scan_binary(self.file_path)
        if sigs:
            for sig in sigs:
                self.log(f"- **Detected**: {sig['name']} ({sig['type']})")
                self.log(f"  - *Description*: {sig['description']}")
        else:
            self.log("No known packer or compiler signatures detected.")

        # 3. Format Specific Details
        if fmt == "PE (Windows Executable)":
            self.analyze_pe()
        elif fmt == "ELF (Linux Executable)":
            self.analyze_elf()

        # 4. String Analysis
        self.log("\n## 4. Indicators of Interest (Strings)")
        all_strs = extract_strings(self.file_path)
        interesting = find_interesting(all_strs)
        
        found_any = False
        for category, items in interesting.items():
            if items:
                found_any = True
                self.log(f"### {category}")
                for item in items[:15]:
                    self.log(f"- `{item}`")
                if len(items) > 15:
                    self.log(f"- ... and {len(items)-15} more")
        
        if not found_any:
            self.log("No specific indicators (IPs, URLs, etc.) found in strings.")

        self.log("\n---\n*WWR Analysis Completed.*")
        return "\n".join(self.report)

    def analyze_pe(self):
        self.log("\n## 3. PE Header Analysis")
        parser = PEParser(self.file_path)
        info = parser.get_basic_info()
        if "error" in info:
            self.log(f"Error parsing PE: {info['error']}")
            return

        self.log(f"- **Entry Point**: `{info['entry_point']}`")
        self.log(f"- **Image Base**: `{info['image_base']}`")
        self.log(f"- **Sections**: {info['number_of_sections']}")
        
        self.log("\n### Sections Map")
        self.log("| Name | Virtual Address | Virtual Size | Raw Size | Entropy |")
        self.log("|------|-----------------|--------------|----------|---------|")
        for s in parser.get_sections():
            self.log(f"| {s['name']} | {s['virtual_address']} | {s['virtual_size']} | {s['raw_size']} | {s['entropy']:.2f} |")

        self.log("\n### Key Imports (Top 10)")
        imports = parser.get_imports()
        count = 0
        for dll, funcs in imports.items():
            self.log(f"- **{dll}**")
            for f in funcs[:5]:
                self.log(f"  - `{f['name']}`")
            count += 1
            if count > 10: break

    def analyze_elf(self):
        self.log("\n## 3. ELF Header Analysis")
        parser = ELFParser(self.file_path)
        info = parser.get_basic_info()
        if "error" in info:
            self.log(f"Error parsing ELF: {info['error']}")
            return

        self.log(f"- **Architecture**: {info['architecture']}")
        self.log(f"- **Bitness**: {info['bitness']}")
        self.log(f"- **Entry Point**: `{info['entry_point']}`")
        
        self.log("\n### Sections Map")
        self.log("| Name | Address | Size | Entropy |")
        self.log("|------|---------|------|---------|")
        for s in parser.get_sections():
            self.log(f"| {s['name']} | {s['address']} | {s['size']} | {s['entropy']:.2f} |")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WWR Flagship Binary Analyzer")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("--output", help="Optional path to save MD report")
    args = parser.parse_args()
    
    analyzer = WWRAnalyzer(args.file)
    result = analyzer.analyze()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(result)
        print(f"Report saved to {args.output}")
    else:
        print(result)
