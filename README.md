# wizard walks reversly (wwr)

A comprehensive reverse engineering and binary analysis plugin designed for advanced security research, malware analysis, and software protection detection.

## 🚀 Features

- **Automated Triage**: Rapid identification of file formats (PE, ELF, Mach-O), architectures, and bitness.
- **Protection Detection**: Automated scanning for common packers and protectors like **UPX**, **Themida**, **VMProtect**, and more.
- **Entropy Analysis Engine**: Section-by-section entropy calculation to identify packed or encrypted code blocks.
- **Advanced Indicator Extraction**: Intelligent string carving that categorizes IPs, URLs, Registry keys, and potential C2 indicators.
- **Detailed Reporting**: Generates high-fidelity Markdown reports with structured findings and security recommendations.
- **Modular Library Architecture**: Built with extensible Python modules for easy integration and customization.

## 🛠️ Integrated Tools

- **wwr_analyze.py**: The flagship orchestrator for full binary triage.
- **wwr_strings.py**: Specialized indicator extraction tool.
- **wwr_entropy.py**: Visual entropy calculation script.

## 📦 Requirements

To use the full capabilities of WWR, ensure the following Python libraries are installed:

```bash
pip install pefile pyelftools capstone
```

## 📖 Usage

### Automated Analysis
Run the main analyzer against any binary to generate a comprehensive report:

```bash
python tools/wwr_analyze.py <path-to-binary>
```

### Specialized Tools
- **Entropy Check**: `python tools/wwr_entropy.py <path-to-binary>`
- **String Extraction**: `python tools/wwr_strings.py <path-to-binary>`

## 🛡️ Safety & Ethics

WWR is developed for authorized security research and educational purposes only. Always:
- Analyze binaries in isolated sandbox environments.
- Follow ethical disclosure guidelines.
- Respect intellectual property rights.

---
*Developed by Wizard-Walk Reverse Engineering Team.*
