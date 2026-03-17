# Project Obsidian

An intelligent, autonomous security auditing tool that leverages local LLM (Gemma-2b) to perform comprehensive security assessments.

## Features

- 🤖 **AI-Powered Analysis**: Uses local LLM for intelligent decision-making and analysis
- 🛡️ **15+ Security Tools**: Integration with industry-standard security tools
- 🎯 **Dynamic Tool Selection**: AI-driven selection of appropriate tools based on findings
- 📊 **Professional Reports**: Generate beautiful HTML reports with charts and severity ratings
- 💾 **Memory System**: Learns from previous scans to improve future assessments
- 🔒 **100% Local**: No external API calls, all processing done on your machine
- 🚀 **Asynchronous**: Fast parallel execution of tools

## Prerequisites

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.8+
- [llama.cpp](https://github.com/ggerganov/llama.cpp) compiled and in PATH
- Security tools installed (see below)

## Installation

1. **Clone the repository**
```bash
git clone https://github.com/zenix8307-rgb/Project-Obsidian.git
cd ai-security-agent
```
2. **Install dependencies**
```bash
pip install -r requirements.txt
```
3. **Install required security tools**
```bash
# Network scanning
sudo apt install nmap amass whatweb nikto sqlmap wpscan nuclei

# Directory enumeration
sudo apt install gobuster dirsearch ffuf

# OSINT tools
sudo apt install theharvester

# Install sublist3r
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
sudo python setup.py install

# Install searchsploit
sudo apt install exploitdb
```
4. **Download LLM Model**
```bash
# Download Gemma-2b model
wget -O models/Gemma-2b-Uncensored-v1.Q5_K_S.gguf https://huggingface.co/brittlewis12/Gemma-2b-Uncensored-GGUF/resolve/main/Gemma-2b-Uncensored-v1.Q5_K_S.gguf
```
## Basic Commands

- Quick scan
python main.py scan example.com --quick

- Full comprehensive audit
- python main.py full-audit example.com

- Generate report from previous scan
- python main.py report example.com --format html

- List previous scans
- python main.py list

- Check agent status
- python main.py status

## Advanced Options

- Web-focused scan
- python main.py scan example.com --web

- Save results to file
- python main.py scan example.com --output results.json

- Generate PDF report (if PDF support installed)
- python main.py report example.com --format pdf
