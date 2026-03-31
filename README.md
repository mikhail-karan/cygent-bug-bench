# Bug Bench

## Purpose
This repository contains a collection of intentionally vulnerable source files designed for educational and testing purposes. It serves as a resource for developers, security researchers, and students to learn about common vulnerabilities across multiple languages and practice vulnerability detection and analysis.

The project covers **Solidity**, **TypeScript**, **Go**, and **Rust**, each with realistic vulnerability patterns relevant to that language's ecosystem.

The project is designed to be a growing collection of vulnerable code. We plan to continuously add more files with diverse vulnerability types in the future to create a comprehensive benchmark for security tools and training.


## Repository Structure

```
.
├── src/                    # Solidity smart contracts (compiled by Foundry)
│   └── LiquidityPool.sol
├── src-ts/                 # TypeScript source files
│   └── api-handler.ts
├── src-go/                 # Go source files
│   └── server.go
├── src-rust/               # Rust source files
│   └── service.rs
├── test/                   # Foundry test suite for Solidity contracts
├── issues/                 # Vulnerability data and tooling
│   ├── fetch_issues.py
│   ├── requirements.txt
│   ├── issues.json
│   └── findings.json
├── lib/                    # Foundry dependencies
├── foundry.toml
└── README.md
```


## Vulnerability Management

### GitHub Issues as Vulnerability Documentation
All vulnerabilities in this codebase are documented as GitHub issues in this repository. This approach provides:
- Structured vulnerability reports with consistent formatting
- Severity classification using GitHub labels
- Community discussion and feedback capabilities
- Version control for vulnerability discoveries and fixes
- Easy integration with security tools and workflows

### Issues Folder
The `/issues` folder contains tooling for managing vulnerability data:

#### Issue Fetching Script
The `fetch_issues.py` script automatically pulls all open vulnerabilities from the GitHub repository:

```bash
cd issues
python3 -m pip install -r requirements.txt
python3 fetch_issues.py
```

**Features:**
- Fetches all open GitHub issues via API
- Extracts severity levels from issue labels
- Saves clean JSON data with only essential fields (id, title, body, severity, language, file)
- Handles pagination for repositories with many issues
- Filters out pull requests automatically

**Output:** The script generates `issues.json` containing all vulnerability data in a simple array format, making it easy to integrate with security analysis tools or create custom reports.


## Languages and Vulnerability Types

| Language | File | Vulnerabilities |
|----------|------|-----------------|
| Solidity | `src/LiquidityPool.sol` | Reentrancy, share calculation errors, signature replay, access control, griefing, DoS |
| TypeScript | `src-ts/api-handler.ts` | SQL injection, path traversal, JWT algorithm bypass |
| Go | `src-go/server.go` | Command injection, SQL injection, SSRF |
| Rust | `src-rust/service.rs` | SQL injection via `format!`, command injection, weak RNG |


## Educational Use

This repository is designed for:
- Security training and workshops across multiple languages
- Vulnerability research and detection tool testing
- Security tool benchmarking and validation
- Bug bounty preparation and practice
- Academic research in application security
- Developing and testing automated vulnerability scanners

## Future Expansion

We plan to expand this benchmark with:
- Additional vulnerability categories per language
- More languages (Python, Java, C/C++)
- Files of varying complexity levels
- Integration with popular testing frameworks
- Automated vulnerability classification tools

## Contributing

When adding new vulnerabilities:
1. Create a GitHub issue with detailed vulnerability description
2. Use appropriate severity labels (Critical, High, Medium, Low)
3. Include proof of concept and recommended mitigation
4. Follow the established issue template format
5. Add `language` and `file` fields to the issues.json entry

**Warning**: These files contain intentional vulnerabilities and should never be deployed to production or used with real data/funds.
