# 🔍 Blockchain Forensics Agent

> Advanced blockchain analysis platform powered by **MiMo V2.5** — 6 specialized AI agents for comprehensive cryptocurrency investigation.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Tests](https://img.shields.io/badge/Tests-60+-brightgreen.svg)
![LOC](https://img.shields.io/badge/LOC-5000+-orange.svg)
![MiMo](https://img.shields.io/badge/AI-MiMo%20V2.5-purple.svg)

## 🤖 Agents

| Agent | Description |
|-------|-------------|
| **TransactionTracer** | Multi-hop fund tracing across blockchain networks with taint analysis |
| **WalletClusterer** | Entity clustering using co-spending, temporal, and behavioral analysis |
| **AnomalyDetector** | Statistical anomaly detection using Z-score, IQR, and ML-based methods |
| **PatternAnalyzer** | Detects mixing, layering, structuring, round-tripping, and peel chains |
| **ComplianceChecker** | AML/CFT compliance with OFAC, FATF Travel Rule, and sanctions screening |
| **ReportGenerator** | Generates comprehensive forensic reports in multiple formats |

## 🚀 Quick Start

```bash
pip install -e ".[dev]"
pytest tests/ -v
python -m src.main analyze --tx <transaction_hash> --chain bitcoin
```

## 📊 Architecture

```
blockchain-forensics-agent/
├── src/
│   ├── agents/          # 6 specialized AI agents
│   ├── models/          # Data models (Transaction, Wallet, Cluster)
│   ├── utils/           # Blockchain adapters, graph engine, crypto utils
│   ├── config/          # Configuration management
│   └── main.py          # CLI entry point
├── tests/               # 60+ comprehensive tests
└── docs/                # Documentation
```

## 🧪 Testing

```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---
*Powered by MiMo V2.5 — Blockchain Forensics Intelligence*
