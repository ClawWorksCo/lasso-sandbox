# LASSO — Banking Regulatory Compliance: IRB, Basel IV, and IFRS 9

**Document version:** 1.0
**Last updated:** 2026-03-24
**Applicable regulations:** CRR (EU 575/2013), Basel IV (CRR III / EU 2024/1623), IFRS 9 (Financial Instruments)
**Audience:** Model validation teams, internal audit, compliance officers, risk management

---

## Purpose

This document describes how LASSO's audit trail, command-level control, and tamper-evident logging support the execution audit layer required by IRB model validation, Basel IV model governance, and IFRS 9 model documentation. LASSO does not replace a full model validation framework, but provides the sandboxed execution environment and immutable evidence trail that regulators expect when AI agents are used in credit risk modeling workflows.

---

## Scope and Limitations

LASSO provides:
- Tamper-evident audit logs of every command executed by an AI agent
- Identity and timestamp attribution (who ran what, when)
- Cryptographic integrity verification of the audit chain
- Policy-enforced command whitelisting and network isolation
- Reproducible sandbox environments with captured configuration

LASSO does **not** provide:
- Statistical model validation (backtesting, benchmarking, discriminatory power analysis)
- Model performance monitoring or outcome analysis
- Credit risk parameter estimation (PD, LGD, EAD)
- Regulatory capital calculation
- Model inventory or model lifecycle management software

LASSO is the **execution audit layer** — it sits between the AI agent and the operating environment, ensuring every action is recorded, attributable, and verifiable.

---

## 1. IRB Model Validation — CRR Articles 144-145

### 1.1 Background

Under the Internal Ratings-Based (IRB) approach, institutions must demonstrate to competent authorities that their internal models meet rigorous validation standards. CRR Article 144 requires institutions to have robust systems for validating the accuracy and consistency of rating systems. Article 145 requires ongoing monitoring and review.

When AI agents are used in model development, calibration, or validation workflows, the execution environment itself becomes part of the validation evidence. Regulators need to know:

- What data was accessed during model development
- What transformations were applied
- What code was executed and in what order
- Whether the execution environment was controlled and reproducible

### 1.2 How LASSO Supports IRB Validation

| CRR Requirement | Article | LASSO Capability |
|---|---|---|
| Accuracy and consistency of rating systems | Art. 144(1) | Every command executed during model development is logged with HMAC-signed entries, providing an immutable record of the modeling process |
| Regular validation of internal models | Art. 144(1) | Audit logs can be verified independently via `lasso audit verify`, proving no entries were added, removed, or modified after the fact |
| Documentation of model development process | Art. 144(1) | Hash-chained JSONL logs capture the full sequence of commands, arguments, working directories, timestamps, and exit codes |
| Independent review of rating systems | Art. 145 | Audit logs are exportable and verifiable by third parties without access to the original LASSO installation |
| Ongoing monitoring | Art. 145(1) | Webhook integration enables real-time streaming of audit events to SIEM systems for continuous monitoring |

### 1.3 Practical Example: IRB PD Model Development

When an AI agent develops or recalibrates a PD (Probability of Default) model inside a LASSO sandbox:

```
# The agent's execution is fully captured:
{"timestamp": "2026-03-15T09:12:33Z", "event": "command_executed",
 "command": "python3 scripts/pd_calibration.py --dataset Q4_2025",
 "sandbox_id": "irb-pd-model-v3", "user": "model-dev-agent",
 "exit_code": 0, "hmac": "a3f1..."}

{"timestamp": "2026-03-15T09:12:34Z", "event": "command_executed",
 "command": "python3 scripts/backtest.py --model pd_v3.pkl",
 "sandbox_id": "irb-pd-model-v3", "user": "model-dev-agent",
 "exit_code": 0, "prev_hash": "b7e2...", "hmac": "c4d8..."}
```

The hash chain (`prev_hash`) links each entry to its predecessor. Tampering with any entry breaks the chain, which `lasso audit verify` detects.

### 1.4 Validation Evidence Package

For IRB model submission to the competent authority, LASSO audit logs can form part of the evidence package:

1. **Execution log** — the full JSONL audit trail from the model development sandbox
2. **Integrity proof** — output of `lasso audit verify` confirming no tampering
3. **Profile configuration** — the TOML profile used, documenting allowed commands, network policy, and resource limits
4. **Environment snapshot** — the container image and configuration used, ensuring reproducibility

---

## 2. Basel IV / CRR III — Model Risk Management

### 2.1 Background

Basel IV (implemented in the EU as CRR III, effective January 2025) strengthens requirements around model risk management, particularly for institutions using the IRB approach. The EBA Guidelines on model validation (EBA/GL/2017/16) and the ECB Guide to Internal Models require institutions to maintain comprehensive documentation of model development, implementation, and use.

### 2.2 Model Governance: Who Ran What, When, With What Data

LASSO's command-level control directly supports model governance requirements:

| Governance Requirement | LASSO Feature |
|---|---|
| **Separation of duties** | Different profiles can enforce different command sets for development vs. validation agents. A development agent may run training scripts; a validation agent may only run backtesting scripts. |
| **Change control** | Every command is logged with timestamps. Profile versioning (`lasso profile diff`) shows exactly what policy changes were made between model versions. |
| **Access control** | Command whitelisting ensures agents can only execute approved tools. Blocked arguments prevent access to production data paths from development sandboxes. |
| **Data lineage** | Audit logs capture which files were read and written. Combined with filesystem mount configuration, this documents what data the agent could and did access. |
| **Reproducibility** | The sandbox profile, container image, and audit log together define a reproducible execution environment. Another team can recreate the exact conditions. |

### 2.3 Model Risk Management Documentation

The ECB's Targeted Review of Internal Models (TRIM) and EBA guidelines expect documentation covering:

- **Model development documentation** — LASSO audit logs provide the execution history component
- **Model implementation testing** — command logs show exactly what tests were run and their results (exit codes, captured output)
- **Model use documentation** — profiles document the operational constraints under which the model was developed
- **Model change documentation** — profile diffs and sequential audit logs document changes over time

### 2.4 Three Lines of Defense

LASSO supports the three-lines-of-defense model for AI-assisted model development:

| Line | Role | LASSO Support |
|---|---|---|
| **1st line** (model developers) | Build and test models | Sandboxed execution with command whitelisting; development profile |
| **2nd line** (model validation) | Independent review | Read-only access to audit logs; `lasso audit verify` for integrity checking; separate validation profile |
| **3rd line** (internal audit) | Assurance | Tamper-evident logs exportable to audit systems; webhook delivery to SIEM; independent verification without LASSO access |

---

## 3. IFRS 9 — Expected Credit Loss Model Documentation

### 3.1 Background

IFRS 9 requires institutions to estimate expected credit losses (ECL) using forward-looking models. The standard and related audit guidance (ISA 540 Revised) require extensive documentation of significant estimates, including the methods, assumptions, data, and processes used.

### 3.2 Audit Trail for ECL Model Processes

When AI agents assist in ECL model development or recalibration:

| IFRS 9 / ISA 540 Requirement | LASSO Capability |
|---|---|
| Documentation of estimation methods | Audit logs capture the full command sequence used in model estimation |
| Data quality and completeness | Network isolation ensures models are built only against authorized data sources; file access logs document which datasets were used |
| Management review of estimates | Audit logs are immutable evidence of what was actually executed, available for management review |
| Sensitivity analysis | Command logs document which sensitivity scenarios were run and their parameters |
| External auditor review | Tamper-evident logs with independent verification support external audit procedures |

### 3.3 Stage Classification and Provisioning

For IFRS 9 stage classification models (Stage 1/2/3 assessment), LASSO provides:

- **Process documentation**: The exact sequence of commands used to develop or recalibrate staging criteria
- **Significant Increase in Credit Risk (SICR) thresholds**: Logs capture which threshold calibration scripts were run and with what parameters
- **Macro-economic scenario modeling**: Network policy can restrict which external data sources the agent accesses for forward-looking scenarios

---

## 4. Integration with Model Validation Frameworks

### 4.1 Complementary Tools

LASSO is designed to complement, not replace, model validation frameworks. Common integrations:

| Framework Component | Provided By | LASSO's Role |
|---|---|---|
| Model inventory | SAS Model Manager, IBM OpenPages, or internal tools | LASSO sandbox IDs can be mapped to model inventory entries |
| Statistical validation | R, Python (statsmodels, scikit-learn), SAS | LASSO sandboxes the execution of these tools |
| Performance monitoring | Internal dashboards, monitoring systems | LASSO webhook events can feed model performance pipelines |
| Documentation management | Confluence, SharePoint, regulated document systems | LASSO audit logs are exportable artifacts for attachment |
| Regulatory reporting | Internal COREP/FINREP systems | LASSO provides execution evidence for report preparation processes |

### 4.2 Recommended Workflow

1. **Create a dedicated profile** for each model type (PD, LGD, EAD, SICR)
2. **Use strict command whitelisting** — only approved modeling tools and scripts
3. **Disable network access** for model development sandboxes (or whitelist only approved data sources)
4. **Export audit logs** after each model development cycle to the model validation documentation system
5. **Run `lasso audit verify`** as part of the model review process to confirm log integrity
6. **Archive the profile TOML** alongside the model documentation for reproducibility

---

## 5. Regulatory References

| Reference | Description |
|---|---|
| CRR Art. 144 | Use of internal models — general requirements, validation |
| CRR Art. 145 | Ongoing review of internal models |
| CRR Art. 174-191 | IRB approach — PD, LGD, EAD estimation requirements |
| EBA/GL/2017/16 | Guidelines on PD estimation, LGD estimation, treatment of defaulted exposures |
| ECB Guide to Internal Models | TRIM guide — model documentation, governance, validation |
| IFRS 9 (paras 5.5.1-5.5.20) | Expected credit loss measurement |
| ISA 540 (Revised) | Auditing accounting estimates — documentation and evidence requirements |
| BCBS d424 | Basel III: Finalising post-crisis reforms (Basel IV) |
| EBA/GL/2020/06 | Guidelines on ICT and security risk management (complements DORA) |

---

## Disclaimer

This document is provided for informational purposes and does not constitute legal or regulatory advice. Institutions must assess their own compliance obligations with the assistance of qualified legal and compliance professionals. LASSO is a technical tool that provides an execution audit layer; achieving full regulatory compliance requires additional organizational, procedural, and technical controls beyond what any single tool provides.
