# Audit Log Tamper Detection

This document describes how LASSO's audit log integrity mechanism works, what it protects against, what it does not protect against, and how to verify logs.

## How the HMAC Hash Chain Works

**Source:** `lasso/core/audit.py` (signing), `lasso/core/audit_verify.py` (verification)

Every audit log entry is signed with HMAC-SHA256, and each signature depends on the previous entry's signature, forming a **hash chain**. This means modifying, reordering, or inserting any entry invalidates all subsequent signatures.

### Chain Construction

1. The chain starts with a seed value of `"0" * 64` (64 ASCII zeros).

2. For each event, the logger serializes the event to JSON (compact format, sorted keys, no signature field):
   ```
   payload = JSON(event without "sig" field)
   ```

3. The chain input combines the previous hash with the current payload:
   ```
   chain_input = f"{previous_chain_hash}:{payload}"
   ```

4. The signature is computed:
   ```
   sig = HMAC-SHA256(signing_key, chain_input)
   ```

5. The signature is stored in the `"sig"` field of the JSON entry and written to the log.

6. The signature becomes the `previous_chain_hash` for the next entry.

### Example Chain

```
Entry 1:  sig_1 = HMAC(key, "000...000:{payload_1}")
Entry 2:  sig_2 = HMAC(key, "sig_1:{payload_2}")
Entry 3:  sig_3 = HMAC(key, "sig_2:{payload_3}")
```

### Log Rotation and Cross-File Linking

When a log file exceeds the configured maximum size, LASSO rotates it:

1. The current file is renamed (e.g., `log.jsonl` becomes `log.jsonl.1`).
2. A new file is created with the chain reset to `"0" * 64`.
3. The **first entry** in the new file is a `lifecycle/log_rotated` event containing:
   - `previous_log_file`: path to the rotated file
   - `previous_chain_hash`: the final chain hash from the previous file
   - `rotation_marker: true`

This allows the `verify_chain()` function to verify a sequence of rotated files as a single continuous chain.

---

## What Tamper Detection Protects Against

### Modification of Entries

If any field in any entry is changed (timestamp, action, outcome, etc.), the computed signature for that entry will not match the stored signature. Because subsequent entries depend on the previous signature, all entries after the modification also fail verification.

**Example:** An attacker changes the outcome of entry 5 from `"blocked"` to `"success"`. The verifier detects a signature mismatch at entry 5 and reports it.

### Reordering of Entries

Each entry's signature depends on the previous entry's signature. Swapping two entries breaks the chain at the first swapped position, because the chain input no longer matches what was originally signed.

### Insertion of Entries

Inserting a new entry between existing entries breaks the chain. The inserted entry would need a valid signature computed from the previous entry's hash, which requires the signing key. Even with the key, the entry following the insertion would have a mismatched chain input.

### Modification of Signatures

Replacing a signature with a different value breaks the chain for all subsequent entries, because they depend on the previous signature as chain input.

---

## What Tamper Detection Does NOT Protect Against

### Deletion of the Entire Log

If an attacker deletes the entire audit log file, there is nothing to verify. The HMAC chain only protects the integrity of entries that exist -- it cannot prove that entries are missing if the entire file is gone.

### Truncation from the End

An attacker with access to the log file can remove entries from the end. The remaining entries will still form a valid chain. The verifier cannot detect that entries were removed unless it has an independent record of the expected entry count or the final chain hash.

### Key Compromise

If the attacker obtains the signing key (`~/.lasso/.audit_key`), they can forge valid signatures for arbitrary entries. The HMAC chain provides no protection when the key is compromised.

**Mitigation:** Store the signing key on a different filesystem from the audit logs. Configure `signing_key_path` in the audit config to point to a secure, access-controlled location.

### Replacement of Both Log and Key

An attacker with access to both the log directory and the key file can regenerate the entire log with a new key, or forge entries with the existing key. This is indistinguishable from a legitimate log.

### Deletion of Individual Entries (with key access)

With the signing key, an attacker can remove an entry and re-sign all subsequent entries to maintain a valid chain.

---

## Primary Tamper-Resistance Recommendation

The local HMAC chain provides a useful integrity check for detecting accidental corruption and opportunistic tampering. However, for environments where audit log integrity is critical (compliance, regulated industries, incident forensics), **do not rely solely on local HMAC signing**.

### Use Webhooks to Forward Events to an External SIEM

Configure webhook dispatch to send audit events in real time to a system outside the LASSO host:

```toml
[[webhooks]]
url = "https://siem.internal.example.com/api/lasso-events"
secret = "your-webhook-hmac-secret"
events = ["command", "lifecycle", "violation", "file", "network"]
enabled = true
```

Benefits:
- Events are stored on a separate system that the sandbox host cannot modify.
- The external system maintains its own timeline, making truncation and deletion detectable.
- Webhook payloads are independently HMAC-signed (using the webhook secret, separate from the audit key).
- Delivery includes unique IDs (`X-Lasso-Delivery`) and timestamps (`X-Lasso-Timestamp`) for correlation.

### Use Syslog Forwarding

For organizations with existing syslog infrastructure:

```toml
[audit]
syslog_address = "tcp://siem.internal.example.com:514"
syslog_facility = "auth"
```

Syslog forwarding sends each audit entry as a structured message to the configured endpoint. Supports Unix sockets, UDP, and TCP.

### Other External Verification Approaches

- **Append audit log hashes to a blockchain or transparency log** periodically.
- **Replicate the signing key to an HSM** and verify signatures from a separate host.
- **Use immutable storage** (e.g., WORM-mode S3 buckets) for archived audit logs.

---

## Verification

### Single File Verification

```bash
lasso audit verify /path/to/audit-log.jsonl
```

This command:
1. Locates the signing key (looks for `.audit_key` in the same directory as the log, or uses `--key-path` if specified).
2. Reads each JSONL entry.
3. Reconstructs the payload without the `"sig"` field.
4. Recomputes the HMAC chain from the seed value.
5. Compares each computed signature against the stored signature using constant-time comparison (`hmac.compare_digest`).

**Output includes:**
- Total entries examined
- Number of verified entries
- Line number of first chain break (if any)
- Specific error messages for each failure
- Final chain hash (useful for cross-file verification)

### Multi-File Verification (Rotated Logs)

The `verify_chain()` function in `lasso/core/audit_verify.py` accepts a list of log files in chronological order and verifies:

1. Each file's internal HMAC chain independently.
2. The cross-file linkage: the `previous_chain_hash` in each file's rotation marker must match the final chain hash of the preceding file.

### Verification Output

The `VerificationResult` dataclass contains:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | True only if all entries verified and no errors |
| `total_entries` | `int` | Number of entries examined |
| `verified_entries` | `int` | Number that passed HMAC check |
| `first_break_at` | `int or None` | Line number of first failure |
| `errors` | `list[str]` | Detailed error messages |
| `final_chain_hash` | `str` | Chain hash after last entry |

### Programmatic Verification

```python
from lasso.core.audit_verify import verify_audit_log, verify_chain

# Single file
result = verify_audit_log("audit/sandbox_abc_20260324T120000Z.jsonl")
if not result.valid:
    print(f"Chain broken at line {result.first_break_at}")
    for err in result.errors:
        print(f"  {err}")

# Multiple rotated files (oldest first)
result = verify_chain([
    "audit/sandbox_abc_20260324T120000Z.jsonl.3",
    "audit/sandbox_abc_20260324T120000Z.jsonl.2",
    "audit/sandbox_abc_20260324T120000Z.jsonl.1",
    "audit/sandbox_abc_20260324T120000Z.jsonl",
])
```

---

## Unsigned Entries

If `sign_entries` is set to `false` in the audit configuration, entries are written without the `"sig"` field. The verifier reports each unsigned entry as an error (`"no signature found"`). An unsigned log provides no tamper detection -- it is a plain append-only JSONL file.
