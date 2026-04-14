# HMAC Key Management

This document describes the lifecycle of cryptographic keys used by LASSO for audit log signing and checkpoint verification.

## Overview

LASSO uses two independent HMAC-SHA256 signing keys:

| Key | Default location | Purpose |
|-----|-----------------|---------|
| Audit signing key | `~/.lasso/.audit_key` (or `<log_dir>/.audit_key`) | Signs audit log entries and maintains the hash chain |
| Checkpoint signing key | `~/.lasso/.checkpoint_key` | Signs checkpoint metadata entries for tamper detection |

Both keys follow the same lifecycle: auto-generated on first use, stored with restricted permissions, and read back on subsequent runs.

> **Co-location note:** The HMAC signing key is stored at `~/.lasso/.audit_key` on the same machine as the audit logs. For compliance environments (DORA, EU AI Act), consider storing the key externally via the `LASSO_AUDIT_KEY` environment variable loaded from a secrets manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault).

---

## Key Generation

**Source:** `lasso/core/audit.py` (`_load_or_create_signing_key`), `lasso/core/checkpoint.py` (`_load_or_create_key`), `lasso/utils/crypto.py` (`generate_key`)

Both keys are generated using Python's `secrets.token_bytes(32)`, which produces 32 bytes (256 bits) of cryptographically secure random data from the operating system's CSPRNG (`/dev/urandom` on Linux, `CryptGenRandom` on Windows).

```python
# From lasso/utils/crypto.py
def generate_key(length: int = 32) -> bytes:
    return secrets.token_bytes(length)

# From lasso/core/audit.py — inline generation
self._signing_key = secrets.token_bytes(32)

# From lasso/core/checkpoint.py — inline generation
key = secrets.token_bytes(32)
```

Keys are raw bytes (not base64 or hex encoded) written directly to disk.

---

## Key Storage

### Audit Signing Key

The audit key location depends on configuration:

1. **If `signing_key_path` is set** in the audit config: the key is stored at that exact path.
2. **If `signing_key_path` is not set** (default): the key is stored alongside the audit logs at `<log_dir>/.audit_key`.

When the key is stored alongside the logs (case 2), LASSO emits a warning:

> Audit signing key stored alongside logs at `<path>`. For tamper-evidence in production, configure `signing_key_path` to an external location.

**Production recommendation:** Always set `signing_key_path` to a location separate from the audit log directory. If the key and logs are on the same filesystem, an attacker with write access to the log directory can also access the key, defeating tamper detection.

### Checkpoint Signing Key

Stored at `~/.lasso/.checkpoint_key`. There is no configuration override for this path -- it always lives in the LASSO state directory.

### File Permissions

Both key files are created with `0o600` (owner read/write only):

```python
os.chmod(str(key_path), 0o600)
```

If `os.chmod` fails (logged as a warning, never crashes), the key file retains the default permissions of the process. This is the expected behavior on Windows -- see the Windows section below.

---

## How Keys Are Used

### Audit Log Signing

The audit signing key is used with HMAC-SHA256 to create a **hash chain** across log entries. Each entry's signature depends on the previous entry's signature, creating a tamper-evident chain. See [audit-tamper-detection.md](audit-tamper-detection.md) for details.

```python
# From lasso/core/audit.py
chain_input = f"{self._chain_hash}:{payload}"
sig = hmac.new(self._signing_key, chain_input.encode(), hashlib.sha256).hexdigest()
self._chain_hash = sig  # becomes input for next entry
```

### Checkpoint Signing

The checkpoint key signs metadata about release checkpoints. The signed payload is `tag:version:released_at`:

```python
# From lasso/core/checkpoint.py
payload = f"{tag}:{version}:{released_at}"
return sign_config(payload, key)  # HMAC-SHA256 via lasso/utils/crypto.py
```

Verification uses constant-time comparison:

```python
# From lasso/utils/crypto.py
def verify_config(config_json: str, signature: str, key: bytes) -> bool:
    expected = hmac.new(key, config_json.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

### Webhook Payload Signing

Webhooks use a separate per-webhook secret (a string, not a key file) configured in the profile. The signing format is:

```python
sig_payload = timestamp + "." + payload
sig = hmac.new(wh.secret.encode(), sig_payload.encode(), hashlib.sha256).hexdigest()
```

The webhook secret is not related to the audit or checkpoint signing keys.

---

## Key Rotation

### Current State

LASSO does **not** currently support automated key rotation. There is no built-in command to rotate keys, and no mechanism to re-sign existing logs with a new key.

### Manual Rotation Procedure

To rotate the audit signing key:

1. **Stop all active sandboxes** to ensure no new entries are being written:
   ```bash
   lasso stop all
   ```

2. **Verify the current audit logs** before rotation (this is your last chance to verify with the old key):
   ```bash
   lasso audit verify /path/to/audit/logs/*.jsonl
   ```

3. **Archive the old key** -- you will need it to verify any logs signed with it:
   ```bash
   cp ~/.lasso/.audit_key ~/.lasso/.audit_key.$(date +%Y%m%d)
   ```

4. **Delete the current key:**
   ```bash
   rm ~/.lasso/.audit_key
   ```

5. **Start a new sandbox.** LASSO will auto-generate a new key on the next sandbox creation.

6. **Verify the new key was created:**
   ```bash
   ls -la ~/.lasso/.audit_key
   ```

To rotate the checkpoint signing key, follow the same procedure with `~/.lasso/.checkpoint_key`. Note that existing checkpoint entries will fail verification with the new key.

---

## Backup and Recovery

### Why Backup Keys

The signing key is required to verify the integrity of audit logs. If the key is lost:

- Existing signed audit logs **cannot be verified** -- the HMAC signatures become uncheckable.
- The log content is still readable (plaintext JSONL), but tamper detection is lost.
- New sandboxes will auto-generate a fresh key, but it will not match old logs.

### Backup Recommendations

1. **Copy the key file** to a secure offline location (encrypted USB, secrets vault):
   ```bash
   cp ~/.lasso/.audit_key /secure/backup/lasso-audit-key-$(date +%Y%m%d)
   cp ~/.lasso/.checkpoint_key /secure/backup/lasso-checkpoint-key-$(date +%Y%m%d)
   ```

2. **Never store the key alongside the audit logs** in your backup. If an attacker gains access to both the logs and the key, they can forge entries.

3. **Document which key corresponds to which time period.** After rotation, label backups with the date range they cover.

4. **For compliance environments**, consider forwarding audit events via webhooks to an external SIEM in real time. This provides an independent record that does not depend on key availability for verification.

---

## Windows Implications

### File Permissions

`os.chmod(path, 0o600)` uses POSIX semantics that may not be enforced on NTFS filesystems. On Windows:

- The `os.chmod` call may succeed silently but have no practical effect on NTFS ACLs.
- The key file may be readable by other users on the same machine.
- LASSO catches `OSError` from `chmod` and logs a warning rather than failing.

### Windows Hardening Recommendations

1. **Use NTFS ACLs** to restrict key file access:
   ```powershell
   icacls "$HOME\.lasso\.audit_key" /inheritance:r /grant:r "$env:USERNAME:(R,W)"
   ```

2. **Store keys in a Windows credential store** or secrets manager rather than flat files on disk.

3. **Encrypt the LASSO state directory** using BitLocker or EFS if the machine is shared.

---

## Key Derivation Details

LASSO does not use key derivation functions (KDF) like PBKDF2, scrypt, or Argon2. Keys are raw random bytes generated by `secrets.token_bytes`, which wraps the OS CSPRNG directly. This is appropriate because:

- Keys are not derived from passwords or passphrases.
- The 256-bit key space provides adequate security for HMAC-SHA256.
- No key stretching is needed since the entropy source is already cryptographically strong.

The signing functions use `hmac.new(key, message, hashlib.sha256)` from Python's standard library, which implements RFC 2104 HMAC.
