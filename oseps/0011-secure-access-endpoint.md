---
title: Secure Access on GetEndpoint and Signed Endpoint
authors:
  - "@Pangjiping"
creation-date: 2026-04-19
last-updated: 2026-04-20
status: draft
---

# OSEP-0011: Secure Access on GetEndpoint and Signed Endpoint

## Summary

Optional `secure_access` on sandbox create. **`GetSignedEndpoint(sandboxId, port)`** returns a URL embedding **`short_sig`** (**10** chars total):

1. **`hex8`** — first **8** lowercase **hex** chars of **`SHA256(inner)`** (covers digest’s first 4 bytes).
2. **`signed_key_id`** — **last 2** chars of `short_sig`, **`[0-9a-z]`**, equal to the **`key_id`** of the `secret_bytes` row used for this mint (same as server **`active_key`** when issuing).

**Inputs to `inner` (both are required):**

- **`canonical_bytes`** — UTF-8 of **protocol + `sandbox_id` + `port`** only:

```text
v3\nshort\n{sandbox_id}\n{port}\n
```

- **`secret_bytes`** — raw decoded secret for that **`key_id`** (same row ingress uses to verify).

```text
inner = BE32(len(secret_bytes)) || secret_bytes || BE32(len(canonical_bytes)) || canonical_bytes
digest = SHA256(inner)
hex8 = lowercase_hex(digest)[0:8]
short_sig = hex8 || signed_key_id
```

`BE32` = big-endian uint32 byte length.

**No** `expires`, **no** DNS suffix in canonical, **no** app path/query. Wildcard parent domain is routing-only. Credential is carried via **gateway routing** (below), not query params.

`GetEndpoint` may still return `OPENSANDBOX-SECURE-ACCESS` when enabled (opaque static token; separate from `short_sig`).

## API

- **CreateSandbox:** `secure_access.enabled` (default `false`).
- **GetSignedEndpoint(sandboxId, port):** returns `signed_endpoint` matching `[ingress.gateway].route.mode`, embedding `short_sig`.

## Gateway routing (parse token)

String shape `<sandbox-id>-<port>-<short_sig>`: **split on `-` from the right** — last = `short_sig` (`[0-9a-f]{8}[0-9a-z]{2}`), second-to-last = `port` (`1..65535`, no leading zeros), rest joined = `sandbox_id`. Else **`400`**.

| Mode | Where                                                        |
|------|--------------------------------------------------------------|
| **Wildcard** | Host: `{sandbox_id}-{port}-{short_sig}.<parent-domain>` (parent domain from gateway DNS only; not signed) |
| **Header** | Value only: `{sandbox_id}-{port}-{short_sig}`                |
| **URI** | Path: `/{sandbox_id}/{port}/{short_sig}/` + rest to upstream |

After verify, strip token from host/header/path prefix; forward remaining path + query unchanged.

## Ingress verify

1. Parse `sandbox_id`, `port`, `short_sig` → `hex8`, `signed_key_id`.
2. Load `secret_bytes` for `signed_key_id` from `--secure-access-keys`.
3. Rebuild `canonical_bytes`, compute `hex8`, constant-time compare → **`401`** on fail.

## Config

**Server (`~/.sandbox.toml`):**

```toml
[ingress.secure_access]
enabled = true
active_key = "k1"                    # 2 chars, must exist in keys

[[ingress.secure_access.keys]]
key_id = "k1"
secret = "base64:..."

[[ingress.secure_access.keys]]
key_id = "k0"
secret = "base64:..."
```

Server mints `short_sig` with `secret_bytes` for **`active_key`**.

**Ingress:**

```bash
opensandbox-ingress --secure-access-enabled \
  --secure-access-keys "k1=base64:...,k0=base64:..."
```

## Errors

- **`400`:** bad token shape / port / charset.
- **`401`:** bad `hex8` or unknown `signed_key_id`.
- **GetSignedEndpoint:** `404` / `403` when sandbox missing or secure access off.

## Tests

- Unit: `inner` / `hex8`, right-split with hyphens in `sandbox_id`.
- Integration: three route modes + one tampered hex → `401`.
