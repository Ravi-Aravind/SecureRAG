# NLI E2E Preflight Report

**Run ID**: `efb02252-fc4e-4696-91f9-9d2d65c74d58`
**CVE**: `CVE-2022-29225`

**EXECUTION ERROR**: Exception: OPENROUTER_API_KEY environment variable is missing. Please set it in your environment before running.

## Evidence Filtering
- **C_min**: 0
- **Retained Documents**: CVE-2022-29225_orig
- **Filtered Documents**: CVE-2022-23913_orig, CVE-2022-4800_orig, CVE-2023-21927_orig, CVE-2024-53984_orig

## LLM Execution
- **Model**: openai/gpt-4o-mini
- **Latency**: 0.00 seconds

### Prompt Context
```text
Context documents:
CVE-2022-29225 envoy envoyproxy
Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 secompressors accumulate decompressed data into an intermediate buffer before overwriting the body in the decode/encodeBody. This may allow an attacker to zip bomb the decompressor by sending a small highly compressed payload. Maliciously constructed zip files may exhaust system memory and cause a denial of service. Users are advised to upgrade. Users unable to upgrade may consider disabling decompression.

Question:
Is envoy version CVE-2022-29225 affected by 1.22.1?

Answer with the exact version boundary. If documents conflict, report both and note the conflict.
```

### Raw Response
```text

```

## Frozen Classifier Results
- **Final Classification**: error
- **Security Consequence**: error

Zero files outside of phase1 were modified.
