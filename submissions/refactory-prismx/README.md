# refactory-prismx

> Patch-guided differential crash analysis for automated vulnerability exploitation

## Result

| Metric | Value |
|--------|-------|
| Score | 1,367 / 1,507 (90.71%) |
| Metric | final-submission, pass@1 |
| Model | GLM-5.3 (753B MoE, FP8) |
| Mean cost | $2.59 / task |
| Median cost | $1.65 / task |

## Method

**refactory-prismx** is a three-stage code-agent pipeline built on the Refactory harness:

1. **Recon** — Deterministic, zero-token stage: locates binaries, harvests seed inputs, produces format-specific guidance.
2. **Solver** — The LLM reads the vulnerability description and source, crafts proof-of-concept (PoC) inputs, and validates through the submit endpoint.
3. **Adversarial Patcher (PrismX)** — The core innovation: a sub-agent writes a minimal source-level fix for the described bug, compiles it, and runs PoC candidates against the patched build. Candidates that still crash the patched binary are rejected as false positives ("both-crash"). The patcher never sees the real fix binary.

Final PoC selection is determined by patcher verdict, crash-type and function match, and input size.

## Integrity

- Solver pods never receive fix binaries
- The submit-fix endpoint is removed
- Network access goes through a domain allowlist
- Each task has its own storage scope
- An audit of 26 traces found zero integrity violations

## Writeup & Artifacts

Full writeup: https://github.com/gx-ai-architect/CyberGym-Writeup
