# CyberGym Submission Guidelines (2026-07-08)

The most capable models under unconstrained resources have nearly saturated the benchmark. Because vulnerability discovery is a real-world, cost-sensitive task, we believe efficiency now matters as much as raw success rate. To make the best use of the benchmark, future submissions are required to report cost alongside success rate.
All reported costs are estimates and should be used carefully for comparison, as they may be affected by factors such as network conditions, throughput, tokenizer differences, and implementation details.

A submission must include the following:

## 1. Report

Submit a structured report by [email](mailto:zhun.wang@berkeley.edu) or GitHub issue along with your results and artifacts.
To better show your result on the plot, please also submit an icon for your system.

### Schema

| Field | Description |
|-------|-------------|
| `agent_name` | Name/version of the agent scaffold. |
| `success_rate` | Fraction of tasks solved under the final-submission metric (see [FAQ](FAQ.md)). |
| `link` | URL of the public writeup, paper, or blog post. |
| `category` | The evaluation can be either model- or agent-focused; by model-focused, we mean it is designed to evaluate the model's underlying capability without relying on specialized agent design. |
| `models[]` | One entry per model the agent invoked (main loop, sub-agents, judges, etc.). |
| `models[].name` | Model identifier. |
| `models[].input_tokens` | Avg non-cached input tokens per task. |
| `models[].cache_read_tokens` | Avg cached-read (prompt-cache hit) input tokens per task; `0` if not applicable. |
| `models[].cache_creation_tokens` | Avg cache-creation (prompt-cache write) tokens per task; `0` if not applicable. |
| `models[].output_tokens` | Avg output tokens per task. |
| `models[].est_usd_cost` | *(Optional)* Avg estimated USD cost per task. `null` for models that are not publicly priced or are served locally. |
| `models[].time_cost_sec` | Avg wall-clock time per task, in seconds. |
| `models[].llm_requests` | Avg number of model requests per task. |

### YAML template

```yaml
agent_name: my-agent
success_rate: 0.40
link: https://example.com/writeup
category: model
models:
  - name: claude-opus-4-8
    input_tokens: 120000
    cache_read_tokens: 480000
    cache_creation_tokens: 90000
    output_tokens: 35000
    est_usd_cost: 4.75
    time_cost_sec: 620
    llm_requests: 42
```

## 2. Artifacts

Include example trajectories, logs, and PoC submissions for at least 10 tasks so we can review the agent's behavior, along with the detailed success/failure status for each instance. We also encourage including these artifacts in the public writeup.

## 3. Detailed writeup

Explain the approach and the full experimental setting (agent scaffold, tools, whether network access was enabled, whether a dynamic environment was provided, etc.; see the [FAQ](FAQ.md)).
