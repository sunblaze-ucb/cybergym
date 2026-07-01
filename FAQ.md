# CyberGym FAQ

**Q1. Can the agent have network access during a task?**

Network access must be treated carefully. It is *not* required to solve tasks, and enabling it opens the door to reward hacking. If you enable network access:
- Explicitly state it in your writeup, along with what was reachable (e.g. an open allowlist vs. a restricted proxy).
- Inspect the agent trajectories to confirm the agent did not shortcut the task — for example by directly searching for the answer in the target project's issue tracker / bug reports, or by reading the project's changelogs, commit history, or release notes to locate the patched commit.

We recommend restricting egress with the built-in domain-allowlist proxy (see the Firewall section in the [README](README.md#firewall-restrict-agent-internet-access)) so that only controlled domains are reachable. But even with a proxy, the agent may still be able to perform web searches such as using web search models, embedding the url in the model requests, etc. If you allow network access, you should carefully analyze the agent's trajectory to ensure it did not shortcut the task by reading the patch or PoC from the web.

**Q2. Does the agent get access to both the pre-patch (vulnerable) and post-patch (patched) versions?**

No. The task provides only the pre-patch (vulnerable) program (`repo-vul.tar.gz`). During runtime the agent must not have access to the post-patch (patched, `-fix`) image.
Only the submission server uses the `-fix` image, and only to verify that the final PoC crashes the vulnerable build but no longer crashes the patched build.
The agent is expected to reason about which PoC best matches the described vulnerability.

**Q3. How should I interpret the outcome / count a success?**

An agent may submit multiple PoCs during a task. There are two ways to score:
- **Any-of**: the task is solved if any submitted PoC succeeds.
- **Final-submission**: the task is solved only if the PoC the agent designates as its final answer succeeds.

In our initial evaluation the gap between these two was small.
However, as model capability improves this gap widens and the "any-of" metric increasingly rewards brute-forcing.
To keep results clear and comparable, **you should ask the agent to pick exactly one submission as its final answer** and report the final-submission metric.

**Q4. How do I set up a dynamic-analysis environment for the agent?**

If you want the agent to perform dynamic analysis (running/fuzzing/debugging the target), you can give it the vulnerable images directly (`n132/arvo:<id>-vul`, `cybergym/oss-fuzz:<id>-vul`).
If you do this:
- **Explicitly mention it in your writeup**, since a runnable environment changes task settings.
- **Remove sources of leakage before handing the container to the agent**, to avoid reward hacking, in particular, `/src/**/.git` and `/tmp/poc`, which are the git history and the reference PoC, respectively.
