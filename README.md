# melissacyber

**Open-source AI cyber harness — autonomous red + blue team in one CLI, with deterministic validation and network-level scope enforcement.**

Built by the **hydralabs deathworks team**.

> Use melissacyber only on systems you own or are explicitly authorized to test.

## What it is

melissacyber (`aegis` CLI) is an agentic security harness: a persistent **coordinator** plans over a probabilistic attack graph and spawns short-lived **solver** agents that attack real targets with real tools — then every claimed finding must pass a **deterministic, non-AI validator** before it reaches your report. Blue-team mode turns verified findings into patches, retests them, and generates + replays detection rules.

Bring your own models: OpenAI, Anthropic, Gemini, OpenRouter, or any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio) — air-gapped included.

```bash
aegis init                       # scope + RoE wizard
aegis run --mode red             # autonomous pentest
aegis run --mode blue            # patch -> retest -> detection -> replay
aegis run --mode purple          # attacker vs defender coevolution
aegis bench --suite cybench      # measure it against public benchmarks
aegis serve --mcp                # expose the harness to other agents
```

## Why it exists

- **Zero false positives**: findings are verified by non-AI validators (canary tokens, OOB interaction, replay) — the XBOW standard, open-sourced.
- **Scope is a network rule, not a prompt**: a default-deny egress proxy enforces your scope at the packet layer.
- **Closed red↔blue loop**: attack → patch → retest → detection rule → replay. Nobody else ships this.
- **Probabilistic attack graph**: the coordinator picks moves by expected utility over a DAG of attack steps, with auditable symbolic paths.
- **Rust core**: single binary, low memory, massively parallel agents. Python lives only in benchmark/ML sidecars.

## Architecture (short)

```
scope.yaml ──► Coordinator (PAG planner)
                    │
   discovery ◄─ knowledge graph ─► solvers (fresh context per task)
                    │                     │
              critic + validators (non-AI code)
                    │
              verified findings ──► blue loop (patch/retest/detect/replay)
                    │
              report: PoC + evidence + SARIF/MD/PDF
```

Full design notes: `docs/` — agent roster (~40 types), tool layers, sandbox profiles (docker / gVisor / Firecracker), domain packs, benchmark methodology.

## Status

Early scaffold (Faz 0/1). See the roadmap in the project board / `docs/`.

## License

Apache-2.0 — see `LICENSE`.
