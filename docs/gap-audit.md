# melissacyber deep gap audit (code review, no live test)

Legend: [C]ritical / [H]igh / [M]edium / [L]ow. Each item: what, why it matters, where, suggested fix.

## Correctness / pipeline

1. [C] `--budget` is decorative. `Spend.usd` is never incremented — only token counts are. `Budget::exhausted()` checks `spent_usd` which is always 0. A runaway engagement burns unbounded API spend.
   Fix: price map per provider (models.yaml `cost_in/cost_out` per spec) or fallback token cap; update usd in runner.

2. [C] No per-call timeout / retry on `provider.complete`. A hung or slow API call freezes that solver forever (no wall-clock budget either — `wall_clock_secs` is parsed but unused).
   Fix: `tokio::time::timeout` per call + bounded retries; wire `wall_clock_secs` into engagement.

3. [H] One provider error kills the engagement. `run_engagement` propagates `?` on the first failed call (observed: auth failure at discovery aborted whole run). Per-agent errors should be caught and logged, engagement continues.
   Fix: wrap `run_agent` returns in the spawn closure; record failures, don't `?`.

4. [H] Transcripts die with the run. `AgentOutcome.transcript` is dropped — no trace files, so no debugging, no replay, no SFT data despite the stated flywheel/arena plans.
   Fix: write `artifacts_dir/traces/<agent>.jsonl` per solver.

5. [H] Findings validated sequentially. `handle()` is awaited inline in the intake loop — an SSRF finding costs ~5s of OOB polling, blocking every other validation.
   Fix: spawn validations with a semaphore (e.g. 8 parallel).

6. [H] No finding dedup. The first live run produced 3 near-identical SSRF entries in the report. Fix: dedup key = (class, url-path, param) — collapse to one entry, merge proofs.

7. [H] Evidence schema is undocumented. Solvers guess evidence fields; a correct multi-step chain finding was dropped for `request.url` vs `url` shape. `validator_contract()` must spell out per-class required keys + the replay schema ({request:{method,url,headers,body},expect}).

8. [M] Param-less endpoints get zero solver objectives. `/backup/config.json` (the secret leak) is only useful as a stepping stone — there's no info-disclosure/auth/access class swept on endpoints without params.
   Fix: add an `InfoDisclosure`/`Access` class sweep per endpoint + validators (status-200 sensitive markers).

9. [M] Critic gate is a fragile substring check: `contains("reject") && !contains("pass")` — "not rejectable" kills a real finding, "reject: no" passes. Fix: require exact-first-word `pass`/`reject`, or JSON verdict.

10. [M] Critic is optional but silent — if models.yaml lacks a `critic` role there is no gate at all and nothing tells the user. Log once at startup.

11. [M] Solvers cannot spawn sub-agents: `spawn_agent` roles=["coordinator"] but no coordinator *agent* ever runs (coordinator is code). The spawn channel is dead code in practice. Either give solvers a bounded spawn or remove.

12. [M] `ReplayValidator` replays GET only — POST/body sinks unverifiable. Add `request.method` + `request.body` passthrough in `probe.get2` (needs post support in ProbeClient).

13. [L] `spec_loader` + `agents/*.yaml` are dead code — never consulted anywhere.

## Security / scope

14. [C] RoE is parsed but unenforced. `rate_limit_rps`, `allow_dos`, `allow_exfil`, `allow_bruteforce`, `hitl_required` — none have an effect anywhere. `--hitl` prints a note only.
    Fix: token-bucket limiter on HttpTool + ProbeClient; HITL gate before solver wave when roe.hitl_required.

15. [C] Host backend bypasses app-level scope. `http_client` checks the allowlist, but `terminal` (curl/sqlmap/etc.) goes direct — a solver can reach anything the VM can. Documented "lab only" but the CLI falls back to Host silently when docker fails.
    Fix: on host fallback, wrap commands in a proxy-forcing env (HTTP(S)_PROXY + iptables owner rule) or refuse non-lab targets.

16. [H] OOB server binds 127.0.0.1 only — blind validation (SSRF/XSS/XXE/XXE OOB) cannot work against remote targets. Needs `serve --oob-bind 0.0.0.0` + public base URL config + token-authed hits endpoint.

17. [H] MCP server has no auth and binds 0.0.0.0 — anyone on the LAN can POST /jobs, /results, /mcp (incl. aegis_oob mint and validator probes against the configured allowlist). Fix: bearer token arg + bind 127.0.0.1 default.

18. [M] `aegis worker` is a stub — it "completes" jobs without running anything (posts {"status":"done"}). Misleading; either wire run_agent or mark clearly experimental.

19. [M] Arena is hardcoded: fixed attack strings + fake responder — no LLM policies despite the self-play docs. Either implement provider-driven rounds or rename to `arena --sim`.

## Money / UX / polish

20. [H] Spend shows `~$0.00` forever — no pricing table. Either read cost from gateway response (Experiential returns `cost`) or models.yaml price map.

21. [M] Report omits rejected findings and their reasons — reviewers can't see what was ruled out. Add a "rejected (with reason)" section + counts per class.

22. [M] `discovery_system` asks the model to "infer framework-standard endpoints" — invites endpoint spam (observed: nodes with `url: "?"`). Validate kg endpoint entries (must be parseable URL on an allowed host) before they become tasks.

23. [L] `endpoint_tasks` ignores `NodeKind::Param` nodes and any `method` recorded — POST-only params get GET-tested.

24. [L] `kg_write` provenance always None; duplicate nodes accumulate — merge by (kind,label).

25. [L] Stubs by design but should be tracked: copilot, bench, replay, watch, report subcommand, pack install/new, gVisor/Firecracker backends, TUI/web dashboard.

## Architecture / roadmap

26. [M] Coordinator is deterministic code, not a reasoning agent — no re-planning between waves (findings don't change the frontier mid-run). PAG expected-utility is currently just a prior sort. Next real step: second planning pass after first verified batch.

27. [M] `SpawnRequest` deferred processing caps at 8 and runs sequentially after all solvers — sub-agent results can't influence the engagement meaningfully today.

28. [L] Docker egress proxy is the only network-enforcement path; HostBackend and ProbeClient rely on the app-level allowlist (HTTP only — DNS rebinding / IP-literal tricks possible: Allowlist.matches does literal host compare, no DNS resolution or IP literal normalization; `127.1` or hex IP forms bypass `127.0.0.1` entry).

29. [L] `EgressProxy` — plain-HTTP + CONNECT handling exists but there's no SNI-aware logging; CONNECT to allowed host then arbitrary protocol inside tunnel is uninspected (acceptable but note it).
