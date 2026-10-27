# Recon Agent (LangGraph + DeepSeek)

An autonomous reconnaissance agent for **authorised** security testing. Given one
or more in-scope targets, it resolves hosts, enumerates subdomains, port-scans,
probes web services, and writes a markdown report — deciding for itself which
tool to call next in a LangGraph ReAct loop.

Built to demonstrate: **agent frameworks (LangGraph), tool calling, multi-step
workflows, and API integration.**

## Why it's safe by design

Every tool calls a `ScopeGuard` before touching the network. A target is only in
scope if it matches a rule you wrote in `scope.yaml`. Target strings are also
sanitised (no shell metacharacters) and every subprocess is called with an
argument list — never a shell string — so a target can't smuggle in extra
commands. If the model ever tries an out-of-scope host, the tool refuses, and the
model is told why.

> Only test systems you own or have **written permission** to test.

## Architecture

```
          ┌─────────┐   tool calls?    ┌────────┐
  task ──▶│  agent  │────────yes──────▶│  tools │
          │ (LLM)   │◀────results──────│        │
          └────┬────┘                  └────────┘
               │ no more calls
               ▼
          summary ──▶ markdown report
```

- `scope.py` — scope model + `ScopeGuard` (the safety core)
- `tools.py` — `resolve_host`, `enumerate_subdomains`, `port_scan`, `http_probe`
- `graph.py` — the LangGraph agent loop
- `llm.py` — DeepSeek via the OpenAI-compatible API
- `report.py` — assembles the markdown report (summary + auditable raw output)
- `cli.py` — command-line entry point

Tools degrade gracefully: if `nmap` or `subfinder` aren't installed, a built-in
connect scan and crt.sh certificate-transparency lookup stand in, so the project
runs anywhere and shines on a Kali box.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env        # add your DeepSeek API key
```

## Usage

1. Edit `scope.yaml` to list only targets you're authorised to test.
2. Run:

```bash
python -m recon_agent.cli --scope scope.yaml --target example.com -o report.md
```

Multiple targets:

```bash
python -m recon_agent.cli --scope scope.yaml \
    --target example.com --target 10.10.10.5 -o report.md
```

The agent refuses to start if any `--target` is outside `scope.yaml`.

### Offline mode (no API key)

Pass `--offline` to drive the loop with a built-in scripted model instead of
DeepSeek — it resolves, port-scans and HTTP-probes each target, then writes the
report. The tools still run for real, but no key or API call is made:

```bash
python -m recon_agent.cli --scope scope.yaml --target 127.0.0.1 --offline
```

Handy for trying the agent, demos, and CI. Point it at in-scope loopback or
RFC-1918 hosts to keep all traffic on your own network.

## Tests

```bash
pytest
```

The suite runs fully offline — scope logic, tool guards, and the complete
agent loop are tested with a scripted fake model, so no API key is needed.

The DeepSeek client (`langchain-openai`) is imported lazily, only when the live
model is actually built. So offline use — the tests, or driving the agent with
your own `llm=...` — needs just `langgraph`, `langchain-core`, `pyyaml`, and
`httpx`; `langchain-openai` is pulled in only when you talk to DeepSeek.

## Tech

Python · LangGraph · LangChain · DeepSeek (OpenAI-compatible API) · httpx · nmap · subfinder
