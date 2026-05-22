# Argala

Argala is a developer-first, high-performance, deterministic reverse proxy middleware that sits inline with an agent's tool-execution loop. It strips safety away from the unstable LLM context layer and moves it into an un-bypassable, compiled execution boundary.

## Overview

When developers give an LLM agent live tools (such as database connections, payment gateways, or shell access), they rely on system prompts to keep it safe (e.g., "You are a safe assistant, never delete tables"). However, system prompts are probabilistic suggestions, not deterministic rules. AI agents encounter execution errors, try to resolve them autonomously, hallucinate, and frequently bypass their own safety logic to be "helpful."

Argala solves this by intercepting tool calls before they reach the execution layer and evaluating them against a deterministic security policy.

## Architecture

```
APPLICATION LAYER (Python: CrewAI / LangChain Core)
  - Single line initialization: protect_tools()
                           │
 (Zero-copy memory bridge via PyO3)
                           ▼
                    PYO3 BINDING LAYER
                           │
                           ▼
  RUST RUNTIME ENGINE
  - High-throughput pattern matching & string analysis
  - Policy evaluation against local policy configuration
```

## Installation

```bash
pip install argala-guard
```

## Usage

```python
from argala import ArgalaEngine, protect_tools

# Define your tools
def execute_sql_query(query_string: str):
    return f"Executed: {query_string}"

# Define security policy
policy = {
    "allowed_methods": ["execute_sql_query"],
    "denied_patterns": ["DROP", "DELETE", "TRUNCATE"]
}

# Protect your tools
protected_tools = protect_tools([execute_sql_query], policy)

# Use protected tools
# protected_tools[0]("SELECT * FROM users")  # OK
# protected_tools[0]("DROP TABLE users")     # Blocked

# Or build the engine directly from TOML policy file
engine = ArgalaEngine.from_policy_file("argala_policy.toml")
# engine.inspect_payload("execute_sql_query", ("SELECT 1",))  # True
```

## Configuration

The security policy can be defined:
- directly in a Python dictionary with:
- `allowed_methods`: List of allowed method names
- `denied_patterns`: List of patterns to block (case-insensitive substring matching)
- or in `argala_policy.toml` (sample provided in this repository)

## Development

To develop locally:

1. Install Rust and Python development tools
2. Install maturin: `pip install maturin`
3. Build in development mode: `maturin develop`
4. Run tests: `pytest test_argala_blocking.py`

### Troubleshooting Python 3.13 / PyO3 version mismatch

If `maturin develop` reports `pyo3-ffi v0.20.3` and says Python 3.13 is newer than supported:
- ensure `Cargo.toml` uses `pyo3 = "0.22.6"` or newer,
- and refresh your lock/dependency resolution:
  - `cargo update -p pyo3 -p pyo3-ffi -p pyo3-build-config`
  - then rerun `maturin develop`.

## License

Apache License 2.0