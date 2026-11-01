# Dependencies and attribution

This inventory describes the direct packages declared by TRACE, with license identifiers read from installed package metadata on 1 November 2026. It is an engineering inventory, not a legal opinion or a claim that all transitive dependencies use the same license.

## Python runtime

Versions are pinned in [`pyproject.toml`](../pyproject.toml) and [`requirements.txt`](../requirements.txt).

| Package | Version | Role | Declared upstream license |
|---|---|---|---|
| [DuckDB](https://duckdb.org/) | 2.0.0 | Analytical SQL, Parquet and bounded database execution | MIT |
| [PyYAML](https://pyyaml.org/) | 6.0.3 | Runtime settings, ATT&CK mapping and Sigma YAML | MIT |
| [FastAPI](https://fastapi.tiangolo.com/) | 0.162.0 | Investigation HTTP API and OpenAPI schema | MIT |
| [Starlette](https://www.starlette.io/) | 1.10.0 | ASGI web foundation used by FastAPI | BSD-3-Clause |
| [Pydantic](https://docs.pydantic.dev/) | 2.14.2 | API request/data validation | MIT |
| [Uvicorn](https://www.uvicorn.org/) | 0.54.0 | ASGI server | BSD-3-Clause |
| [psutil](https://psutil.readthedocs.io/) | 7.2.2 | Process-tree memory sampling and host resource checks | BSD-3-Clause |
| [fsspec](https://filesystem-spec.readthedocs.io/) | 2026.9.0 | File-interface support used by ingestion handoff | BSD-3-Clause |

SQLite, threading, concurrent futures, JSON, hashing and subprocess support come from Python's standard library; no additional service is needed for local analyst storage. GCC/Clang is an optional build tool for the repository's C FortiGate tokenizer. Docker installs GCC for that path.

### Optional / test packages

| Package | Version | Role | Declared license |
|---|---|---|---|
| [Neo4j Python driver](https://neo4j.com/docs/python-manual/current/) | 6.4.1 | Optional graph synchronization/backend; install `.[graph]` | Apache-2.0 AND Python-2.0 |
| [pytest](https://docs.pytest.org/) | 9.2.0 | Unit, API and pipeline tests; install `.[dev]` | MIT |
| [HTTPX](https://www.python-httpx.org/) | 0.28.1 | API test client support | BSD-3-Clause |

The default Docker backend does not install the optional Neo4j extra. For the optional graph workflow use a native `pip install -e ".[graph]"` environment and follow the graph-sync documentation. The Neo4j server is a separate optional product with its own license; the Python driver's license does not cover the server.

## Frontend

Direct versions are declared in [`frontend/package.json`](../frontend/package.json). The committed [`package-lock.json`](../frontend/package-lock.json) records the full resolved npm tree, including transitive package metadata.

| Package | Version | Role | Declared license |
|---|---|---|---|
| [Next.js](https://nextjs.org/docs) | 16.4.2 | App routing, production server and server-side API proxy | MIT |
| [React / React DOM](https://react.dev/) | 19.3.1 | Interactive investigation UI and rendering | MIT |
| [Cytoscape.js](https://js.cytoscape.org/) | 3.34.4 | Evidence graph visualization | MIT |
| [cytoscape-fcose](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose) | 2.2.0 | Graph layout | MIT |
| [Lucide React](https://lucide.dev/) | 1.58.0 | UI icons | ISC |
| [Tailwind CSS / PostCSS adapter](https://tailwindcss.com/) | 4.3.3 | Styling and build integration | MIT |
| [TypeScript](https://www.typescriptlang.org/) | 5.9.3 | Static checking | Apache-2.0 |
| `@types/node` | 22.20.5 | Node API types | MIT |
| `@types/react` | 19.3.0 | React types | MIT |
| `@types/react-dom` | 19.3.0 | React DOM types | MIT |

Use `npm ci` to reproduce the lockfile. For a complete machine-readable installed Python inventory, run `.venv/bin/python -m pip inspect --local` (Windows: `.venv\Scripts\python.exe`). Installed inventories can include unrelated or previously installed extras: they are not automatically the application's runtime dependency tree. `npm ls --all` describes the installed frontend tree; upstream license files remain authoritative.

## Rules, knowledge and optional providers

- SigmaHQ rules retain author metadata, the imported manifest and the [Detection Rule License 1.1 notice](../rules/community/LICENSE). A rule package's license is separate from the Sigma specification's public-domain status.
- MITRE ATT&CK supplies technique/tactic knowledge. Preserve the attribution and usage terms accompanying any downloaded STIX bundle; [`attack/README.md`](../attack/README.md) explains verification.
- The legacy UI vendors Cytoscape with its [MIT license](../web/vendor/CYTOSCAPE-LICENSE.txt).
- Sarvam is an optional external API service, not an open-source library bundled with TRACE. Provider model access, service terms and credits are separate from the local software.
- CERT-Shield and Vigil-SOC were design references for triage/reporting and investigation UX. They are not runtime packages or submodules in this repository; no license rights are implied by referencing them.

## TRACE's own license

The repository does not currently declare a top-level license for its own code. Do not label the entire repository MIT, Apache or unrestricted based on dependency licenses. A project owner must explicitly choose the project license; this cleanup does not invent one.
