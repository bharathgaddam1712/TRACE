# Temporal engineering and ML review — 2026-10-31

## Problem definition

There are three different tasks. TRACE must not reuse the accuracy of one as the
accuracy of another:

1. Rule-based attack detection and incident reconstruction: requires independently
   reviewed attack events and incident membership to measure precision/recall.
2. Next network interaction: can use observed source/destination/time triples as
   self-supervision, but missing interactions are only sampled negatives, not
   ground-truth benign activity. A successful forecast is not attack prediction.
3. Next ATT&CK technique: requires dated incident sequences with reviewed labels.
   Exporting TRACE's own labels is useful for annotation, not independent truth.

The 500 MiB demo is a contiguous complete-line prefix of the supplied FortiGate
file. It is not a random sample and cannot establish full-file representativeness.
Its manifest records size, SHA-256, extraction policy, and credential-field scan
counts. Network identifiers remain; the user explicitly requested publishing the
sample. Git LFS stores the large file, rather than ordinary Git blobs.

## Research and decisions

| Source | Relevant finding | Decision for this repository |
|---|---|---|
| [TGN, Rossi et al., 2020](https://arxiv.org/abs/2006.10637) | Memory plus graph operators represents continuous-time interactions. | Preserve causal event order and separate scoring from memory updates. TGN remains a neural challenger, not a synonym for any temporal model. |
| [Temporal Graph Benchmark, 2023](https://ai.stanford.edu/~jure/pubs/temporal-neurips23.pdf) | Standardized chronological evaluation and harder negatives matter. | Report candidate construction, coverage, ties, chronological splits, and cold-pair performance. |
| [TGB 2.0, 2024](https://proceedings.nips.cc/paper_files/paper/2024/file/fda026cf2423a01fcbcf1e1e43ee9a50-Paper-Datasets_and_Benchmarks_Track.pdf) | EdgeBank is competitive on some heterogeneous temporal tasks; complex models do not universally win. | Compare memory/frequency heuristics before accepting neural latency and dependencies. |
| [TGM, 2025](https://arxiv.org/abs/2510.07586) | Shared infrastructure can substantially reduce temporal-model execution costs on the authors' benchmarks. | A future TGN experiment should use a maintained framework; these reported speedups are not TRACE measurements. |
| [FLASH, IJCAI 2026](https://ijcai.org/proceedings/2026/476) | Adaptive historical-neighbor sampling can improve temporal GNNs. | Bound history now; investigate learned sampling only after a credible neural baseline exists. |
| [ATNSF, IJCAI 2026](https://ijcai.org/proceedings/2026/302) | Historical hard negatives and pairwise ranking losses affect quality and scalability. | Include historical alternatives in sampled evaluation. Our sampler is not an implementation of ATNSF. |
| [TTGBench, September 2026 preprint](https://arxiv.org/abs/2609.08226) | Structural changes and semantic drift are distinct temporal tasks. | Keep edge prediction distinct from changes in attack semantics; do not infer broad security accuracy from link ranking. |

This is a targeted review of relevant primary sources, not an exhaustive claim
to have surveyed every publication. Results from social/recommendation benchmarks
do not prove transfer to firewall logs.

## Implemented causal benchmark

`tracekc temporal-benchmark` reads normalized Parquet produced with `run --keep-work`.
The default bounded experiment uses the first 100,000 chronological, distinct
network interaction triples. It drops a truncated final timestamp group. It does
not randomly shuffle events. Bounds are explicit in each report.

The split uses 70%/85% cut points among distinct timestamps. All records sharing
a timestamp stay on the same side. Features and candidate inventories use only
strictly earlier observations; equal-time groups are scored before any updates.
During validation/test the memory observes previously completed events, but model
weights never fit test labels. This is prequential evaluation, not frozen-history
multi-hour forecasting.

Features: log pair frequency, pair recency, source/destination frequencies,
source/destination recencies, and UTC time-of-day sine/cosine. Target-event bytes,
outcome, rule labels and future graph degree are deliberately excluded.

Recency uses `2 ** (-elapsed_ms / half_life_ms)` with a one-hour half-life.
Pair memory is bounded to 200,000 most recently updated edges. Historical negative
candidate lists retain at most 128 destinations per source. Node state is bounded
by the explicit input cap, not claimed to be constant-space infinite streaming.

Models:

- EdgeBank-style recency ranking (a baseline variant, not the official package).
- Pair frequency and pair novelty (anti-repetition) rankings.
- Destination popularity.
- Entropy decision trees with depths 3, 6 and 10 and minimum leaf size 20.

Tree splits minimize weighted entropy `H = -sum(p * log2(p))`. Depth selection uses
validation MRR only. Tree models are refitted on training plus validation before
the final test. JSON tree artifacts avoid executable pickle loading.

Negatives combine prior source destinations with random previously seen targets.
The default `degree_matched` protocol restricts both to the same log2 past
destination-frequency bin as the query target; `--negative-mode mixed` is an
explicit easier ablation. Degree matching uses only pre-query counts. Skip queries
without the requested number of distinct negatives, and account for them in
coverage. This avoids silently comparing ranks from different candidate counts.
Every observed positive for a source at the same timestamp is excluded. Unknown
positive destinations are excluded from retrieval evaluation and counted: adding
them to a known-only negative pool creates an artificial cold-start advantage.
Report candidate counts, query coverage and cold-pair MRR. A small sampled candidate
set is easier than full-network retrieval. Average tie ranks avoid favoring the
positive merely because it is first in the candidate array.

`MRR = mean(1 / rank_of_observed_destination)`. Hits@K uses average tie ranks.
Scores are candidate-set dependent and not calibrated compromise probabilities.
If all test pairs are novel, a high novelty/tree score may describe data generation
patterns rather than transferable attacker behavior. Multi-seed evaluation and
an independent data source are required before operational conclusions.

## Engineering changes

- Keep the direct event scan for small applicable rule sets. Larger rule sets
  materialize expensive process/IP joins once and evaluate bounded batches on
  explicitly scoped subsets. Preserve original Sigma predicates, including NULL
  and NOT semantics; do not prune by naive field-presence tests.
- Index correlation edges by source signal before incident materialization,
  avoiding an all-edge scan for every incident.
- Index access observations by source account/host. Lookahead reads only relevant
  histories, retaining timestamp cutoffs and expiry. Sort observations to select
  the latest eligible relation deterministically.
- Apply relation-specific user/IP thresholds after time and hub guards. Explicit
  process/logon links remain distinct; accepted weak associations carry their
  threshold reason. This is a configurable heuristic change, not learned truth.

## TGN experiment acceptance gate

A TGN is **not implemented or claimed trained in this revision**. A technically
sound next experiment should use a verified reference TGN/TGM implementation with:

1. An explicit external candidate inventory for genuine unseen-target evaluation.
2. Train-only parameter fitting; reset/replay memory between runs; score-before-
   update semantics, including timestamp ties and batch boundaries.
3. Bounded past-neighbor sampling and memory, with measured CPU/GPU RAM.
4. The same split and negative protocol as the CPU baselines; at least three seeds.
5. Known-node and new-node results, MRR/Hits@K, coverage, latency and ablations.
6. A separate reviewed attack dataset before interpreting predictions as attacks.

Adding a custom unvalidated neural architecture would not make this demo more
credible. Promote a neural model only if it improves held-out utility enough to
justify its latency and resource cost. Sarvam remains an optional explanation
service and is not placed in per-event processing or used as ground truth.

## Attacker-technique sequence forecasting

This is separate from the network interaction experiment. The incident-history
benchmark now compares majority, first-order Markov, second-order Markov and a
30-day recency-weighted first-order Markov model. Decay uses whole-incident end
times before the training cutoff; no time-to-next-event labels are invented.
The fixed decay half-life is not optimized on the test set.

Automatic split selection uses timestamp ranges and case counts only. It searches
coarse chronological boundaries for at least ten whole incidents per partition,
preferring 70/15/15 proportions and retaining cases. Cases crossing boundaries
are excluded. Explicit date boundaries remain available. Warnings identify small
validation sets, unreviewed labels, and insufficient multi-step test prefixes.

Bounded beam search returns top-N hypothetical continuations, with depth <= 5,
beam width <= 50, and minimum historical support. Each step discloses whether it
used two-technique context, one-technique context or the global prior. Path scores
multiply empirical conditional shares; they are not calibrated compromise
probabilities. Cycles can occur because repeated techniques are legitimate, but
depth is bounded. Model selection uses single-step validation MRR; exact-sequence
top-5 is additionally reported by horizon on the held-out set, not used to tune it.

The sequence model uses compact in-memory dictionaries. DuckDB handles event
processing and extraction; Neo4j is unnecessary for this bounded prediction task.

## Time-respecting graph search

The graph now additionally supports a bounded earliest-arrival algorithm over
explicit recorded observation timestamps. It keeps the earliest arrival per
(node, hop-count) state and uses a priority queue, with binary search over each
edge's sorted observations. Waiting is allowed. An earlier arrival dominates a
later arrival with the same hop count; limiting depth bounds traversal.

Observed first/last signal times are stored as actual endpoints; intermediate
times are not fabricated. The algorithm excludes untimed, inferred and hypothesis
edges and respects an incident cutoff. It can reject a cheap Dijkstra path whose
edge observations occur in reverse chronological order. A time-respecting chain
of observed associations is still not proof of an attacker's route.
