"""Causal temporal interaction benchmark, separate from attack-label prediction.

All features precede the query timestamp. Equal-time edges are scored together
before updating memory. Sampled non-interactions are NOT benign/attack labels.
CPU baselines deliberately precede any claim that a neural TGN is necessary.
"""
from collections import Counter, OrderedDict, defaultdict
from itertools import groupby
import hashlib
import json
import math
from pathlib import Path
import random
import time

FEATURES = ['log_pair_count', 'pair_recency', 'log_source_count',
            'log_destination_count', 'source_recency', 'destination_recency',
            'hour_sin', 'hour_cos']


class TemporalMemory:
    def __init__(self, max_edges=200000, half_life_s=3600):
        if max_edges < 1 or half_life_s <= 0:
            raise ValueError('Memory capacity and half-life must be positive')
        self.capacity, self.half_life = max_edges, half_life_s * 1000
        self.edges = OrderedDict()
        self.sources, self.destinations = {}, {}
        self.evictions = 0

    def features(self, src, dst, ts):
        def history(mapping, key):
            count, last = mapping.get(key, (0, None))
            if last is not None and last >= ts:
                raise ValueError('Temporal leakage: memory contains current/future observations')
            recency = 0.0 if last is None else 2 ** (-(ts-last)/self.half_life)
            return math.log1p(count), recency
        pair = history(self.edges, (src, dst))
        source = history(self.sources, src)
        destination = history(self.destinations, dst)
        angle = 2 * math.pi * ((ts // 1000) % 86400) / 86400
        return [pair[0], pair[1], source[0], destination[0], source[1], destination[1],
                math.sin(angle), math.cos(angle)]

    def update(self, src, dst, ts):
        for mapping, key in ((self.edges, (src,dst)), (self.sources,src), (self.destinations,dst)):
            previous = mapping.get(key, (0, ts))
            if previous[1] > ts:
                raise ValueError('Events must be chronological')
            mapping[key] = (previous[0]+1, ts)
        self.edges.move_to_end((src,dst))
        if len(self.edges) > self.capacity:
            self.edges.popitem(last=False)
            self.evictions += 1


def load_interactions(path, max_events=100000):
    import duckdb
    if not 100 <= max_events <= 1000000:
        raise ValueError('max_events must be between 100 and 1,000,000')
    with duckdb.connect() as con:
        con.execute("SET memory_limit='1GB'")
        con.execute('SET threads=2')
        # Deduplicate interaction triples; repeated event IDs were removed by ingest.
        # Outcomes/bytes from the target event are deliberately NOT model features.
        query = """SELECT DISTINCT ts_ms, src_ip, dst_ip FROM read_parquet(?)
                   WHERE action='network_connection' AND ts_ms IS NOT NULL
                   AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND src_ip <> dst_ip
                   ORDER BY ts_ms, src_ip, dst_ip LIMIT ?"""
        rows = con.execute(query, [str(path), max_events+1]).fetchall()
    truncated = len(rows) > max_events
    if truncated:
        boundary = rows[max_events][0]
        rows = [row for row in rows[:max_events] if row[0] < boundary]
    if not rows:
        raise ValueError('No complete timestamp groups in the bounded interaction sample')
    return rows, truncated


def examples(rows, negatives=10, seed=17, max_edges=200000, half_life_s=3600, negative_mode='degree_matched'):
    """One candidate group per positive; half historical, half random past targets.

    Sampling uses only previously observed destinations, excluding ALL observed
    positives for the same source at the current timestamp. This remains a
    sampled-candidate task: absence is not evidence of a malicious/benign label.
    """
    if not 1 <= negatives <= 100:
        raise ValueError('negatives must be between 1 and 100')
    if negative_mode not in {'mixed','degree_matched'}:
        raise ValueError('Unknown negative sampling mode')
    memory = TemporalMemory(max_edges, half_life_s)
    rng = random.Random(seed)
    known, known_set, histories = [], set(), defaultdict(OrderedDict)
    buckets, positions = defaultdict(list), {}
    skipped = cold_destinations = 0
    for ts, batch_iter in groupby(rows, key=lambda row: row[0]):
        batch = list(batch_iter)
        positives = defaultdict(set)
        for _, src, dst in batch:
            positives[src].add(dst)
        pending = []
        for _, src, dst in batch:
            # Destination retrieval cannot propose an identifier never observed
            # before. Do not inject that held-out target into a known-node pool:
            # doing so makes unseen positives trivially separable from negatives.
            if dst not in known_set:
                cold_destinations += 1
                continue
            excluded = positives[src] | {src}
            degree_bin = memory.destinations[dst][0].bit_length()
            historical = [d for d in histories[src] if d not in excluded and
                          (negative_mode == 'mixed' or memory.destinations[d][0].bit_length() == degree_bin)]
            chosen = rng.sample(historical, min(len(historical), negatives//2))
            # Fixed work per query, not a full scan of all known destinations.
            pool = buckets[degree_bin] if negative_mode == 'degree_matched' else known
            for candidate in rng.sample(pool, min(len(pool), negatives*8)):
                if candidate not in excluded and candidate not in chosen:
                    chosen.append(candidate)
                if len(chosen) == negatives:
                    break
            if len(chosen) < negatives:
                skipped += 1
                continue
            candidates = [dst] + chosen
            pending.append({'ts': ts, 'features': [memory.features(src,d,ts) for d in candidates],
                            'cold_pair': (src,dst) not in memory.edges,
                            'cold_destination': dst not in memory.destinations,
                            'negative_count': len(chosen)})
        # No same-timestamp information reaches any feature, including other sources.
        for _, src, dst in batch:
            memory.update(src,dst,ts)
            new_bin = memory.destinations[dst][0].bit_length()
            old = positions.get(dst)
            if old is None or old[0] != new_bin:
                if old is not None:
                    old_bin, index = old
                    moved = buckets[old_bin][-1]
                    buckets[old_bin][index] = moved
                    positions[moved] = (old_bin,index)
                    buckets[old_bin].pop()
                positions[dst] = (new_bin,len(buckets[new_bin]))
                buckets[new_bin].append(dst)
            if dst not in known_set:
                known_set.add(dst); known.append(dst)
            histories[src][dst] = None
            histories[src].move_to_end(dst)
            if len(histories[src]) > 128:
                histories[src].popitem(last=False)
        yield from pending
    examples.last_stats = {'skipped_insufficient_negatives': skipped, 'cold_destination_queries_excluded':cold_destinations,
                           'edge_evictions': memory.evictions,
                           'retained_edges': len(memory.edges), 'sources': len(memory.sources),
                           'destinations': len(memory.destinations)}


def ranking_metrics(groups, scorer):
    sums = Counter()
    for group in groups:
        scores = scorer(group['features'])
        # Average rank for ties; never reward the positive for being first.
        rank = 1 + sum(s > scores[0] for s in scores[1:]) + 0.5 * sum(s == scores[0] for s in scores[1:])
        sums['queries'] += 1
        sums['mrr'] += 1 / rank
        sums['hits1'] += rank <= 1
        sums['hits3'] += rank <= 3
        sums['hits10'] += rank <= 10
    n = sums['queries']
    return {'queries': n, **{key: sums[key]/n if n else None for key in ('mrr','hits1','hits3','hits10')}}


def tree_artifact(model):
    tree = model.tree_
    return {'features': FEATURES, 'classes': model.classes_.tolist(),
            'children_left': tree.children_left.tolist(), 'children_right': tree.children_right.tolist(),
            'feature': tree.feature.tolist(), 'threshold': tree.threshold.tolist(),
            'value': tree.value[:,0,:].tolist()}


def tree_scores(artifact, features):
    positive = artifact['classes'].index(1)
    scores = []
    for row in features:
        node = 0
        while artifact['children_left'][node] != -1:
            node = artifact['children_left'][node] if row[artifact['feature'][node]] <= artifact['threshold'][node] else artifact['children_right'][node]
        values = artifact['value'][node]
        scores.append(values[positive] / sum(values))
    return scores


def benchmark(events_path, out_dir, max_events=100000, negatives=10, seed=17, negative_mode='degree_matched'):
    try:
        from sklearn.tree import DecisionTreeClassifier
        import numpy as np
        import sklearn
    except ImportError as exc:
        raise ValueError('Install temporal extras: pip install -e ".[temporal]"') from exc
    started = time.perf_counter()
    rows, truncated = load_interactions(events_path,max_events)
    times = sorted({row[0] for row in rows})
    if len(times) < 10:
        raise ValueError('Need at least ten distinct timestamps for chronological evaluation')
    left, right = times[int(len(times)*.7)], times[int(len(times)*.85)]
    groups = {'train':[], 'validation':[], 'test':[]}
    for group in examples(rows, negatives=negatives,seed=seed,negative_mode=negative_mode):
        split = 'train' if group['ts'] < left else 'validation' if group['ts'] < right else 'test'
        groups[split].append(group)
    if any(not values for values in groups.values()):
        raise ValueError('Need nonempty causal train, validation and test queries')

    def arrays(selected):
        x = np.asarray([f for g in selected for f in g['features']], dtype=np.float32)
        y = np.asarray([int(i==0) for g in selected for i in range(len(g['features']))])
        return x,y

    x,y = arrays(groups['train'])
    baseline = {'edgebank_recency':lambda fs:[f[1] for f in fs],
                'pair_frequency':lambda fs:[f[0] for f in fs],
                'pair_novelty':lambda fs:[-f[0] for f in fs],
                'destination_popularity':lambda fs:[f[3] for f in fs]}
    validation = {name:ranking_metrics(groups['validation'],fn) for name,fn in baseline.items()}
    trees = {}
    for depth in (3,6,10):
        name = f'entropy_tree_depth_{depth}'
        model = DecisionTreeClassifier(criterion='entropy', max_depth=depth, min_samples_leaf=20, random_state=seed)
        model.fit(x,y)
        trees[name] = tree_artifact(model)
        validation[name] = ranking_metrics(groups['validation'],lambda fs:tree_scores(trees[name],fs))
    methods = list(validation)
    selected = max(methods, key=lambda name:(validation[name]['mrr'], -methods.index(name)))
    # Report all held-out baselines, but select exclusively on validation.
    x,y = arrays(groups['train'] + groups['validation'])
    fitted = {}
    for name in trees:
        model = DecisionTreeClassifier(criterion='entropy',max_depth=int(name.rsplit('_',1)[1]),min_samples_leaf=20,random_state=seed)
        model.fit(x,y);fitted[name] = tree_artifact(model)
    scorers = {**baseline, **{name:(lambda fs, tree=tree:tree_scores(tree,fs)) for name,tree in fitted.items()}}
    test = {name:ranking_metrics(groups['test'],fn) for name,fn in scorers.items()}
    cold = [g for g in groups['test'] if g['cold_pair']]
    sample_hash = hashlib.sha256()
    for row in rows:
        sample_hash.update(json.dumps(row,separators=(',',':')).encode()+b'\n')
    report = {'task':'future_network_interaction_ranking', 'attack_accuracy':None,
              'label_source':'observed interactions versus sampled absent interactions; no attack labels',
              'protocol':'chronological prequential: predict then observe; all equal-time positives excluded from negatives',
              'negative_sampling':negative_mode,
              'negative_sampling_detail':'historical and random past destinations; degree_matched additionally matches log2 past destination frequency bins',
              'candidate_universe':'previously observed destinations; unseen positive destinations excluded and counted',
              'tie_policy':'average rank', 'seed':seed, 'requested_negatives':negatives,
              'negative_count_range':[min(g['negative_count'] for gs in groups.values() for g in gs),
                                      max(g['negative_count'] for gs in groups.values() for g in gs)],
              'events':len(rows), 'max_events':max_events, 'truncated':truncated,
              'interaction_sha256':sample_hash.hexdigest(), 'train_before_ms':left, 'test_after_ms':right,
              'split_queries':{key:len(value) for key,value in groups.items()},
              'validation':validation, 'test':test, 'selected_on_validation':selected,
              'cold_pair_test':{name:ranking_metrics(cold,fn) for name,fn in scorers.items()},
              'memory':examples.last_stats, 'features':FEATURES, 'sklearn_version':sklearn.__version__,
              'query_coverage':sum(len(g) for g in groups.values())/len(rows),
              'seconds':round(time.perf_counter()-started,3),
              'limitations':['Not a TGN implementation or a forecast of attack success.',
                            'Sampled ranking is not full-network destination retrieval; negatives can be unobserved positives.',
                            'First bounded chronological interactions from the sample; not a representative whole-file estimate.',
                            'Unseen destination prediction requires an external candidate inventory and is not evaluated.',
                            'State observes earlier validation/test events; weights do not train on test labels.',
                            'Scores are not calibrated real-world probabilities.']}
    target = Path(out_dir); target.mkdir(parents=True,exist_ok=True)
    (target/'temporal-benchmark.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    artifact = {'selected_model':selected, 'training_before_ms':right, 'features':FEATURES,
                'tree':fitted.get(selected), 'interaction_sha256':sample_hash.hexdigest(),
                'note':'Weights only; causal entity memory must be rebuilt from prior events.'}
    (target/'temporal-model.json').write_text(json.dumps(artifact,indent=2),encoding='utf-8')
    return report
