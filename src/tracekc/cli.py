"""Command line: tracekc run | serve | eval | watch | plant | gen-scale | attack-verify | rules-check."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from tracekc.config import load_config, project_path, load_env


def _cfg(args) -> dict:
    return load_config(args.config, args.set or [])


def cmd_run(args) -> int:
    from tracekc.pipeline import run_pipeline
    report = run_pipeline(_cfg(args), Path(args.input), Path(args.out), keep_work=args.keep_work)
    print(json.dumps({k: report[k] for k in ("timings", "peak_process_tree_rss_gb", "output", "signals")}, indent=1))
    if report["rules"]["rejected"]:
        print(f"WARNING: {len(report['rules']['rejected'])} rule(s) rejected, see run_metrics.json", file=sys.stderr)
    return 0


def cmd_serve(args) -> int:
    import uvicorn
    from tracekc.api import create_app
    uvicorn.run(create_app(Path(args.out)), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_eval(args) -> int:
    from tracekc.evaluate import evaluate, gt_from_labels
    gt = gt_from_labels(Path(args.gt_from_labels)) if args.gt_from_labels else json.loads(Path(args.gt).read_text(encoding="utf-8-sig"))
    result = evaluate(Path(args.out), gt)
    print(json.dumps(result, indent=1))
    if args.save:
        Path(args.save).write_text(json.dumps(result, indent=1))
    return 0


def cmd_watch(args) -> int:
    """Basic live mode (B-5): re-run the pipeline whenever input files change. The API reloads
    automatically. Full re-runs are fine for small/medium inputs; not seconds-fast at 50 GB."""
    from tracekc.ingest import find_inputs
    from tracekc.pipeline import run_pipeline
    cfg = _cfg(args)
    last = None
    while True:
        snap = tuple((str(p), p.stat().st_size, p.stat().st_mtime)
                     for p in find_inputs(Path(args.input), cfg["ingest"]["patterns"]))
        if snap and snap != last:
            report = run_pipeline(cfg, Path(args.input), Path(args.out))
            print(f"[watch] {report['output']['incidents']} incidents in {report['timings']['total_wall_seconds']}s",
                  flush=True)
            last = snap
        time.sleep(args.interval)


def cmd_plant(args) -> int:
    from tracekc.synth import write_planted
    ev, gt = write_planted(Path(args.out))
    print(f"wrote {ev} and {gt}")
    return 0


def cmd_gen_scale(args) -> int:
    from tracekc.synth import scale_up
    print(json.dumps(scale_up(Path(args.sample), Path(args.out), args.target_gb, plant=not args.no_plant), indent=1))
    return 0


def cmd_attack_verify(args) -> int:
    from tracekc.label import verify_mapping
    cfg = _cfg(args)
    problems = verify_mapping(project_path(cfg, "configs/attack_mapping.yaml"), Path(args.stix), write=args.write)
    for p in problems:
        print(p)
    print(f"{len(problems)} difference(s)" + (" - mapping rewritten from STIX" if args.write and problems else ""))
    return 1 if problems and not args.write else 0


def cmd_rules_check(args) -> int:
    from tracekc.sigma import load_rules
    cfg = _cfg(args)
    rules, errors = load_rules(project_path(cfg, cfg["detection"]["rules_dir"]))
    for r in rules.values():
        print(f"OK   {r.id:40s} {r.kind:12s} {r.level:9s} {','.join(r.techniques)}")
    for e in errors:
        print(f"FAIL {e}")
    return 1 if errors else 0


def cmd_train_forecast(args) -> int:
    from tracekc.forecast import train
    from tracekc.materialize import write_json
    model = train(Path(args.input), args.before)
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    write_json(target, model)
    print(json.dumps({key: model[key] for key in ('method', 'training_incidents', 'heldout')}, indent=2))
    return 0


def cmd_graph_sync(args) -> int:
    from tracekc.neo4j_store import Neo4jStore
    store = Neo4jStore(Path(args.out))
    try:
        print(json.dumps(store.sync(Path(args.out)), indent=2))
    finally:
        store.close()
    return 0


def cmd_export_history(args) -> int:
    from tracekc.forecast import export_history
    from tracekc.materialize import write_json
    target=Path(args.save);target.parent.mkdir(parents=True,exist_ok=True)
    result=export_history(Path(args.out));write_json(target,result)
    print(f"Exported {len(result['incidents'])} unreviewed histories to {target}")
    return 0


def cmd_forecast_benchmark(args) -> int:
    from tracekc.forecast import benchmark, compare_sarvam, automatic_cutoffs
    from tracekc.materialize import write_json
    from tracekc.label import load_mapping
    from tracekc.config import PROJECT_ROOT
    source=Path(args.input)
    left,right=args.train_before,args.test_after
    if not left and not right:
        rows=json.loads(source.read_text(encoding='utf-8-sig'))['incidents']
        left,right=automatic_cutoffs(rows)
    if not left or not right:raise ValueError('Provide both --train-before and --test-after, or neither for 70/15/15 time cutoffs')
    report,model,test=benchmark(source,left,right)
    target=Path(args.out);target.parent.mkdir(parents=True,exist_ok=True)
    write_json(target,report)
    model_target=Path(args.model_out);model_target.parent.mkdir(parents=True,exist_ok=True);write_json(model_target,model)
    if args.sarvam:
        from tracekc.ai import SarvamService
        catalog={tid:item['name'] for tid,item in load_mapping(PROJECT_ROOT/'configs/attack_mapping.yaml')['techniques'].items()}
        report['sarvam']=compare_sarvam(test,SarvamService(target.parent),catalog,args.sarvam_limit)
        write_json(target,report)
    print(json.dumps(report,indent=2))
    return 0


def cmd_import_rules(args) -> int:
    from tracekc.rulepacks import import_sigma
    print(json.dumps(import_sigma(Path(args.source),Path(args.dest)),indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    load_env()
    p = argparse.ArgumentParser(prog="tracekc", description=__doc__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    schemas = sub.add_parser('parser-schemas',help='Print supported input contracts and explicit ECS projection')
    def schema_command(args):
        from tracekc.parser_contracts import contracts
        print(json.dumps(contracts(),indent=2))
        return 0
    schemas.set_defaults(fn=schema_command)
    attach=sub.add_parser('attach-forecast',help='Attach a fitted model without repeating ingestion/detection')
    attach.add_argument('--out',required=True)
    attach.add_argument('--model',required=True)
    def attach_command(args):
        from tracekc.forecast import attach_model
        print(json.dumps(attach_model(Path(args.out),Path(args.model)),indent=2))
        return 0
    attach.set_defaults(fn=attach_command)
    temporal = sub.add_parser('temporal-benchmark', help='Causal network interaction ranking; not attack accuracy')
    temporal.add_argument('--events', required=True, help='Normalized work/events.parquet from run --keep-work')
    temporal.add_argument('--out', required=True)
    temporal.add_argument('--max-events', type=int, default=100000)
    temporal.add_argument('--negatives', type=int, default=10)
    temporal.add_argument('--seed', type=int, default=17)
    temporal.add_argument('--negative-mode', choices=['mixed','degree_matched'], default='degree_matched')
    def temporal_command(args):
        from tracekc.temporal import benchmark
        report = benchmark(args.events,args.out,args.max_events,args.negatives,args.seed,args.negative_mode)
        print(json.dumps(report,indent=2))
        return 0
    temporal.set_defaults(fn=temporal_command)
    sequence = sub.add_parser('predict-sequence',help='Bounded hypothetical next ATT&CK sequences from a fitted historical model')
    sequence.add_argument('--model',required=True)
    sequence.add_argument('--history',nargs='+',required=True,help='Observed ATT&CK technique IDs in order')
    sequence.add_argument('--as-of',required=True,help='Incident start time, ISO8601 with timezone')
    sequence.add_argument('--depth',type=int,default=3)
    sequence.add_argument('--top-n',type=int,default=5)
    sequence.add_argument('--beam-width',type=int,default=20)
    def sequence_command(args):
        from tracekc.forecast import predict
        model = json.loads(Path(args.model).read_text(encoding='utf-8-sig'))
        result = predict(model,args.history[-1],args.as_of,args.history,
                         {'sequence_depth':args.depth,'top_n':args.top_n,'beam_width':args.beam_width})
        print(json.dumps(result,indent=2))
        return 0
    sequence.set_defaults(fn=sequence_command)

    def common(sp):
        sp.add_argument("--config", help="config YAML (default configs/config.yaml)")
        sp.add_argument("--set", action="append", metavar="KEY=VALUE", help="override a config key")

    r = sub.add_parser("run", help="process a log directory end to end")
    r.add_argument("--input", required=True, help="directory (searched recursively) or single file")
    r.add_argument("--out", default="out")
    r.add_argument("--keep-work", action="store_true", help="keep work/ (DuckDB file, events.parquet)")
    common(r)
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("serve", help="start the API + web page")
    s.add_argument("--out", default="out")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    e = sub.add_parser("eval", help="score output against ground truth")
    e.add_argument("--out", default="out")
    g = e.add_mutually_exclusive_group(required=True)
    g.add_argument("--gt", help="ground-truth JSON")
    g.add_argument("--gt-from-labels", metavar="INPUT", help="use SimEDR simulated_detection labels as one-step GT")
    e.add_argument("--save", help="write result JSON here")
    e.set_defaults(fn=cmd_eval)

    w = sub.add_parser("watch", help="live mode: re-run when inputs change")
    w.add_argument("--input", required=True)
    w.add_argument("--out", default="out")
    w.add_argument("--interval", type=float, default=10.0)
    common(w)
    w.set_defaults(fn=cmd_watch)

    pl = sub.add_parser("plant", help="write the planted attack chain + its ground truth")
    pl.add_argument("--out", default="data/planted")
    pl.set_defaults(fn=cmd_plant)

    gs = sub.add_parser("gen-scale", help="replicate a sample to N GB for load tests")
    gs.add_argument("--sample", default="data/sample/edr_events.json")
    gs.add_argument("--out", required=True)
    gs.add_argument("--target-gb", type=float, required=True)
    gs.add_argument("--no-plant", action="store_true")
    gs.set_defaults(fn=cmd_gen_scale)

    av = sub.add_parser("attack-verify", help="check configs/attack_mapping.yaml against MITRE STIX")
    av.add_argument("--stix", required=True)
    av.add_argument("--write", action="store_true", help="rewrite names/tactics from STIX")
    common(av)
    av.set_defaults(fn=cmd_attack_verify)

    rc = sub.add_parser("rules-check", help="validate every Sigma rule in rules/")
    common(rc)
    rc.set_defaults(fn=cmd_rules_check)

    forecast = sub.add_parser('train-forecast', help='train an optional next-technique baseline on dated historical incidents')
    forecast.add_argument('--input', required=True)
    forecast.add_argument('--before', required=True, help='time split in ISO8601, including timezone')
    forecast.add_argument('--out', default='out/forecast-model.json')
    forecast.set_defaults(fn=cmd_train_forecast)

    graph = sub.add_parser('graph-sync', help='synchronize incident graphs to the configured Neo4j namespace')
    graph.add_argument('--out', default='out')
    graph.set_defaults(fn=cmd_graph_sync)

    history=sub.add_parser('export-history',help='export inferred incident sequences for analyst review')
    history.add_argument('--out',default='out');history.add_argument('--save',required=True);history.set_defaults(fn=cmd_export_history)
    comparison=sub.add_parser('forecast-benchmark',help='chronological majority/Markov comparison with optional Sarvam baseline')
    comparison.add_argument('--input',required=True);comparison.add_argument('--train-before');comparison.add_argument('--test-after')
    comparison.add_argument('--out',default='out/forecast-comparison.json');comparison.add_argument('--model-out',default='out/forecast-model.json')
    comparison.add_argument('--sarvam',action='store_true');comparison.add_argument('--sarvam-limit',type=int,default=5)
    comparison.set_defaults(fn=cmd_forecast_benchmark)
    imports=sub.add_parser('rules-import',help='import a compiler-compatible stable/test SigmaHQ pack with rejection inventory')
    imports.add_argument('--source',required=True);imports.add_argument('--dest',required=True);imports.set_defaults(fn=cmd_import_rules)

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return args.fn(args)
