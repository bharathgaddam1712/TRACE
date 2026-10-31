"""Optional, auditable next-technique baseline trained on time-stamped historical incidents."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import re
import math
from pathlib import Path


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Forecast timestamps must include a timezone')
    return parsed.astimezone(timezone.utc)


def automatic_cutoffs(rows):
    """Choose boundaries using timestamps/counts only, never labels or scores.

    Long incidents crossing boundaries are excluded. Start-time percentiles alone
    can leave one validation case, so prefer a balanced feasible whole-case split.
    """
    ranges = [(timestamp(r['started_at']),timestamp(r['ended_at'])) for r in rows if len(r['techniques'])>=2]
    starts = sorted({start for start,_ in ranges})
    if len(starts)<10:
        raise ValueError('Automatic split requires at least 10 distinct incident start times')
    candidates = sorted({starts[min(len(starts)-1,int(len(starts)*q/100))] for q in range(40,96,5)})
    best = None
    for left in candidates:
        for right in candidates:
            if left>=right:
                continue
            counts = [sum(end<left for start,end in ranges),
                      sum(start>=left and end<right for start,end in ranges),
                      sum(start>=right for start,end in ranges)]
            if min(counts)<10:
                continue
            retained = sum(counts)
            score = sum(abs(n/retained-target) for n,target in zip(counts,(.7,.15,.15))) + .25*(1-retained/len(ranges))
            candidate = (score,left,right)
            if best is None or candidate < best:
                best = candidate
    left,right = (best[1],best[2]) if best else (starts[int(len(starts)*.7)],starts[int(len(starts)*.85)])
    return left.isoformat(),right.isoformat()


def train(source: Path, before: str) -> dict:
    cutoff = timestamp(before)
    histories = json.loads(source.read_text(encoding='utf-8-sig'))['incidents']
    counts, training, heldout = defaultdict(Counter), [], []
    seen = set()
    for incident in histories:
        if incident['id'] in seen:
            raise ValueError('Historical incident IDs must be unique')
        seen.add(incident['id'])
        start, end = timestamp(incident['started_at']), timestamp(incident['ended_at'])
        if start > end:
            raise ValueError('Historical incident starts after its end')
        sequence = incident['techniques']
        if not sequence or any(not isinstance(t, str) or not re.fullmatch(r'T\d{4}(?:\.\d{3})?', t) for t in sequence):
            raise ValueError('Each incident needs an ordered technique list')
        if end < cutoff:
            training.append(incident)
            for a, b in zip(sequence, sequence[1:]):
                counts[a][b] += 1
        elif start >= cutoff:
            heldout.append(incident)
        # Incidents crossing the split are excluded to avoid temporal contamination.
    if not counts:
        raise ValueError('No historical transitions before the training cutoff')
    evaluated = hits = transitions = 0
    for incident in heldout:
        for a, b in zip(incident['techniques'], incident['techniques'][1:]):
            transitions += 1
            if counts.get(a):
                evaluated += 1
                best = sorted(counts[a], key=lambda t: (-counts[a][t], t))[0]
                hits += best == b
    return {'method': 'historical_first_order_transition_baseline', 'training_until': before,
            'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'training_incidents': len(training), 'transitions': dict(counts),
            'heldout': {'incidents': len(heldout), 'transitions': transitions, 'covered_transitions': evaluated,
                        'top1_accuracy_on_covered': hits / evaluated if evaluated else None}}


def predict(model: dict | None, technique: str | None, first_seen: str, history=None, settings=None) -> dict:
    if not model:
        return {'status': 'unavailable', 'reason': 'No historical next-technique model configured.'}
    if timestamp(model['training_until']) >= timestamp(first_seen):
        return {'status': 'unavailable', 'reason': 'Model training cutoff is not before this incident.'}
    if model.get('fitted'):
        prefix=history or [technique]
        candidates=rank(model['fitted'],prefix,model['selected_model'])
        options = settings or {}
        sequences = beam_sequences(model['fitted'],prefix,model['selected_model'],
                                   depth=int(options.get('sequence_depth',3)),
                                   top_n=int(options.get('top_n',5)),beam_width=int(options.get('beam_width',20)),
                                   min_support=int(options.get('min_support',3)))
        return {'status':'estimated' if sequences else 'unknown','method':model['selected_model'],
                'training_until':model['training_until'],'label_source':model.get('label_source','unspecified'),
                'candidates':[{'technique':t} for t in candidates[:5]], 'sequences':sequences,
                'reason':None if sequences else 'Insufficient historical support for a complete sequence at the requested depth.',
                'evaluation_warnings':model.get('benchmark',{}).get('warnings',[]),
                'interpretation':'Historical model selected on validation; bounded hypothetical sequences, not calibrated attack probabilities.'}
    counts = model['transitions'].get(technique, {})
    total = sum(counts.values())
    if total < 3:
        return {'status': 'unknown', 'reason': 'Fewer than three historical transitions for the last technique.'}
    return {'status': 'estimated', 'method': model['method'], 'training_until': model['training_until'],
            'support': total, 'candidates': [
                {'technique': t, 'count': n, 'historical_share': round(n / total, 4)}
                for t, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5]],
            'interpretation': 'Historical transition frequency, not a calibrated probability of the next attack.'}

def _fit(histories, reference=None):
    one,two,overall,decayed=defaultdict(Counter),defaultdict(Counter),Counter(),defaultdict(Counter)
    for row in histories:
        sequence=row['techniques']
        age_days = max(0,(timestamp(reference)-timestamp(row['ended_at'])).total_seconds()/86400) if reference else 0
        weight = 2 ** (-age_days/30)
        for index in range(1,len(sequence)):
            target=sequence[index];overall[target]+=1;one[sequence[index-1]][target]+=1
            decayed[sequence[index-1]][target]+=weight
            if index>1:two['|'.join(sequence[index-2:index])][target]+=1
    return {'first_order':dict(one),'second_order':dict(two),'overall':dict(overall),
            'decayed_first_order':dict(decayed),'half_life_days':30}


def rank(artifact,prefix,method):
    counts,_,_ = transition_counts(artifact,prefix,method)
    return sorted(counts,key=lambda key:(-counts[key],key))


def transition_counts(artifact,prefix,method):
    counts = artifact['overall']; support = sum(counts.values()); context = 'global_prior'
    if prefix and method in {'markov1','markov2','recency_markov1'}:
        raw = artifact['first_order'].get(prefix[-1],{})
        if raw:
            counts = artifact.get('decayed_first_order',{}).get(prefix[-1],raw) if method=='recency_markov1' else raw
            support,context = sum(raw.values()), 'last_technique'
    if method=='markov2' and len(prefix)>=2:
        raw = artifact['second_order'].get('|'.join(prefix[-2:]),{})
        if raw:
            counts,support,context = raw,sum(raw.values()),'last_two_techniques'
    return counts,support,context


def beam_sequences(artifact,prefix,method,depth=3,top_n=5,beam_width=20,min_support=3):
    """Bounded autoregressive empirical forecasts; future steps remain hypotheses.

    Work is bounded by depth * beam_width * vocabulary; retain at most beam_width
    branches per step. Global backoff is disclosed, never disguised as observed
    technique-to-technique evidence. No external graph database is needed.
    """
    if not (1 <= depth <= 5 and 1 <= top_n <= beam_width <= 50 and min_support >= 1):
        raise ValueError('Require depth 1..5, 1 <= top_n <= beam_width <= 50, positive support')
    if not prefix or not all(prefix):
        return []
    beams = [([],0.0,[])]
    for _ in range(depth):
        expanded = []
        for suffix,log_score,reasons in beams:
            counts,support,context = transition_counts(artifact,list(prefix)+suffix,method)
            total = sum(counts.values())
            if support < min_support or total <= 0:
                continue
            for technique,count in sorted(counts.items(),key=lambda item:(-item[1],item[0]))[:beam_width]:
                if count <= 0:
                    continue
                share = count/total
                expanded.append((suffix+[technique],log_score+math.log(share),
                                 reasons+[{'context':context,'historical_support':support,'conditional_share':share}]))
        beams = sorted(expanded,key=lambda row:(-row[1],row[0]))[:beam_width]
        if not beams:
            break
    return [{'techniques':seq,'model_path_score':math.exp(score),'steps':reasons,
             'interpretation':'Product of empirical conditional shares, not probability of an actual attack.'}
            for seq,score,reasons in beams[:top_n]]


def sequence_metrics(rows,artifact,method):
    results = {}
    for depth in (1,2,3):
        total = hits = covered = 0
        for row in rows:
            sequence = row['techniques']
            for index in range(1,len(sequence)-depth+1):
                total += 1
                candidates = beam_sequences(artifact,sequence[:index],method,depth=depth)
                covered += bool(candidates)
                hits += any(c['techniques']==sequence[index:index+depth] for c in candidates)
        results[str(depth)] = {'eligible_prefixes':total, 'coverage':covered/total if total else None,
                               'exact_sequence_top5':hits/total if total else None}
    return results


def _metrics(rows,artifact,method):
    hits1=hits3=covered=total=0;reciprocal=0.0
    for row in rows:
        sequence=row['techniques']
        for index in range(1,len(sequence)):
            total+=1;predictions=rank(artifact,sequence[:index],method);target=sequence[index]
            if predictions:covered+=1
            if target in predictions:
                position=predictions.index(target)+1
                hits1+=position==1;hits3+=position<=3;reciprocal+=1/position
    return {'transitions':total,'coverage':covered/total if total else None,
            'top1':hits1/total if total else None,'top3':hits3/total if total else None,
            'mrr':reciprocal/total if total else None}


def benchmark(source:Path,train_before:str,test_after:str):
    payload=json.loads(source.read_text(encoding='utf-8-sig'))
    rows=payload['incidents'];left,right=timestamp(train_before),timestamp(test_after)
    if left>=right:raise ValueError('Training cutoff must be before the test cutoff')
    groups={'train':[],'validation':[],'test':[],'crossing_excluded':[]};seen=set()
    for row in rows:
        if row['id'] in seen:raise ValueError('Duplicate historical incident ID')
        seen.add(row['id']);start,end=timestamp(row['started_at']),timestamp(row['ended_at'])
        if start>end:raise ValueError('Incident start is after end')
        if len(row['techniques'])<2:continue
        if any(not isinstance(t,str) or not re.fullmatch(r'T\d{4}(?:\.\d{3})?',t) for t in row['techniques']):raise ValueError('Invalid technique ID')
        group='train' if end<left else 'validation' if start>=left and end<right else 'test' if start>=right else 'crossing_excluded'
        groups[group].append(row)
    if any(not groups[name] for name in ('train','validation','test')):
        raise ValueError('Need nonempty chronological train, validation and test incident sets; overlapping incidents are excluded')
    artifact=_fit(groups['train'],train_before);methods=['majority','markov1','markov2','recency_markov1']
    validation={method:_metrics(groups['validation'],artifact,method) for method in methods}
    selected=max(methods,key=lambda method:((validation[method]['mrr'] or 0),(validation[method]['top1'] or 0),-methods.index(method)))
    # Refit selected approach on pre-test data. Never select it using the test scores.
    fitted=_fit(groups['train']+groups['validation'],test_after)
    tests={method:_metrics(groups['test'],fitted,method) for method in methods}
    report={'split':'chronological_by_whole_incident','train_before':train_before,'test_after':test_after,
            'counts':{name:len(values) for name,values in groups.items()},'validation':validation,'test':tests,
            'selected_on_validation':selected,'label_source':payload.get('label_source','unspecified'),
            'sequence_test':sequence_metrics(groups['test'],fitted,selected),
            'interpretation':'Scores measure agreement with supplied labels. Unreviewed TRACE labels are not independent attack ground truth.'}
    report['warnings'] = []
    if payload.get('label_source') != 'analyst_reviewed':
        report['warnings'].append('Labels are not declared analyst-reviewed; no independent attack-accuracy claim is supported.')
    if len(groups['validation']) < 10 or validation[selected]['transitions'] < 20:
        report['warnings'].append('Validation support is small; model selection is exploratory.')
    if report['sequence_test']['3']['eligible_prefixes'] < 20:
        report['warnings'].append('Fewer than 20 held-out three-step prefixes; multi-step accuracy is not established.')
    model={'method':'historical_transition_model_comparison','selected_model':selected,'training_until':test_after,
           'label_source':payload.get('label_source','unspecified'),
           'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'training_incidents':len(groups['train'])+len(groups['validation']),
           'transitions':fitted['first_order'],'fitted':fitted,'benchmark':report}
    return report,model,groups['test']


def export_history(out_dir:Path):
    index=json.loads((out_dir/'index.json').read_text(encoding='utf-8-sig'));rows=[]
    for item in index:
        inc=json.loads((out_dir/'incidents'/f"{item['id']}.json").read_text(encoding='utf-8-sig'))
        sequence=[]
        for step in inc['timeline']:
            technique=step.get('technique')
            if technique and (not sequence or sequence[-1]!=technique):sequence.append(technique)
        rows.append({'id':inc['fingerprint'],'started_at':inc['first_seen'],'ended_at':inc['last_seen'],'techniques':sequence})
    return {'label_source':'trace_predictions_unreviewed','incidents':rows,
            'warning':'Review these inferred incidents and labels before using them as independent evaluation ground truth.'}


def compare_sarvam(test_rows,service,catalog,limit=10):
    total=hits1=hits3=0;reciprocal=0.0
    for row in sorted(test_rows,key=lambda r:(r['started_at'],r['id'])):
        sequence=row['techniques']
        for index in range(1,len(sequence)):
            if total>=limit:break
            # Only the observed prefix is supplied. The held-out target never enters the prompt.
            result=service.predict_next(sequence[:index],catalog)
            predictions=result['technique_ids'];target=sequence[index];total+=1
            if target in predictions:
                position=predictions.index(target)+1;hits1+=position==1;hits3+=position<=3;reciprocal+=1/position
        if total>=limit:break
    return {'model':service.model,'transitions':total,'top1':hits1/total if total else None,
            'top3':hits3/total if total else None,'mrr':reciprocal/total if total else None,
            'note':'Exploratory held-out comparison; does not replace the model selected using validation.'}
