"""Explainable incident relationships using candidate indexing, overlap and time constraints."""
from collections import defaultdict
from tracekc.timeutil import timestamp


def jaccard(a,b):
    return len(a&b)/len(a|b) if a|b else 0.0


def related_incidents(incidents, settings):
    threshold=float(settings.get('threshold',0.6)); minimum=float(settings.get('technique_overlap',0.3))
    window=float(settings.get('time_window_s',86400)); cap=int(settings.get('max_candidates_per_incident',200))
    postings=defaultdict(list); features={}; skipped=0
    for inc in incidents:
        entities={f'{kind}:{v}' for kind in ('hosts','users','external_ips') for v in inc['entities'].get(kind,[])}
        techniques={t for step in inc['timeline'] for t in step.get('technique_ids',[step.get('technique')]) if t}
        features[inc['id']]=(entities,techniques,timestamp(inc['first_seen']).timestamp(),timestamp(inc['last_seen']).timestamp())
        for entity in entities: postings[entity].append(inc['id'])
    links=[];examined=set()
    for inc in incidents:
        iid=inc['id'];entities,techniques,start,end=features[iid]
        counts=defaultdict(int)
        for entity in entities:
            posting=postings[entity]
            if len(posting)>int(settings.get('hub_limit',100)):
                skipped+=1;continue
            for other in posting:
                if other != iid:counts[other]+=1
        for other in sorted(counts,key=lambda k:(-counts[k],k))[:cap]:
            pair=tuple(sorted((iid,other)))
            if pair in examined: continue
            examined.add(pair)
            oe,ot,os,of=features[other]; gap=max(0,start-of,os-end)
            if gap>window:continue
            overlap=jaccard(techniques,ot);entity_overlap=jaccard(entities,oe)
            time_score=1-gap/window if window else float(gap==0)
            score=0.45*overlap+0.4*entity_overlap+0.15*time_score
            if overlap < minimum or score < threshold:continue
            links.append({'source':pair[0],'target':pair[1],'score':round(score,4),'threshold':threshold,
                          'technique_overlap':round(overlap,4),'entity_overlap':round(entity_overlap,4),
                          'time_score':round(time_score,4),'time_gap_s':gap,
                          'shared_techniques':sorted(techniques&ot),'shared_entities':sorted(entities&oe),
                          'reason':f'Shared techniques and entities within {int(window)} seconds; weighted overlap meets threshold.',
                          'kind':'inferred_relationship_not_campaign_attribution'})
    links.sort(key=lambda l:(-l['score'],l['source'],l['target']))
    return {'links':links,'settings':settings,'candidate_pairs_evaluated':len(examined),'hub_postings_skipped':skipped,
            'interpretation':'Related incident hypotheses; incident identities and evidence are preserved.'}
