"""Bounded adjacency search and depth-constrained Dijkstra on evidence graphs."""
from collections import defaultdict, deque
import hashlib
import heapq
import json
import math
from bisect import bisect_left


class GraphIndex:
    def __init__(self, graph):
        self.nodes = {n['id']:n for n in graph['nodes']}
        self.edges, self.adjacency = {}, defaultdict(list)
        for original in graph['edges']:
            edge = dict(original)
            edge.setdefault('evidence_kind','hypothesis' if edge['kind']=='could_reach' else 'observed_association')
            edge['id'] = edge.get('id') or hashlib.sha256(json.dumps([edge['source'],edge['target'],edge['kind'],edge.get('relation')]).encode()).hexdigest()[:20]
            edge['cost'] = float(edge.get('cost', 4 if edge['kind']=='could_reach' else 2 if edge.get('evidence_kind')=='inferred' else 1))
            if not math.isfinite(edge['cost']) or edge['cost'] <= 0:
                raise ValueError('Graph costs must be finite and positive')
            if edge['source'] not in self.nodes or edge['target'] not in self.nodes:
                raise ValueError('Graph contains a dangling edge')
            self.edges[edge['id']] = edge
            edge['observation_times_ms'] = sorted(set(int(t) for t in edge.get('observation_times_ms',[])))
            self.adjacency[edge['source']].append((edge['target'],edge['id'],True))
            self.adjacency[edge['target']].append((edge['source'],edge['id'],False))

    def neighborhood(self, root, depth=2, limit=500, directed=False):
        if root not in self.nodes:
            raise KeyError(root)
        seen, edge_ids, queue, truncated = {root}, set(), deque([(root,0)]), False
        while queue:
            node, hops = queue.popleft()
            if hops >= depth:
                continue
            for neighbor, eid, forward in self.adjacency[node]:
                if directed and not forward:
                    continue
                if neighbor not in seen:
                    if len(seen) >= limit:
                        truncated = True
                        continue
                    seen.add(neighbor); queue.append((neighbor,hops+1))
                edge_ids.add(eid)
        return {'nodes':[self.nodes[n] for n in sorted(seen)],'edges':[self.edges[e] for e in sorted(edge_ids)],
                'depth':depth,'truncated':truncated,'total_nodes':len(self.nodes),'total_edges':len(self.edges)}

    def shortest_path(self, source, target, max_depth=6, directed=True, include_hypotheses=False):
        if source not in self.nodes or target not in self.nodes:
            raise KeyError('Unknown source or target')
        distances, previous = {(source,0):0.0}, {}
        queue = [(0.0,0,source)]
        while queue:
            cost,hops,node = heapq.heappop(queue)
            state=(node,hops)
            if cost != distances[state]: continue
            if node == target:
                nodes,edges=[node],[]
                while state in previous:
                    state,eid=previous[state];nodes.append(state[0]);edges.append(eid)
                return {'status':'found','algorithm':'depth_constrained_dijkstra','nodes':list(reversed(nodes)),
                        'edge_ids':list(reversed(edges)),'total_cost':round(cost,5),'hops':hops,
                        'interpretation':'Lowest configured evidence cost within depth; not proof of an attack path.'}
            if hops >= max_depth: continue
            for neighbor,eid,forward in self.adjacency[node]:
                edge=self.edges[eid]
                if directed and not forward: continue
                if not include_hypotheses and edge.get('evidence_kind')=='hypothesis': continue
                new=(neighbor,hops+1); candidate=cost+edge['cost']
                if candidate < distances.get(new,float('inf')):
                    distances[new]=candidate;previous[new]=(state,eid);heapq.heappush(queue,(candidate,hops+1,neighbor))
        return {'status':'not_found','algorithm':'depth_constrained_dijkstra','max_depth':max_depth}

    def temporal_path(self, source, target, start_ms, as_of_ms, max_depth=6):
        """Earliest-arrival path over recorded observation times, with waiting.

        Untimed/inferred/hypothesis edges are excluded. For each (node,hops), an
        earlier arrival dominates a later arrival. Never invent intermediate
        observations inside an aggregated first/last interval.
        """
        if source not in self.nodes or target not in self.nodes:
            raise KeyError('Unknown source or target')
        if start_ms > as_of_ms or not 1 <= max_depth <= 12:
            raise ValueError('Use ordered timestamps and depth 1..12')
        distance, previous = {(source,0):start_ms}, {}
        queue = [(start_ms,0,source)]
        while queue:
            arrival,hops,node = heapq.heappop(queue)
            state=(node,hops)
            if distance[state] != arrival:
                continue
            if node == target:
                nodes,edges,times = [node],[],[]
                while state in previous:
                    state,eid,observed = previous[state]
                    nodes.append(state[0]);edges.append(eid);times.append(observed)
                return {'status':'found','algorithm':'bounded_earliest_arrival',
                        'nodes':nodes[::-1],'edge_ids':edges[::-1], 'observation_times_ms':times[::-1],
                        'arrival_ms':arrival,'hops':hops,'as_of_ms':as_of_ms,
                        'interpretation':'Time-respecting observed associations; does not establish an attacker route.'}
            if hops >= max_depth:
                continue
            for neighbor,eid,forward in self.adjacency[node]:
                edge=self.edges[eid]
                if not forward or edge['evidence_kind'] in {'inferred','hypothesis'}:
                    continue
                times=edge['observation_times_ms'];position=bisect_left(times,arrival)
                if position == len(times) or times[position] > as_of_ms:
                    continue
                observed=times[position];new=(neighbor,hops+1)
                if observed < distance.get(new,float('inf')):
                    distance[new]=observed;previous[new]=(state,eid,observed)
                    heapq.heappush(queue,(observed,hops+1,neighbor))
        return {'status':'not_found','algorithm':'bounded_earliest_arrival','max_depth':max_depth,
                'as_of_ms':as_of_ms,'reason':'No ordered observed path; untimed, inferred and hypothesis edges excluded.'}


def weighted_jaccard(left, right):
    keys=set(left)|set(right)
    denominator=sum(max(left.get(k,0),right.get(k,0)) for k in keys)
    return sum(min(left.get(k,0),right.get(k,0)) for k in keys)/denominator if denominator else 0.0


def signal_similarity(left,right):
    def features(signal):
        result={}
        for key,weight in [('host',3),('user_name',3),('src_ip',1),('dst_ip',1),('technique',1)]:
            if signal.get(key): result[key+':'+str(signal[key])]=weight
        for identity in signal.get('process_keys') or []: result['process:'+identity]=5
        return result
    return weighted_jaccard(features(left),features(right))


def link_decision(left, right, relation, config):
    """Relation-specific gate, after SQL time/session and hub filtering.

    A shared external endpoint/account can span hosts: a universal Jaccard
    threshold incorrectly penalizes that intended relationship. Scores are
    association strengths, never probabilities or proof of common attribution.
    """
    score = signal_similarity(left, right)
    threshold = float(config.get('relation_thresholds', {}).get(
        relation, config.get('similarity_threshold', 0.3)))
    specific = relation in {'lateral', 'process_entity'}
    return {'accepted': specific or score >= threshold, 'similarity': score,
            'threshold': None if specific else threshold,
            'reason': ('specific process/logon evidence' if specific else
                       f'{relation} pivot passed time/hub guards; similarity {score:.4f}, threshold {threshold:.4f}')}
