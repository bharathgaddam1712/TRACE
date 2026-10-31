"""Bounded adjacency search and depth-constrained Dijkstra on evidence graphs."""
from collections import defaultdict, deque
import hashlib
import heapq
import json
import math


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
