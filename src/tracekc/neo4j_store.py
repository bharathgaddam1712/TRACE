"""Optional Neo4j graph persistence. Parameterized, indexed, batched and namespace-scoped."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import uuid

from tracekc.config import load_env
from tracekc.graph_algorithms import GraphIndex


class Neo4jStore:
    def __init__(self, out_dir:Path, driver=None):
        load_env()
        self.dataset=hashlib.sha256(str(out_dir.resolve()).encode()).hexdigest()[:24]
        self.database=os.environ.get('NEO4J_DATABASE','neo4j')
        if driver is None:
            from neo4j import GraphDatabase
            password=os.environ.get('NEO4J_PASSWORD','')
            if not password:raise ValueError('Set NEO4J_PASSWORD in the repository-root .env')
            driver=GraphDatabase.driver(os.environ.get('NEO4J_URI','bolt://127.0.0.1:7687'),
                                       auth=(os.environ.get('NEO4J_USER','neo4j'),password),
                                       connection_timeout=10,max_connection_pool_size=8)
        self.driver=driver

    def close(self):self.driver.close()

    def query(self, query, **parameters):
        records,summary,keys=self.driver.execute_query(query,parameters_=parameters,database_=self.database)
        return [record.data() for record in records]

    def sync(self, out_dir:Path):
        self.driver.verify_connectivity()
        self.query('CREATE CONSTRAINT trace_dataset_id IF NOT EXISTS FOR (d:TraceDataset) REQUIRE d.id IS UNIQUE')
        self.query('CREATE CONSTRAINT trace_node_identity IF NOT EXISTS FOR (n:TraceNode) REQUIRE (n.scope,n.id) IS UNIQUE')
        generation=uuid.uuid4().hex;nodes=edges=incidents=0
        index=json.loads((out_dir/'index.json').read_text(encoding='utf-8-sig'))
        for row in index:
            incident=json.loads((out_dir/'incidents'/f"{row['id']}.json").read_text(encoding='utf-8-sig'))
            scope=f"{self.dataset}:{generation}:{incident['fingerprint']}"
            indexed=GraphIndex(incident['graph'])
            graph={'nodes':list(indexed.nodes.values()),'edges':list(indexed.edges.values())};incidents+=1
            for offset in range(0,len(graph['nodes']),500):
                batch=[{'id':n['id'],'data':json.dumps(n),'type':n['type']} for n in graph['nodes'][offset:offset+500]]
                self.query('UNWIND $rows AS row MERGE (n:TraceNode {scope:$scope,id:row.id}) SET n.dataset=$dataset,n.generation=$generation,n.type=row.type,n.data=row.data',rows=batch,scope=scope,dataset=self.dataset,generation=generation)
                nodes+=len(batch)
            for offset in range(0,len(graph['edges']),500):
                batch=[{'id':e['id'],'source':e['source'],'target':e['target'],'cost':e['cost'],'data':json.dumps(e)} for e in graph['edges'][offset:offset+500]]
                self.query('UNWIND $rows AS row MATCH (a:TraceNode {scope:$scope,id:row.source}) WITH a,row MATCH (b:TraceNode {scope:$scope,id:row.target}) MERGE (a)-[r:TRACE_LINK {id:row.id}]->(b) SET r.cost=row.cost,r.data=row.data',rows=batch,scope=scope)
                edges+=len(batch)
        self.query('MERGE (d:TraceDataset {id:$dataset}) SET d.generation=$generation',dataset=self.dataset,generation=generation)
        return {'backend':'neo4j','dataset':self.dataset,'generation':generation,'incidents':incidents,'nodes':nodes,'edges':edges}

    def scope(self,fingerprint):
        rows=self.query('MATCH (d:TraceDataset {id:$dataset}) RETURN d.generation AS generation',dataset=self.dataset)
        if not rows:raise ValueError('Graph not synchronized; run tracekc graph-sync for this output directory')
        return f"{self.dataset}:{rows[0]['generation']}:{fingerprint}"

    def load_graph(self,fingerprint):
        scope=self.scope(fingerprint)
        nodes=self.query('MATCH (n:TraceNode {scope:$scope}) RETURN n.data AS data',scope=scope)
        edges=self.query('MATCH (a:TraceNode {scope:$scope})-[r:TRACE_LINK]->(b:TraceNode {scope:$scope}) RETURN r.data AS data',scope=scope)
        if not nodes:raise ValueError('Incident not synchronized in the active graph generation')
        return {'nodes':[json.loads(r['data']) for r in nodes],'edges':[json.loads(r['data']) for r in edges]}

    def neighborhood(self,fingerprint,root,depth=2,limit=500):
        scope=self.scope(fingerprint)
        found=self.query('MATCH (n:TraceNode {scope:$scope,id:$id}) RETURN n.data AS data',scope=scope,id=root)
        if not found:raise KeyError(root)
        nodes={root:json.loads(found[0]['data'])};edges={};frontier=[root];truncated=False
        for _ in range(depth):
            if not frontier:break
            rows=self.query('UNWIND $frontier AS id MATCH (a:TraceNode {scope:$scope,id:id})-[r:TRACE_LINK]-(b:TraceNode {scope:$scope}) RETURN DISTINCT b.data AS node,r.data AS edge LIMIT $cap',frontier=frontier,scope=scope,cap=limit*8)
            following=[]
            if len(rows)>=limit*8:truncated=True
            for row in rows:
                node,edge=json.loads(row['node']),json.loads(row['edge'])
                if node['id'] not in nodes:
                    if len(nodes)>=limit:truncated=True;continue
                    nodes[node['id']]=node;following.append(node['id'])
                edges[edge['id']]=edge
            frontier=following
        return {'nodes':list(nodes.values()),'edges':list(edges.values()),'depth':depth,'truncated':truncated,'backend':'neo4j'}
