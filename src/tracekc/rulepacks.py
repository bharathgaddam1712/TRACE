"""Import only compiler-compatible SigmaHQ rules, retaining a complete rejection inventory."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from collections import Counter
import yaml

from tracekc.sigma import parse_rule, load_rules


def import_sigma(source:Path,target:Path):
    if target.exists() and any(target.iterdir()):
        raise ValueError('Import destination must be empty; review/update rule packs in a fresh directory')
    target.mkdir(parents=True,exist_ok=True)
    commit=subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    manifest={'repository':'https://github.com/SigmaHQ/sigma','commit':commit,'license':'DRL-1.1',
              'accepted':[],'rejected':[],'excluded':[]}
    for path in sorted((source/'rules').rglob('*.yml')):
        relative=path.relative_to(source).as_posix()
        try:
            docs=list(yaml.safe_load_all(path.read_text(encoding='utf-8-sig')))
            for doc in docs:
                if not doc:continue
                if doc.get('status') not in {'stable','test'}:
                    manifest['excluded'].append({'source':relative,'reason':'status is not stable/test'});continue
                try:
                    rule=parse_rule(doc,relative)
                    # YAML is data; no upstream scripts are executed.
                    output=target/(hashlib.sha256(relative.encode()).hexdigest()[:12]+'.yml')
                    output.write_text(yaml.safe_dump(doc,sort_keys=False,allow_unicode=True),encoding='utf-8')
                    manifest['accepted'].append({'source':relative,'id':rule.id,'title':rule.title,'author':rule.author,'techniques':rule.techniques,'file':output.name})
                except (ValueError,TypeError,KeyError,AttributeError) as exc:
                    manifest['rejected'].append({'source':relative,'id':doc.get('id'),'reason':str(exc)})
        except (yaml.YAMLError,UnicodeError) as exc:
            manifest['rejected'].append({'source':relative,'reason':str(exc)})
    rules,errors=load_rules(target)
    if errors:raise ValueError('Imported rule dependencies failed: '+str(errors[:10]))
    shutil.copy2(source/'LICENSE',target/'LICENSE')
    manifest['summary']={'enabled':len(rules),'unsupported':len(manifest['rejected']),'excluded_status':len(manifest['excluded']),
                         'techniques':len({t for r in rules.values() for t in r.techniques})}
    manifest['unsupported_reason_counts']=dict(Counter(item['reason'].split(' on ')[0] for item in manifest['rejected']))
    (target/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    return manifest['summary']
