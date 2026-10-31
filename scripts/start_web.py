"""Start the built Next.js console and TRACE API on localhost, with hidden Windows processes."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlparse
import psutil

from tracekc.config import PROJECT_ROOT, load_env
from tracekc.materialize import write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',default=str(Path(os.environ.get('LOCALAPPDATA',Path.home()/'.cache'))/'TRACE/firex-full-optimized'))
    parser.add_argument('--port',type=int,default=3000)
    parser.add_argument('--api-port',type=int,default=8001)
    args=parser.parse_args();output=Path(args.out).resolve()
    if not (output/'index.json').exists():
        raise ValueError('No completed pipeline results in '+str(output))
    frontend=PROJECT_ROOT/'frontend'
    if not (frontend/'.next/BUILD_ID').exists():
        raise ValueError('Build frontend first: cd frontend; npm ci; npm run build')
    for port in (args.port,args.api_port):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',port))
    load_env();flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
    logs=output/'ui-logs';logs.mkdir(exist_ok=True)
    api_log=(logs/'api.log').open('ab')
    web_log=(logs/'web.log').open('ab')
    api=subprocess.Popen([sys.executable,'-m','tracekc','serve','--out',str(output),'--port',str(args.api_port)],
                         cwd=PROJECT_ROOT,stdout=api_log,stderr=subprocess.STDOUT,creationflags=flags)
    env=os.environ.copy();env['TRACE_API_URL']=f'http://127.0.0.1:{args.api_port}'
    env.pop('SARVAM_API_KEY',None);env['NEXT_TELEMETRY_DISABLED']='1'
    web=subprocess.Popen(['node',str(frontend/'node_modules/next/dist/bin/next'),'start','--hostname','127.0.0.1','--port',str(args.port)],
                         cwd=frontend,env=env,stdout=web_log,stderr=subprocess.STDOUT,creationflags=flags)
    api_log.close();web_log.close()
    write_json(output/'ui_processes.json',{'api_pid':api.pid,'web_pid':web.pid,'api_port':args.api_port,'web_port':args.port})
    deadline=time.monotonic()+60
    try:
        for url in (f'http://127.0.0.1:{args.api_port}/health',f'http://127.0.0.1:{args.port}'):
            while True:
                if api.poll() is not None or web.poll() is not None:
                    raise RuntimeError('A server exited; inspect '+str(logs))
                try:
                    headers={}
                    if args.api_port==urlparse(url).port and env.get('TRACE_API_TOKEN'):
                        headers['Authorization']='Bearer '+env['TRACE_API_TOKEN']
                    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=3) as response:
                        if response.status==200:break
                except (OSError,ValueError):
                    if time.monotonic()>deadline:raise TimeoutError('Server readiness timed out; inspect '+str(logs))
                    time.sleep(.5)
    except BaseException:
        for process in (api,web):
            try:
                parent=psutil.Process(process.pid)
                for child in parent.children(recursive=True):child.terminate()
                parent.terminate()
            except psutil.NoSuchProcess:
                pass
        raise
    print(f'TRACE console: http://127.0.0.1:{args.port}')
    print(f'TRACE API: http://127.0.0.1:{args.api_port}')


if __name__=='__main__':
    main()
