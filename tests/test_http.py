"""Real HTTP MCP process tests; only MTA's engine boundary is stubbed."""
import base64
import contextlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error

ROOT=pathlib.Path(__file__).resolve().parents[1]
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); return s.getsockname()[1]

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dotnet=os.environ['PULSAR_TEST_DOTNET']
        cls.tmp=tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        config=pathlib.Path(cls.tmp.name)
        cls.token=secrets.token_hex(32); cls.api=secrets.token_hex(32); cls.password=secrets.token_hex(32)
        for name,value in [('bearer',cls.token),('api-key',cls.api),('password',cls.password)]:
            (config/name).write_text(value)
        (config/'policy.json').write_text('{"actions":{}}')
        cls.requests=[]
        class Mta(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                payload=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                cls.requests.append((self.path,dict(self.headers),payload))
                data=json.dumps({'schema':'pulsar.debug.v1','players':0,'resources':[]}).encode()
                self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
            def log_message(self,*args): pass
        cls.mta=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mta)
        cls.thread=threading.Thread(target=cls.mta.serve_forever,daemon=True); cls.thread.start()
        cls.port=free_port(); cls.url=f'http://127.0.0.1:{cls.port}/mcp'
        env=os.environ.copy(); env.update(CREDENTIALS_DIRECTORY=str(config),PULSAR_GATEWAY_CONFIG=str(config),
            PULSAR_GATEWAY_PORT=str(cls.port),PULSAR_MTA_PORT=str(cls.mta.server_port),
            ASPNETCORE_URLS=f'http://127.0.0.1:{cls.port}',DOTNET_GENERATE_ASPNET_CERTIFICATE='false')
        cls.proc=subprocess.Popen([cls.dotnet,str(ROOT/'MtaDebugCompanionMcp.Http/bin/Release/net10.0/MtaDebugCompanionMcp.Http.dll')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',cls.port),.1): break
            except OSError:
                if cls.proc.poll() is not None: raise RuntimeError('MCP host terminated during startup')
                time.sleep(.1)
        else: raise RuntimeError('MCP host startup timed out')
    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate(); cls.proc.wait(timeout=10); cls.mta.shutdown(); cls.mta.server_close(); cls.tmp.cleanup()
    def rpc(self,method,params=None,*,auth=True,origin=None,path='/mcp'):
        data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or {}}).encode()
        headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'}
        if auth: headers['Authorization']='Bearer '+self.token
        if origin: headers['Origin']=origin
        try:
            with urllib.request.urlopen(urllib.request.Request(self.url.removesuffix('/mcp')+path,data,headers),timeout=8) as r:
                raw=r.read().decode(); value=json.loads(raw) if not raw.startswith('event:') else json.loads(next(l[5:].strip() for l in raw.splitlines() if l.startswith('data:')))
                return r.status,value
        except urllib.error.HTTPError as e: return e.code,None
    def test_ingress_auth_and_origin(self):
        self.assertEqual(self.rpc('tools/list',auth=False)[0],401)
        self.assertEqual(self.rpc('tools/list',origin='https://evil.invalid')[0],403)
    def test_safe_discovery(self):
        status,body=self.rpc('tools/list')
        self.assertEqual(status,200)
        self.assertEqual(sorted(t['name'] for t in body['result']['tools']),['GetLogs','GetRuntimeStatus','ResourceAction'])
    def test_diagnostics_use_separate_mta_auth(self):
        status,body=self.rpc('tools/call',{'name':'GetRuntimeStatus','arguments':{}})
        self.assertEqual(status,200)
        self.assertFalse(body.get('error') or body.get('result',{}).get('isError'))
        path,headers,payload=self.requests[-1]
        self.assertEqual(path,'/pulsar_debug_gateway/')
        self.assertEqual(payload,{'operation':'status'})
        expected='Basic '+base64.b64encode(('pulsar_debug_gateway:'+self.password).encode()).decode()
        self.assertTrue(headers.get('Authorization')==expected,'Dedicated MTA Basic identity missing')
        self.assertTrue(headers.get('api-key')==self.api,'Independent resource key missing')
        self.assertNotIn(self.token,json.dumps(headers))
    def test_mutation_denied_before_mta(self):
        before=len(self.requests)
        status,body=self.rpc('tools/call',{'name':'ResourceAction','arguments':{'name':'dev_probe','action':'restart'}})
        self.assertEqual(status,200)
        self.assertTrue(body.get('error') or body.get('result',{}).get('isError'))
        self.assertEqual(len(self.requests),before)

if __name__=='__main__': unittest.main()
