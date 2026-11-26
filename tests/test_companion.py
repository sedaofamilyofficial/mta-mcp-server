"""Security regressions for the actual companion sources and HTTP process."""
import pathlib
from typing import Any
import unittest
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]

class SurfaceTests(unittest.TestCase):
    def test_resource_has_no_legacy_execution_or_key_generation(self):
        for path in (ROOT/'Resources/debugCompanion').rglob('*.lua'):
            source=path.read_text()
            self.assertNotIn('loadstring',source,path.name)
            self.assertNotIn('generateApiKey',source,path.name)

    def test_no_arbitrary_code_surface(self):
        meta = ET.parse(ROOT / 'Resources/debugCompanion/meta.xml').getroot()
        exposed = {node.get('function') for node in meta.findall('export')}
        self.assertNotIn('httpRun', exposed, 'Arbitrary Lua execution must not be exported')
        tools = (ROOT / 'MtaDebugCompanionMcp.Common/Tools/MtaDebugCompanionTools.cs').read_text()
        self.assertNotIn('RunCode(', tools, 'Arbitrary Lua execution must not be an MCP tool')

class LuaGatewayTests(unittest.TestCase):
    def setUp(self):
        from lupa.lua51 import LuaRuntime
        self.lua: Any = LuaRuntime(unpack_returned_tuples=True)
        self.source = ROOT / 'Resources/debugCompanion/server/gateway.lua'
        self.lua.execute('''
            root = {}; resourceRoot = {}; now = 10000; count = 0; calls = 0
            credentials = {account='pulsar_debug_gateway', apiKey=string.rep('a',64)}
            policy = {actions={}}; body = {operation='status'}; handlers = {}
            function fileExists(p) return true end
            function fileOpen(p) return p end
            function fileGetSize(p) return 32 end
            function fileRead(p,n) return p end
            function fileClose(p) end
            function fromJSON(s)
                if s == 'credentials.json' then return credentials end
                if s == 'policy.json' then return policy end
                if s == 'request' then return body end
                return nil
            end
            function toJSON(v) result = v; return '[response]' end
            function getTickCount() return now end
            function isGuestAccount(a) return a == 'guest' end
            function getAccountName(a) return a end
            function addEventHandler(e,r,fn) handlers[e]=fn end
            function getThisResource() return 'self' end
            function getElementsByType(t) local p={} for i=1,count do p[i]=i end return p end
            function getResources() return {'dev_probe', 'pulsar_core'} end
            function getResourceName(r) return r end
            function getResourceState(r) return 'running' end
            function getResourceFromName(r) if r=='missing' then return false end return r end
            function isResourceProtected(r) return r=='protected' end
            authority=true
            function hasObjectPermissionTo(...) return authority end
            function startResource(r) calls=calls+1; return true end
            function stopResource(r) calls=calls+1; return true end
            function restartResource(r) calls=calls+1; return true end
        ''')

    def load(self):
        self.assertTrue(self.source.is_file(), 'Authenticated HTTP router is missing')
        self.lua.execute(self.source.read_text())

    def request(self, account='pulsar_debug_gateway', key='a'*64):
        return self.lua.eval('httpGateway')(
            self.lua.table_from({'account':account, 'method':'POST', 'path':'/',
                                 'headers':self.lua.table_from({'api-key':key}), 'body':'request'}))

    def test_authentication_fails_closed(self):
        self.load()
        self.assertEqual(self.request('guest')['status'],401)
        self.assertEqual(self.request('other')['status'],401)
        self.assertEqual(self.request(key='wrong')['status'],401)
        self.assertEqual(self.request()['status'],200)
        self.assertEqual(self.lua.globals().result['players'],0)
        self.assertEqual(self.lua.globals().calls,0)

    def test_bounded_status_and_strict_request(self):
        self.load()
        self.assertEqual(self.request()['status'],200)
        result = self.lua.globals().result
        self.assertEqual(result['totalResources'],2)
        self.assertEqual(result['resources'][1]['name'],'dev_probe')
        self.lua.execute("now=now+1000; body={operation='status',resource='../secret'}")
        self.assertEqual(self.request()['status'],400)
        self.lua.execute("now=now+1000; body={operation='status',extra='bad'}")
        self.assertEqual(self.request()['status'],400)
        self.lua.execute("now=now+1000; body={operation='status',resource='missing'}")
        self.assertEqual(self.request()['status'],404)

    def test_missing_or_default_key_denies(self):
        for value in ['nil', "{account='pulsar_debug_gateway',apiKey='default'}"]:
            with self.subTest(value=value):
                self.setUp()
                self.lua.execute('credentials='+value)
                self.load()
                self.assertEqual(self.request()['status'],401)

    def test_log_cache_is_bounded_sanitized_and_rate_limited(self):
        self.load()
        handler = self.lua.globals().handlers['onDebugMessage']
        self.assertIsNotNone(handler, 'Bounded diagnostic log cache missing')
        for i in range(120):
            handler(f'warning {i} api_key=private-value 127.0.0.1 ' + 'b'*64,2,'test.lua',7)
        self.lua.execute("body={operation='logs',lines=50}")
        self.assertEqual(self.request()['status'],200)
        logs = self.lua.globals().result['logs']
        self.assertEqual(len(logs),50)
        self.assertNotIn('private-value',logs[1]['message'])
        self.assertNotIn('127.0.0.1',logs[1]['message'])
        self.assertNotIn('b'*64,logs[1]['message'])
        self.assertEqual(self.request()['status'],429)
        self.lua.execute("now=now+1000; body={operation='logs',lines=51}")
        self.assertEqual(self.request()['status'],400)

    def test_actions_require_policy_engine_authority_zero_online(self):
        cases = [('',403), ("policy.actions.dev_probe={restart=true}",200),
                 ("policy.actions.dev_probe={restart=true}; authority=false",403),
                 ("policy.actions.dev_probe={restart=true}; count=1",409),
                 ("policy.actions.pulsar_core={restart=true}; body.resource='pulsar_core'",403),
                 ("policy.actions.protected={restart=true}; body.resource='protected'",403),
                 ("policy.actions.missing={restart=true}; body.resource='missing'",404),
                 ("policy.actions.dev_probe={restart=true}; body.action='shell'",400)]
        for setup, expected in cases:
            with self.subTest(setup=setup):
                self.setUp()
                self.lua.execute("body={operation='action',resource='dev_probe',action='restart'}; "+setup)
                self.load()
                self.assertEqual(self.request()['status'],expected)
                self.assertEqual(self.lua.globals().calls,1 if expected==200 else 0)
                if expected==200:
                    self.lua.execute('now=now+1000')
                    self.assertEqual(self.request()['status'],429)
                    self.assertEqual(self.lua.globals().calls,1)

    def test_protected_names_case_insensitive(self):
        self.lua.execute("policy.actions.PULSAR_CORE={restart=true}; body={operation='action',resource='PULSAR_CORE',action='restart'}")
        self.load()
        self.assertEqual(self.request()['status'],403)

    def test_false_log_limit_rejected(self):
        self.lua.execute("body={operation='logs',lines=false}")
        self.load()
        self.assertEqual(self.request()['status'],400)

if __name__ == '__main__':
    unittest.main()
