"""Run the fixed bootstrap with Lua 5.1; no real accounts or MTA process."""
from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime
ROOT=Path(__file__).resolve().parents[1]

class BootstrapTests(unittest.TestCase):
    def test_fixed_account_bootstrap_is_verified_and_idempotent(self):
        source=ROOT/'Resources/debugBootstrap/server/bootstrap.lua'
        self.assertTrue(source.is_file(),'Dedicated fixed-account bootstrap missing')
        for exists,password_ok,expected_add,ready in [(False,False,1,True),(True,True,0,True),(True,False,0,False)]:
            with self.subTest(exists=exists,password_ok=password_ok):
                lua=LuaRuntime(unpack_returned_tuples=True); lua.execute('''
                    resourceRoot={}; callbacks={}; adds=0; writes=0; passwordOk=false; exists=false
                    function addEventHandler(e,r,fn) callbacks[e]=fn end
                    function fileExists(p) return true end
                    function fileOpen(p) return p end
                    function fileGetSize(p) return 1 end
                    function fileRead(p,n) return 'private' end
                    function fileClose(p) end
                    function fromJSON(v) return {account='pulsar_debug_gateway',password=string.rep('a',64)} end
                    function toJSON(v) return '[{}]' end
                    function getAccount(name,password)
                        if not exists then return false end
                        if not password or passwordOk then return {} end
                        return false
                    end
                    function addAccount(name,password) adds=adds+1; exists=true; passwordOk=true; return {} end
                    function fileCreate(p) writes=writes+1; return p end
                    function fileWrite(p,t) end
                    function outputServerLog(t) assert(not t:find(string.rep('a',64),1,true)) end
                ''')
                lua.globals()['exists']=exists; lua.globals()['passwordOk']=password_ok
                lua.execute(source.read_text()); lua.globals()['callbacks']['onResourceStart']()
                self.assertEqual(lua.globals()['adds'],expected_add)
                self.assertEqual(lua.globals()['writes'],1 if ready else 0)
                lua.globals()['callbacks']['onResourceStart']()
                self.assertEqual(lua.globals()['adds'],expected_add)

if __name__=='__main__': unittest.main()
