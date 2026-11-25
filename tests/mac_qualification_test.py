"""Exercise the qualification pipeline using synthetic files and no native execution."""
import unittest,tempfile,pathlib,os,sys,runpy,json,subprocess
from unittest.mock import patch
from mac_binary_audit_test import fixture
SCRIPTS=pathlib.Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
class Pipeline(unittest.TestCase):
 def exercise(self,library='/usr/lib/libSystem.B.dylib',secret=False,new_finding=False):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);runner=root/'source/packages/paperclip-runner/runner';deps=runner/'target/release/deps';deps.mkdir(parents=True)
   (runner/'Cargo.lock').write_text('version = 4\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n')
   for name in ['rustls','webpki_roots']:(deps/('lib'+name+'-fixture.rlib')).write_bytes(b'fixture')
   (runner/'target/release/paperclip-runnerd').write_bytes(fixture([library])+(b'sk-proj-'+b'A'*50 if secret else b''))
   (root/'scripts').mkdir();(root/'scripts/b3-rust-versions.json').write_text('{"rustls":"0.23.46"}');(root/'pins.json').write_text('{}');(root/'security-review.json').write_text('{"reviewed_rust_finding_keys":[]}')
   def fake(args,**kw):
    cmd=str(args[0]);stdout=''
    if cmd=='cargo':stdout='rustls v0.23.46\n'
    elif cmd=='rustc':pass
    elif cmd.endswith('openssl'):stdout='Synthetic OpenSSL test double\n'
    elif cmd.endswith('/tls-tests'):stdout='test result: ok. 6 passed; 0 failed\n'
    elif cmd.endswith('/paperclip-runnerd'):stdout='{"fixture":true}'
    elif cmd.endswith('/otool'):stdout=str(args[-1])+':\n\t'+library+' (compatibility version 1.0.0, current version 1.0.0)\n'
    else:raise AssertionError('Unexpected external command '+cmd)
    return subprocess.CompletedProcess(args,0,stdout,'')
   previous=os.getcwd()
   try:
    os.chdir(root)
    with patch('platform.system',return_value='Darwin'),patch('platform.machine',return_value='arm64'),patch('subprocess.run',side_effect=fake),patch('audit_rust.audit_lock',return_value={'findings':[{'name':'fixture','version':'1.0.0','id':'NEW'}] if new_finding else []}),patch.dict(os.environ,{'GITHUB_REPOSITORY':'example/build','GITHUB_RUN_ID':'1','GITHUB_SHA':'a'*40}):
     runpy.run_path(str(SCRIPTS/'mac_runner_qualify.py'),run_name='__main__')
    proof=json.loads((root/'native-publication/verification.json').read_text());self.assertTrue(proof['pass']);self.assertFalse(any('key' in x.name for x in (root/'native-publication').iterdir()))
   finally:os.chdir(previous)
 def test_complete_synthetic_success(self):self.exercise()
 def test_non_system_dylib_rejected(self):
  with self.assertRaises(AssertionError):self.exercise(library='/opt/homebrew/lib/unsafe.dylib')
 def test_secret_marker_rejected(self):
  with self.assertRaises(AssertionError):self.exercise(secret=True)
 def test_new_advisory_rejected(self):
  with self.assertRaises(AssertionError):self.exercise(new_finding=True)
if __name__=='__main__':unittest.main()

class Preservation(unittest.TestCase):
 def test_preserved_without_execution(self):
  from preserve_native import prepare
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);binary=root/'synthetic';binary.write_bytes(fixture(['/usr/lib/libSystem.B.dylib']));out=root/'out';p=prepare(binary,out,'a'*40,'1');self.assertEqual(p['qualification'],'NOT_COMPLETED_DO_NOT_EXECUTE');self.assertEqual(len(list(out.iterdir())),2)
 def test_secret_not_preserved(self):
  from preserve_native import prepare
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);binary=root/'synthetic';binary.write_bytes(fixture(['/usr/lib/libSystem.B.dylib'])+b'sk-proj-'+b'A'*50)
   with self.assertRaises(AssertionError):prepare(binary,root/'out','a'*40,'1')
   self.assertFalse((root/'out').exists())
