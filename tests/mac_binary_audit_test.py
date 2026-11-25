import unittest,pathlib,sys,struct
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from mac_binary_audit import macho_libraries,system_libraries,otool_libraries
def fixture(names):
 commands=[]
 for name in names:
  raw=name.encode()+b'\0';length=(24+len(raw)+7)//8*8;commands.append(struct.pack('<IIIIII',0x0c,length,24,0,0,0)+raw+b'\0'*(length-24-len(raw)))
 return struct.pack('<IIIIIIII',0xfeedfacf,0x0100000c,0,2,len(commands),sum(map(len,commands)),0,0)+b''.join(commands)
class Audit(unittest.TestCase):
 def test_header_is_not_a_dylib(self):
  p='/Users/runner/work/recipe/source/runnerd';s=p+':\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n';self.assertEqual(otool_libraries(s,p),['/usr/lib/libSystem.B.dylib'])
 def test_real_macho_system_libraries(self):self.assertEqual(system_libraries(macho_libraries(fixture(['/usr/lib/libSystem.B.dylib','/System/Library/Frameworks/Security.framework/Versions/A/Security'])))[0],'/usr/lib/libSystem.B.dylib')
 def test_homebrew_dependency_denied(self):
  with self.assertRaises(AssertionError):system_libraries(macho_libraries(fixture(['/opt/homebrew/lib/unsafe.dylib'])))
 def test_owner_directory_dependency_denied(self):
  with self.assertRaises(AssertionError):system_libraries(macho_libraries(fixture(['/Users/runner/unsafe.dylib'])))
 def test_rpath_dependency_denied(self):
  with self.assertRaises(AssertionError):system_libraries(macho_libraries(fixture(['@rpath/unsafe.dylib'])))
 def test_path_traversal_denied(self):
  with self.assertRaises(AssertionError):system_libraries(['/usr/lib/../../opt/unsafe.dylib'])
 def test_truncated_binary_denied(self):
  with self.assertRaises((AssertionError,struct.error)):macho_libraries(fixture(['/usr/lib/libSystem.B.dylib'])[:-1])
 def test_wrong_platform_denied(self):
  with self.assertRaises(AssertionError):macho_libraries(b'\x7fELF'+bytes(100))
if __name__=='__main__':unittest.main()
