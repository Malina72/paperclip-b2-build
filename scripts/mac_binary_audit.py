"""Read Mach-O load commands as data; do not confuse otool's header with dependencies."""
import struct,posixpath
LOAD_DYLIB={0x0c,0x80000018,0x8000001f,0x20,0x80000023}
def macho_libraries(data):
 assert len(data)>=32 and data[:4]==b'\xcf\xfa\xed\xfe','Expected little-endian64bit Mach-O'
 assert struct.unpack_from('<I',data,4)[0]==0x0100000c,'Expected Apple ARM64'
 n,size=struct.unpack_from('<II',data,16);assert n<4096 and 32+size<=len(data)
 offset=32;libraries=[]
 for _ in range(n):
  command,length=struct.unpack_from('<II',data,offset);assert length>=8 and offset+length<=32+size
  if command in LOAD_DYLIB:
   assert length>=24;nameoff=struct.unpack_from('<I',data,offset+8)[0];assert 24<=nameoff<length
   raw=data[offset+nameoff:offset+length];assert b'\0'in raw
   libraries.append(raw.split(b'\0',1)[0].decode('utf8'))
  offset+=length
 assert offset==32+size and libraries,'Missing dylib inventory'
 return libraries
def system_libraries(libraries):
 assert libraries
 for name in libraries:
  assert name.startswith('/') and posixpath.normpath(name)==name,'Noncanonical dylib path: '+name
  assert name.startswith(('/usr/lib/','/System/Library/')),'Non-system dylib: '+name
 return libraries
def otool_libraries(text,binary_path):
 lines=text.splitlines();assert lines and lines[0]==str(binary_path)+':','Unexpected otool binary header'
 result=[]
 for line in lines[1:]:
  assert line.startswith(('\t',' ')) and ' (compatibility version 'in line,'Malformed dependency record'
  result.append(line.strip().split(' (compatibility version ',1)[0])
 return system_libraries(result)
