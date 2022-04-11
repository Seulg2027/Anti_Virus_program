# -*-coding:utf-8 -*-
import sys, hashlib, os

VirusDB = []
# 악성코드의 데이터가 저장
vdb = []
# 악성코드의 파일 크기만 저장
vsize = []

def LoadVirusDB():
  fp = open('virus.db', 'rb')
  
  while True:
    line = fp.readline()
    if not line: break
    
    line = line.strip()
    VirusDB.append(line)
  
  fp.close()

def MakeVirusDB():
  for pattern in VirusDB:
    t = []
    pattern_str = pattern.decode('utf-8')
    v = pattern_str.split(':')
    t.append(v[1])
    t.append(v[2])
    vdb.append(t)
    
    size = int(v[0])
    if vsize.count(size) == 0:
      vsize.append(size)

def SearchVDB(fmd5):
  # vdb에 저장된 바이러스 해쉬값이 있다면 True 값 반환!!
  for t in vdb:
    if t[0] == fmd5:
      return True, t[1]
  return False, ''

if __name__ == '__main__':
  LoadVirusDB()
  MakeVirusDB()
  
  if len(sys.argv) != 2:
    print("Usage : antivirus.py [file]")
    exit(0)
  
  fname = sys.argv[1]
  
  size = os.path.getsize(fname)
  if vsize.count(size):
    fp = open(fname, 'rb')
    buf = fp.read()
    fp.close()
    
    m = hashlib.md5()
    m.update(buf)
    fmd5 = m.hexdigest()
    
    ret, vname = SearchVDB(fmd5)
    if ret == True:
      print("%s : %s" %(fname, vname))
      os.remove(fname)
    else:
      print("%s : ok" %(fname))
  else:
    print("%s : ok" %(fname))