import sys, hashlib, os, time

start = time.time()

VirusDB = [
  '44d88612fea8a8f36de82e1278abb02f:EICAR Test',
  '77bff0b143e4840ae73d4582a8914a43:Dummy Test'
]

# 악성코드의 데이터가 저장
vdb = []
# 악성코드의 파일 크기만 저장
vsize = []

def MakeVirusDB():
  for pattern in VirusDB:
    t = []
    v = pattern.split(':')
    t.append(v[0])
    t.append(v[1])
    vdb.append(t)

def SearchVDB(fmd5):
  # vdb에 저장된 바이러스 해쉬값이 있다면 True 값 반환!!
  for t in vdb:
    if t[0] == fmd5:
      return True, t[1]
  return False, ''

if __name__ == '__main__':
  MakeVirusDB()
  
  if len(sys.argv) != 2:
    print("Usage : antivirus.py [file]")
    exit(0)
  
  fname = sys.argv[1]
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
  print(time.time() - start, "초가 걸렸습니다")