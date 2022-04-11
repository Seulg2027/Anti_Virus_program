import hashlib
import zlib

def DecodeKMD(fname):
  try:
    fp = open(fname, 'rb')
    buf = fp.read()
    fp.close()
    
    buf2 = buf[:-32]
    fmd5 = buf[-32:]
    
    f = buf2
    for i in range(3):
      md5 = hashlib.md5()
      md5.update(f)
      f = md5.hexdigest()
    
    if f != fmd5:
      raise SyntaxError
    
    buf3 = ''
    for c in buf2[4:]:
      buf3 += chr(ord(c) ^ 0xFF)
    
    buf4 = zlib.decompress(buf3)
    return buf4
  except:
    pass
  
  return None