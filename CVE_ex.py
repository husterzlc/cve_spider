from CVE_json import craw
from multiprocessing import Pool,Manager,Lock
import os
import pickle
import functools
import signal
import copy

def cve_extract(b,d):
 filename = 'CVE_list_all.txt' # txt文件和当前脚本在同一目录下，所以不用写具体路径
 line_index=0
 if d[b]==-1:
     return 0
 index=d[b]-2
 with open(filename, 'r') as file_to_read:
  while True:
    lines = file_to_read.readline()# 整行读取数据
    if line_index<index:
      line_index=line_index+1
      continue
    line_index=line_index+1
    d[b]=line_index
    if not lines:
      d[b]=-1
      break
    if lines[0]=='N' and lines[1]=='a'and lines[2]=='m'and lines[3]=='e'and lines[4]==':' and int(lines[10:14])==(b+1999):
     pos=lines[6:19]
     strl1= "".join(pos)
     try:
       craw(strl1,lines[10:14])
     except Exception:
       with open("uncrawed.txt",'ab') as f:
                pickle.dump(strl1,f)
       pass

    
def terminate(d,m,sig_num, addtion):
    with open("log.txt",'wb') as f:
       d_temp=copy.deepcopy(d)
       pickle.dump(d_temp,f)
    for i in xrange(0,20):
        print d[i]   
    os.killpg(os.getpgid(os.getpid()),signal.SIGKILL)    
    m.shutdown()
    os._exit(0)
    
if __name__=="__main__":
    pool=Pool()
    m=Manager()
    d=m.dict()
    for j in xrange(0,20):
        d[j]=0
    handler=functools.partial(terminate,d,m)
    signal.signal(signal.SIGINT,handler)
    
    if  os.path.exists('log.txt'):
        with open("log.txt",'rb') as f:
             d=pickle.load(f)
             
    for i in xrange(1999,2019):
           pool.apply_async(cve_extract,args=(i-1999,d,))
    print "start"
    while True:
        tag=0
        for i in xrange(0,20):
          if d[i]==-1:
             continue
          else:
             tag=1
             break
        if tag==1:
          tag=0
        else:
          break
    with open("log.txt",'wb') as f:
        pickle.dump(d,f)
    print "down"

