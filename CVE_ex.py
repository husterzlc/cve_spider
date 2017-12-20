from CVE_json import craw
from multiprocessing import Pool
import os


def cve_extract(b,index):
 global f_log
 filename = 'CVE_list_all.txt' # txt文件和当前脚本在同一目录下，所以不用写具体路径
 pos = []
 line_index=0

 with open(filename, 'r') as file_to_read:
  while True:
    lines = file_to_read.readline()# 整行读取数据
    if line_index<index:
      line_index=line_index+1
      continue
    line_index=line_index+1
    f_log=open('log_'+str(b)+".txt",'w')
    f_log.write(str(line_index))
    f_log.close()
    if not lines:
      f_log=open('log_'+str(b)+".txt")
      f_log.write("-1")
      break
    
    if lines[0]=='N' and lines[1]=='a'and lines[2]=='m'and lines[3]=='e'and lines[4]==':' and int(lines[10:14])==b:
     pos=lines[6:19]
     str1= "".join(pos)
     try:
      craw(str1,lines[10:14])
     except Exception:
      pass
    
if  __name__=="__main__":
    pool=Pool(processes=20)
    for i in xrange(1999,2019):
        if not os.path.exists('log_' + str(i) + ".txt"):
            f_log = open("log_" + str(i) + ".txt", 'w')
            f_log.write("0")
            f_log.close()
            index =0
        else:
            f_log=open('log_'+str(i)+".txt","r")
            lines = f_log.readline()
            f_log.close()
            index = int(lines)

        if index==-1:
           continue
        pool.apply_async(cve_extract,args=(i,index))
    print "start"
    pool.close()
    pool.join()
    print "down"


