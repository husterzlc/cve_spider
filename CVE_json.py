#coding:utf-8

from bs4 import BeautifulSoup
import requests
import codecs
import json
import chardet
#from multiprocessing import Lock

def craw(str1,year):
 print str1
 #漏洞编码
 cve_id = str1
 #相应漏洞URL
 url = 'http://cve.scap.org.cn/' + cve_id + '.html'
 file_name ='cve_'+year+'.json'
 #请求
 request = requests.get(url)
 #获得网页内容
 page = request.content#html内容
 #为方便查看HTML内容，将其存储于文件cve_txt中
 #创建soup对象
 soup = BeautifulSoup(page,"lxml")
 #所需要的内容在ul标签内，html文档中有多个ul标签，第二个是需要得到的
 ul_ = soup.find_all('ul')[1]
 info = {}#字典，key为漏洞编码，value为漏洞相关信息
 info_value = []
 #获得ul标签中href
 tag = []#列表，为漏洞的几个标签
 for a_ in ul_.find_all('a'):
   tag.append(a_['href'].strip().split("#")[1])

 for t in tag:
    content = soup.find(id = t)
    product_info = {}#字典，key为标签，value为标签下的所有信息
    all_cell = []#列表，所有项目信息
    #项目数
    num = len(content.find_all('h2'))
    if num==0:
        continue
    titles = content.find_all('h2')
    tables = content.find_all('table')
    for i in xrange(num):
        title = titles[i]#项目名称
        temp = title.text.strip().split()
        title = ''#存储标签下一级标题
        for j in xrange(1,len(temp)):
            title = title + temp[j]
        cell_info = {}
        table = tables[i]#项目下的table标签
        tab = []#保存表格中的信息
        for row in table.find_all('tr'):
            if title == u'CPE(受影响的平台与产品)':
                first = True
                for col in row.find_all('td'):
                    if first:
                       tmp = col.text.strip()
                       res=tmp[7:]
                       tab.append(res)
                       first = False
            elif title==u'相关参考':
                ul_2 = []#保存一行中的信息
                for col in row.find_all('li'):
                    t1 = col.text.replace("\r\n","")
                    t1 = t1.replace("\n","")
                    t1 = t1.replace("\t\t\t\t\t\t\t\t\t\t\t\t\t\t"," ")
                    ul_2.append(t1.strip())
                tab.append(ul_2)
            else:
                tr = []#保存一行中的信息
                for col in row.find_all('td'):
                    t1 = col.text.replace("\r\n","")
                    t1 = t1.replace("\n","")
                    t1 = t1.replace("\t\t\t\t\t\t\t\t\t\t\t\t\t\t"," ")
                    if t1 == u"文件下载:[点击下载]":
                        hf = col.find("a")["href"]
                        t1 = u"文件下载:" + hf
                    tr.append(t1.strip())
                tab.append(tr)
        cell_info[title] = tab
        all_cell.append(cell_info)
    product_info[t] = all_cell
    info_value.append(product_info)


 info[cve_id] = info_value


 #保存
# lock=Lock()
# lock.acquire()
 with codecs.open(file_name,'a','utf-8') as file_object:
    json.dump(info,file_object,indent=4,ensure_ascii=False)
 file_object2=open(file_name,'a')
 file_object2.write('\n')
 file_object2.close()
# lock.release()







