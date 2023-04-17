import json
import socket
import os
import sys
import time
import zlib
from threading import Thread
import whois
import re
import requests
from bs4 import BeautifulSoup
from lxml import etree

# 探测开放的端口



#全局请求头，供爬虫使用
head = {
       'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.69',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
       'referer':'',         #该请求没有来源网页可不填
       'Accept-Language': 'en-US,en;q=0.8',
       'Cache-Control': 'max-age=0',
       'Connection': 'keep-alive',
       'Referer': 'http://www.baidu.com/',
       'Cookie': 'BAIDUID=CF948A73765852480FDDB76FA11E55A4:FG=1; BIDUPSID=CF948A73765852480FDDB76FA11E55A4; PSTM=1662196505; BDUSS=hxallQS2ExNGlZazFnSjBJUFlzcXN-azBkWTR-ZXlST0RudWpiN2pLeVFpaU5rRVFBQUFBJCQAAAAAAAAAAAEAAADwKqKPwuWw19TawrfJzwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJD9-2OQ~ftjZF; BDUSS_BFESS=hxallQS2ExNGlZazFnSjBJUFlzcXN-azBkWTR-ZXlST0RudWpiN2pLeVFpaU5rRVFBQUFBJCQAAAAAAAAAAAEAAADwKqKPwuWw19TawrfJzwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJD9-2OQ~ftjZF; BD_UPN=12314753; BDORZ=B490B5EBF6F3CD402E515D22BCDA1598; BA_HECTOR=25a4ala4ak0k0k21050185bm1i0uaga1m; ZFY=O5QSY7gWVWALv3HOxuDXPxl0SWVMgskl:AIWt:B03d67E:C; BAIDUID_BFESS=CF948A73765852480FDDB76FA11E55A4:FG=1; BD_CK_SAM=1; PSINO=1; delPer=0; H_PS_PSSID=38185_36545_37555_38113_38125_37861_38170_38289_38379_36804_37934_38312_38382_38285_26350_38282_37881; H_PS_645EC=cc640b%2BojxktnIMWy808%2B%2FnR%2B6JhW%2B1%2Fv24kw9c2ogA6q9w7IFNOVyLb86g; BD_HOME=1; __bid_n=183d6490c8ef6ce11b4207; ab_sr=1.0.1_ZWRkZDZjNzQzODMxZjQwMzVjODdkYzFhYmJjNzMzZjRjMmVjMmE1MjdkYjUxYTE5MWZlNDQ3YzAwZDg5NGEyZWI5MmQ1ZGQ3YjY2ZjYyMzc3MDY1NTc2MzliMDM4YjVjMDExZjAwNWE3MTNmMmI1ZDk0MDA2OGI3Y2QyNzdkN2FiODZhZjJiZjQxMDQxYzY1NDkzOGRlMWZlNmZkNTk2ZmJhOGM1NjdjMTY4NDNlYWI4NmQ2NjQzNjJjMDY4NmQy',
    }



def check_port(ip):

    global f
    global open_list
    result = '未检测'
    dic = open('dic/port.txt', 'r')

    if ip.count('.')<1:
        print('您输入的可能不是一个正确的域名，请重新输入')
        sys.exit()
    open_list = []
    for port1 in dic.readlines():
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 模板写法
        port = int(port1)  # 将字符串转换成整数型
        try:
            sk.settimeout(0.2)  # 设置超时时间
            sk.connect((ip, port))  # 测试端口是否开放，没有开放的话会爆出异常，所以要try
            result = '   --------------------开放'
            open_list.append(port)
            f = open('result/' + ip + '.txt', 'a')  # 创建一个文件，以ip命名，追加写入的方式打开
            f.write(str(port) + result + '\n')  # 将结果保存到txt文档中
        except Exception:
            result = '   关闭'
        sk.close()
        print(str(port) + result)  # 输出每个端口的结果在页面上

    f.write('开放端口有：  '+str(open_list))
    f.write('\n')
    f.write('------------------------------------------------端口探测结束---------------------------------------------------')
    f.write('\n')
    f.close()
    print('--------端口开放情况检测完成-------')


# whois查询
def scan_whois(domain):
    f = open('result/' + domain + '.txt', 'a')
    info = whois.whois(domain)  # Info返回了所有的whois查询信息，可根据需要选择想要提取的查询方法
    whoisInfo = {}
    try:
        whoisInfo.update({'域名': str(info['domain_name'])})
        whoisInfo.update({'注册人': info['registrar']})
        whoisInfo.update({'更新日期': str(info['updated_date'])})
        whoisInfo.update({'创建日期': str(info['creation_date'])})
        whoisInfo.update({'转介地址': str(info['referral_url'])})
        whoisInfo.update({'到期日期': str(info['expiration_date'])})
        whoisInfo.update({'服务器名字': str(info['name_servers'])})
        whoisInfo.update({'邮箱': str(info['emails'])})
        whoisInfo.update({'域名系统安全协议': info['dnssec']})
        whoisInfo.update({'国家': info['country']})
        whoisInfo.update({'org': info['org']})
        whoisInfo.update({'address': str(info['address'])})
        whoisInfo.update({'city': str(info['city'])})
        whoisInfo.update({'state': info['state']})
        whoisInfo.update({'registrant_postal_code': str(info['registrant_postal_code'])})
        whoisInfo.update({'status': str(info['status'])})
    except:
        print()

    print(whoisInfo)
    f.write(str(info))
    f.write('\n\n\n\n')
    for key, value in whoisInfo.items():
        f.write('--' + str(key) + '--' + ':      ' + str(value) + '\n')

    f.write('\n\n')
    f.write(
        '------------------------------------------------whois查询结束---------------------------------------------------')
    f.close()
    print('--------whois查询完成-------')


# 检查cdn是否存在
def check_cdn(url):
    global result
    a = os.popen('nslookup ' + url)
    response = a.read()
    # print(response)
    ip_addr = re.findall(r'\d\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response, re.S)  # 这个表达式的意思是提取出以x.x.x.x形式的内容
    # 如果不使用re.S参数，则只在每一行内进行匹配，如果一行没有，就换下一行重新开始。
    # 而使用re.S参数以后，正则表达式会将这个字符串作为一个整体，在整体中进行匹配。

    # print(ip_addr)
    # print(type(ip_addr))
    # print(len(ip_addr))
    if len(ip_addr) > 2:
        result = '存在cdn'
    elif len(ip_addr) == 2:
        result = '不存在cdn'
    elif len(ip_addr) < 2:
        result = '未知错误，请检查目标地址是否正确'
        sys.exit()
    print(response)
    print(result)
    f = open('result/' + url + '.txt', 'a')
    f.write('\n\n\n\n')
    f.write('cdn探测结果如下：'+'\n')
    f.write(response)
    f.write(
        '------------------------------------------------cdn探测结束---------------------------------------------------')
    f.write('\n')
    f.write('-----------------' + result+'\n')
    f.write('\n\n\n\n')
    f.close()
    print('--------cdn查询完成-------')


# 探测网站子域名（利用爬虫）
def scan_domain_path(url):
    print(url.split('.', 4)[1])
    #截取输入的url关键词，用于后面筛选爬出来的子域名
    a=url.split('.', 4)
    url_str=url.split('.', 4)[1]
    file = open('result/' + url + '.txt', 'a',encoding='gb18030',errors='ignore')    #这里写编码是为了防止写入过程中报错
    sites = []
    for i in range(10):
        # https://cn.bing.com/search?q=inurl+www.hpcgc.com
        # https://cn.bing.com/search?q=inurl+www.hpcgc.com&qs=n&sp=-1&lq=0&pq=inurl+www.hpcgc.com&sc=10-19&sk=&cvid=BE444BD0574E439AA1B809F19B55444A&ghsh=0&ghacc=0&ghpl=&first=1&FORM=PERE
        # 'https://cn.bing.com/search?q=inurl'+url+'&first='10*i
        # https://cn.bing.com/search?q=inurl+www.hpcgc.com&qs=n&sp=-1&lq=0&pq=inurl+www.hpcgc.com&sc=10-19&sk=&cvid=BE444BD0574E439AA1B809F19B55444A&ghsh=0&ghacc=0&ghpl=&first=20&FORM=PERE1

        target = 'https://cn.bing.com/search?q=inurl+{0}&first={1}'.format(url, i*10)
        # target = "https://www.baidu.com/s?wd=inurl%3A{0}&pn={1}0".format(url, i)
        print('第'+str(i+1)+'页'+':     '+target)

        #target2="https://www.baidu.com/s?wd=inurl%3Awww.xiaodi8.com&pn=0"
		#https://www.baidu.com/s?wd=inurl%3Awww.xiaodi8.com&pn=0
		#https://www.baidu.com/s?wd=inurl%3Awww.xiaodi8.com&pn=10
		#https://www.baidu.com/s?wd=inurl%3Awww.huanghuai.edu.cn&rsv_spt=1&rsv_iqid=0xcd11eb0a0002bf05&issp=1&f=8&rsv_bp=1&rsv_idx
        response = requests.get(target, headers=head)
        # response.encoding = 'utf-8'
        result = response.content.decode('utf-8')     ## print(response.content)     #打印出的是二进制形式
        # print(result)
        tree = etree.HTML(result)
        value = tree.xpath('//div[@class="b_title"]/a/@href')
        print(value)
        for a in value:
            # print(a)
            if len(url.split('.', 4)) > 3:
                url_str2 = url.split('.', 4)[2]
                if (url_str in a or url_str2 in a):      #域名过长的话默认匹配两个关键词
                    sites.append(a)
                    file.write(a)
                    file.write('\n')
            else:
                if (url_str in a):
                    sites.append(a)
                    file.write(a)
                    file.write('\n')


    file.write('\n\n')
    file.write(
        '------------------------------------------------子域名探测结束---------------------------------------------------')
    print('查询到结果条数：'+str(len(sites)))
    site = list(set(sites))  # set()实现去重
    print('去重后的条数：'+str(len(site)))
    file.write('共' + str(len(site)) + '条')
    file.write('\n\n\n\n')
    file.close()
    print('--------子域名探测完成-------')
    # set () 函数为 Python 的内置函数，其功能是将字符串、列表、元组、range 对象等可迭代对象转换成集合,集合元素不可以重复，可达到去重的结果
    # print site

# 网站目录扫描
def scan_web_path(base_url):

    file=open('result/'+base_url+'.txt','a')
    # 调用字典进行爆破
    dir1 = open('dic/备份文件.txt','r',errors='ignore')
    # # 常见网站源码备份文件后缀
    # final2 = ['tar', 'tar.gz', 'zip', 'rar', 'bak']
    # 开始扫描
    url_head='http://'
    file.write('扫面到网站目录如下：' + '\n')
    time_start_2 = time.time()

    for i in dir1:
       url=url_head+base_url+i
       print(url)
       r=requests.get(url=url,headers=head)
       if r.status_code==200:
          print(url+'成功请求--------------------------------------')
          file.write(url)
    file.write('\n\n\n\n')
    file.close()
    # code
    time_end_2 = time.time()
    print("运行时间：" + str((time_end_2 - time_start_2) / 1000000) + "秒")
    print('--------网站目录扫描完成-------')

# cms 探测
def cms(url):
    print('cms探测由于接口访问量较多，为防止结果不准，默认查询两次')
    try:
        file = open('result/' + url + '.txt', 'a')
        url2 = 'http://' + url
        response = requests.get(url2, verify=False)
        whatweb_dict = {"url": response.url, "text": response.text, "headers": dict(response.headers)}
        whatweb_dict = json.dumps(whatweb_dict)
        whatweb_dict = whatweb_dict.encode()
        whatweb_dict = zlib.compress(whatweb_dict)
        data = {"info": whatweb_dict}
        request = requests.post("http://whatweb.bugscaner.com/api.go", files=data)
        # print(request.headers["X-RateLimit-Remaining"])
        print(u"识别结果")
        # print(request.headers["Server"])

        print(request.json())

        # print(str(request.json()))
        file.write('cms探测结果：' + str(request.json()) + '\n')

        # 上面的cms识别代码为copy的内容，原作者地址：https://www.cnblogs.com/lanyincao/p/12001586.html
        r = os.popen('ping ' + url).read()
        print(r)
        # re.findall(r'\d\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response, re.S)
        s = re.findall('TTL=[0-9]+', r, re.S)  # 正则表达式
        # print(s)
        # print(s[1])
        # print(s[1].split('='))
        # print(s[1].split('=')[1])
        # print(type(int(s[1].split('=')[1])))
        try:
            if int(s[1].split('=')[1]) > 100:
                print('判断操作系统为windows，' + 'ttl值为：' + s[1].split('=')[1])
                file.write(r)
                file.write('\n\n')
                file.write('--------------判断操作系统为windows，' + 'ttl值为：' + s[1].split('=')[1])
            elif int(s[1].split('=')[1]) < 100:
                print('判断操作系统为linux，' + 'ttl值为：' + s[1].split('=')[1])
                file.write(r)
                file.write('\n\n')
                file.write('--------------判断操作系统为linux，' + 'ttl值为：' + s[1].split('=')[1])
        except:
            print('可能访问被拒绝了，无法访问')
            file.write('可能访问被拒绝了，无法探测到目标操作系统')
        file.write('\n')
        file.write(
            '------------------------------------------------cms探测结束---------------------------------------------------')
        file.write('\n\n\n\n')
        print('--------cms探测完成完成-------')
    except:
        print('cms探测出现问题，可能有waf，导致无法访问')

if __name__ == "__main__":
    # s = 'blog.csdn.net'
    #t1 = Thread(target=check_port(s), args=("线程1",))
    #t2 = Thread(target=check_port(s), args=("线程2",))
    #t3 = Thread(target=check_port(s), args=("线程2",))
    #t4 = Thread(target=check_port(s), args=("线程2",))
    #t5 = Thread(target=check_port(s), args=("线程2",))
    #t6 = Thread(target=check_port(s), args=("线程2",))
    #t1.start()
    #t2.start()
    #t3.start()
    #t4.start()
    #t5.start()
    #t6.start()
    # www.huanghuai.edu.cn
    # check_port(s)    #检查开放的端口
    # scan_whois(s)    #查询whois信息
    # check_cdn(s)     #检查是否存在cdn
    #scan_domain_path(s)     #扫描子域名
    # # scan_web_path(s)    #扫描网站路径，备份文件（此功能由于字典太大，过程很慢）
    # cms(s)


    a='''

/**
 *                    .::::.
 *                  .::::::::.
 *                 :::::::::::
 *             ..:::::::::::'
 *           '::::::::::::'
 *             .::::::::::
 *        '::::::::::::::..
 *             ..::::::::::::.
 *           ``::::::::::::::::
 *            ::::``:::::::::'        .:::.
 *           ::::'   ':::::'       .::::::::.
 *         .::::'      ::::     .:::::::'::::.
 *        .:::'       :::::  .:::::::::' ':::::.
 *       .::'        :::::.:::::::::'      ':::::.
 *      .::'         ::::::::::::::'         ``::::.
 *  ...:::           ::::::::::::'              ``::.
 * ```` ':.          ':::::::::'                  ::::..
 *                    '.:::::'                    ':'````..                         飞塔scan_tool
 */

'''
    print(a)
    print('''
        注：网址请不要加上http，第一个参数一定要是 -u，最少两个参数
        示例用法：
		python scan.py -u www.baidu.com -all      探测所有功能
		python scan.py -u www.baidu.com -port -cms       探测cms和端口
        尽量不要使用 -path参数来查询网站路径，待完善
       ''')


    def four(url):
        try:
            if sys.argv[4] == '-port':
                check_port(url)
            if sys.argv[4] == '-whois':
                scan_whois(url)
            if sys.argv[4] == '-cdn':
                check_cdn(url)
            if sys.argv[4] == '-domain':
                scan_domain_path(url)
            if sys.argv[4] == 'path':  # 扫描网站路径，备份文件（此功能由于字典太大，过程很慢）,不建议使用
                scan_web_path(url)
            if sys.argv[4] == '-cms':
                cms(url)
                cms(url)
        except:
            print()

    def five(url):
        try:
            if sys.argv[5] == '-port':
                check_port(url)
            if sys.argv[5] == '-whois':
                scan_whois(url)
            if sys.argv[5] == '-cdn':
                check_cdn(url)
            if sys.argv[5] == '-domain':
                scan_domain_path(url)
            if sys.argv[5] == 'path':  # 扫描网站路径，备份文件（此功能由于字典太大，过程很慢）,不建议使用
                scan_web_path(url)
            if sys.argv[5] == '-cms':
                cms(url)
                cms(url)
        except:
            print()

    def six(url):
        try:
            if sys.argv[6] == '-port':
                check_port(url)
            if sys.argv[6] == '-whois':
                scan_whois(url)
            if sys.argv[6] == '-cdn':
                check_cdn(url)
            if sys.argv[6] == '-domain':
                scan_domain_path(url)
            if sys.argv[6] == 'path':  # 扫描网站路径，备份文件（此功能由于字典太大，过程很慢）,不建议使用
                scan_web_path(url)
            if sys.argv[6] == '-cms':
                cms(url)
                cms(url)
        except:
            print()

    def seven(url):
        try:
            if sys.argv[7] == '-port':
                check_port(url)
            if sys.argv[7] == '-whois':
                scan_whois(url)
            if sys.argv[7] == '-cdn':
                check_cdn(url)
            if sys.argv[7] == '-domain':
                scan_domain_path(url)
            if sys.argv[7] == 'path':  # 扫描网站路径，备份文件（此功能由于字典太大，过程很慢）,不建议使用
                scan_web_path(url)
            if sys.argv[7] == '-cms':
                cms(url)
                cms(url)
        except:
            print()



    try:
        if sys.argv[1] == '-u':

            url = sys.argv[2]


            if sys.argv[3] == '-port':
                check_port(url)
                four(url)
                five(url)
                six(url)
                seven(url)

            if sys.argv[3] == '-whois':
                scan_whois(url)
                four(url)
                five(url)
                six(url)
                seven(url)
            if sys.argv[3] == '-cdn':
                check_cdn(url)
                four(url)
                five(url)
                six(url)
                seven(url)
            if sys.argv[3] == '-domain':
                scan_domain_path(url)
                four(url)
                five(url)
                six(url)
                seven(url)
            if sys.argv[3] == 'path':  # 扫描网站路径，备份文件（此功能由于字典太大，过程很慢）,不建议使用
                scan_web_path(url)
                four(url)
                five(url)
                six(url)
                seven(url)
            if sys.argv[3] == '-cms':
                cms(url)
                cms(url)
                four(url)
                five(url)
                six(url)
                seven(url)
            if sys.argv[3] == '-all':
                check_port(url)    #检查开放的端口
                scan_whois(url)    #查询whois信息
                check_cdn(url)     #检查是否存在cdn
                scan_domain_path(url)     #扫描子域名
                #scan_web_path(url)    #扫描网站路径，备份文件（此功能由于字典太大，过程很慢）
                cms(url)
                cms(url)
            print('执行完成，结果已放在：' + 'result/' + url + '.txt' + ' 中')
    except:
         print('''   输入结果可能有误或者缺少参数，请重新输入
                     ！！！！！！！！！！   ''')

