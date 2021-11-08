import re
import yaml
import json
import requests
import argparse
from base64 import b64encode
from ddddocr import DdddOcr
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pksc1_v1_5
from Crypto.PublicKey import RSA

class Course():
    def __init__(self) -> None:
        self.id = 0
        self.title = None
        self.url = None
        self.end_img_url = None
        self.study_url = None

    def update(self, headers):
        try:
            r = requests.get("https://m.bjyouth.net/dxx/index", headers=headers, timeout=5)
            #print(r.status_code)
            index = json.loads(r.text)
            self.id = index['newCourse']['id']
            self.title = index['newCourse']['title']
            self.url = index['newCourse']['url']
            i = self.url.find("/m.html")
            self.end_img_url = self.url[:i] + '/images/end.jpg'
            self.study_url = f"https://m.bjyouth.net/dxx/check?id={self.id}&org_id=%s"
            print(f'[INFO] updated course: {self.title}')
            return 1
        except:
            print('[ERROR] update course failed!')
            return 0


class Youth():
    def __init__(self):
        self.cookies = ''
        self.username = ''
        self.password = ''
        self.org_id = ''
        self.get_cookies_turn = 5
        self.course = Course()
        self.course_need_update = True
        self.ua = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x6303004c)"
        self.headers = {
            "Host": "m.bjyouth.net",
            "User-Agent": self.ua,
            "Cookie": '',
            "Referer": "https://m.bjyouth.net/qndxx/index.html"
        }
        
    def get_cookie(self):
        for i in range(self.get_cookies_turn):
            print(f'[INFO] try to get cookie ... {i}/{self.get_cookies_turn}')
            cookies = self.get_cookie_with_requests()
            if cookies:
                self.cookies = 'PHPSESSID=' + cookies
                self.headers["Cookie"] = self.cookies
                print('[INFO] get cookie successfully.')
                return 1
        print('[ERROR] get cookie error! please check your password.')
        return 0

    def encrypt(self, password, public_key=''):
        if public_key == '':
            public_key = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD5uIDebA2qU746e/NVPiQSBA0Q3J8/G23zfrwMz4qoip1vuKaVZykuMtsAkCJFZhEcmuaOVl8nAor7cz/KZe8ZCNInbXp2kUQNjJiOPwEhkGiVvxvU5V5vCK4mzGZhhawF5cI/pw2GJDSKbXK05YHXVtOAmg17zB1iJf+ie28TbwIDAQAB\n-----END PUBLIC KEY-----"
        rsakey = RSA.importKey(public_key)
        cipher = Cipher_pksc1_v1_5.new(rsakey)
        cipher_text = b64encode(cipher.encrypt(password.encode()))
        return cipher_text.decode()

    def get_cookie_with_requests(self):
        try:
            S = requests.Session()
            headers = {"Host": "m.bjyouth.net", "User-Agent": self.ua}
            r = S.get(url="https://m.bjyouth.net/site/login", headers=headers, timeout=5)
            #print(r.status_code)
            cap_url = "https://m.bjyouth.net" + re.findall(r'src="/site/captcha.+" alt=', r.text)[0][5:-6]
            headers["Referer"] = "https://m.bjyouth.net/site/login"
            cap = S.get(url=cap_url, headers=headers, timeout=5)
            #print(cap.status_code)
            ocr = DdddOcr()
            cap_text = ocr.classification(cap.content)
            print(f'[INFO] Captcha OCR: {cap_text}')
            _csrf_mobile = S.cookies.get_dict()['_csrf_mobile']
            headers['Origin'] = "https://m.bjyouth.net"
            login_username = self.encrypt(self.username)
            login_password = self.encrypt(self.password)
            login_r = S.post('https://m.bjyouth.net/site/login',
                             headers=headers,
                             data={
                                 '_csrf_mobile': _csrf_mobile,
                                 'Login[username]': login_username,
                                 'Login[password]': login_password,
                                 'Login[verifyCode]': cap_text
                             },
                             timeout=5)
            return login_r.cookies.get_dict()['PHPSESSID']
        except:
            return 0
        
    def study(self):    
        # update if needed
        if self.course_need_update:
            if not self.course.update(self.headers):
                return 0
            self.course_need_update = False
        # study
        r = requests.get(url=self.course.study_url % self.org_id, headers=self.headers, timeout=5)
        if r.text:
            print('[Error] study error: {r.text}')
            return 0
        print('[INFO] study complete.')
        return 1
    

def main(args):
    print('[INFO] Start')
    youth = Youth()
    youth.username = args.username
    youth.password = args.password
    youth.org_id = args.org_id

    if not youth.get_cookie():
        return 0
    if not youth.study():
        return 0

    return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--username', type=str)
    parser.add_argument('--password', type=str)
    parser.add_argument('--org_id', type=str)
    args = parser.parse_args()
    main(args)
