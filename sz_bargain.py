#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import time
import traceback
import logging.handlers
import requests.packages.urllib3
import requests.cookies
import requests
import hashlib
import ddddocr
import xlrd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://yyhc.szggzy.com:9000'   # 登陆host
host2 = 'https://yyhc.szggzy.com:9000'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.session()
headers = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
    "Host": host1.split('/')[-1],
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"'
}
session.verify = False
requests.packages.urllib3.disable_warnings()
session.mount("https://", adapter)
session.mount("http://", adapter)

if hasattr(sys, 'frozen'):
    current_path = os.path.dirname(sys.executable)
else:
    current_path = os.path.dirname(os.path.abspath(__file__))
logger = logging.getLogger()
formatter = logging.Formatter('%(asctime)s[%(lineno)d] - %(levelname)s - %(message)s')
logger.setLevel(level=logging.INFO)
file_handler = logging.handlers.TimedRotatingFileHandler(os.path.join(current_path, 'run.txt'), when='midnight', interval=1, backupCount=3)
file_handler.suffix = '%Y-%m-%d.txt'
console_handler = logging.StreamHandler()
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
cookie_path = os.path.join(current_path, 'cookie.txt')
auth_file_path = os.path.join(current_path, '授权文件')
auth_file_url = {}
company_dict = {}


def get_code():
    try:
        response = session.get(f'{host1}/sso/captchaImg', headers=headers)
        if response.status_code == 200:
            img_bytes = response.content
            ocr = ddddocr.DdddOcr(show_ad=False)
            return ocr.classification(img_bytes)
        else:
            raise Exception('获取验证码失败')
    except:
        logger.error(traceback.format_exc())


def login(username, password):
    try:
        url = f'{host1}/sso/login.html'
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            answer = get_code()
            headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            headers.update({'X-Requested-With': 'XMLHttpRequest'})
            url = f'{host1}/sso/loginAuth.html'
            data = {'userId': None, 'username': username, 'password': calc_md5(password), 'answer': answer}
            response = session.post(url, data=data, headers=headers)
            if response.status_code == 200:
                phone_nums = re.findall('class="inp phone-inp">(.*?)</p>', response.text)
                if len(phone_nums) == 1 and phone_nums[0]:
                    users = re.findall('id="userId".*value="(.*?)">', response.text)
                    if len(users) == 1 and users[0]:
                        url = f'{host1}/sso/sendSMS.html?userId={users[0]}'
                        response = session.post(url, headers=headers)
                        if response.status_code == 200:
                            res_json = json.loads(response.text)
                            if res_json['status'] == '1':
                                logger.info(res_json['message'])
                                g = input("请输入手机验证码，然后按 Enter 键：")
                                url = f'{host1}/sso/checkSMS.html?userId={users[0]}'
                                data = {'userId': users[0], 'checkSMSCode': g}
                                response = session.post(url, data=data, headers=headers)
                                if response.status_code == 200:
                                    res_json = json.loads(response.text)
                                    if res_json['status'] == '1':
                                        url = f'{host1}/sso/loginAuth.html'
                                        data = {'userId': users[0], 'username': username, 'password': calc_md5(password), 'answer': None}
                                        response = session.post(url, data=data, headers=headers)
                                        if response.status_code == 200:
                                            with open(cookie_path, 'w', encoding='utf-8') as f:
                                                c = session.cookies.get_dict()
                                                f.write(json.dumps(c))
                                            logger.info(f"登陆成功")
                                            return True
                                        else:
                                            logger.error(f'/sso/loginAuth.html 页面 状态码：{response.status_code}')
                                            return None
                                    else:
                                        logger.error(res_json['message'])
                                        return None
                                else:
                                    logger.error(f"check 手机验证码失败。")
                                    return None
                            else:
                                logger.error(res_json['message'])
                                return None
                        else:
                            logger.error(f"发送手机验证码失败。")
                            return None
                    else:
                        logger.error(f"登录失败。")
                        return None
                else:
                    logger.error(f"验证码识别失败。")
                    return None
            else:
                logger.error(f"登录失败。")
                return None
        else:
            logger.error(f"登陆失败。")
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def query_bargain(ms_code, hospital):
    headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
    headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
    headers.update({'Sec-Fetch-Site': 'same-origin'})
    headers.update({'Sec-Fetch-Dest': 'empty'})
    headers.update({'Sec-Fetch-Mode': 'cors'})
    try:
        url = f'{host2}/hctrade/suppurBargain/getResponeHospProcurecatalogListData.html'
        data = {'_search': False, 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'productName': None, 'brand': None, 'companyDays': None,
                'regCode': None, 'goodsName': None, 'sourceId': None, 'goodsIds': None, 'procurecatalogId': ms_code, 'hospitalName': hospital,
                'bargainID': None, 'hasPs': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) == 1:
                return {"bargainId": res_json['rows'][0]['bargainId'], "hospitalId": res_json['rows'][0]['hospitalId'], "hospitalName": res_json['rows'][0]['hospitalName']}
            else:
                logger.error(f"查询议价列表为空，产品代码：{ms_code}，医院名称：{hospital}，响应值：{res_json['rows']}")
                raise
        else:
            logger.error(f"查询议价列表失败，产品代码：{ms_code}，医院名称：{hospital}，状态码：{response.status_code}")
            raise
    except:
        raise


def agree_bargain(agree_val, agree_price, res: dict, c_bargain, r_bargain):
    try:
        url = f'{host2}/hctrade/suppurBargain/confirmCompanyBargain.html'
        if agree_val == '同意议价':
            res.update({'remark': ''})
            data = {"bargainList": json.dumps([res], ensure_ascii=False), "bargainStatus": 2}
        elif agree_val == '拒绝议价':
            res.update({'remark': r_bargain})
            data = {"bargainList": json.dumps([res], ensure_ascii=False), "bargainStatus": 3}
        elif agree_val == '继续议价':
            try:
                _ = float(agree_price)
            except:
                raise Exception(f"{agree_val} 填写不正确：当前值 {agree_price}")
            res.update({'remark': c_bargain})
            res.update({'price': agree_price})
            data = {"bargainList": json.dumps([res], ensure_ascii=False), "bargainStatus": 1}
        else:
            raise Exception(f"议价判断填写不正确：当前值 {agree_val}")
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success'] or res_json['code'] != 0:
                logger.error(f"议价失败，议价号：{res['bargainId']}，响应值：{response.text}")
                raise Exception(res_json['msg'])
        else:
            logger.error(f"议价失败，议价号：{res['bargainId']}，状态码：{response.status_code}")
            raise
    except:
        raise


def calc_md5(data: str) -> str:
    hash_obj = hashlib.md5()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def check_login():
    try:
        if os.path.exists(cookie_path):
            cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
            coo = requests.cookies.RequestsCookieJar()
            for k, v in cookies_dict.items():
                coo.set(k, v)
            session.cookies.update(coo)
            headers.update({'Host': host2.split('/')[-1]})
            url = f'{host2}/hctrade/index.html'
            response = session.get(url, headers=headers)
            if response.status_code == 200:
                user_infos = re.findall('<p>(.*?)</p>', response.text)
                if len(user_infos) == 1:
                    logger.info(f"免登陆成功，用户：{user_infos[0]}")
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    except:
        logger.error(traceback.format_exc())
        return False


try:
    username = ''
    password = ''
    continue_bargain = '继续议价'
    reject_bargain = '请核对价格是否正确'
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()
            if 'continue_bargain' in lin:
                continue_bargain = lin.split('=')[-1].strip()
            if 'reject_bargain' in lin:
                reject_bargain = lin.split('=')[-1].strip()

    if not check_login():
        coo = requests.cookies.RequestsCookieJar()
        session.cookies = coo
        access_token = None
        for _ in range(3):
            headers.update({"Host": host1.split('/')[-1]})
            access_token = login(username, password)
            if access_token:
                coo = requests.cookies.RequestsCookieJar()
                session.cookies = coo
                headers = {'Host': host1.split('/')[-1], 'Sec-Fetch-User': '?1', 'Sec-Fetch-Site': 'none',
                           'Sec-Fetch-Mode': 'navigate', 'Upgrade-Insecure-Requests': '1', 'Sec-Fetch-Dest': 'document', 'Sec-Ch-Ua-Mobile': '?0',
                           'Cache-Control': 'max-age=0', 'sec-ch-ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
                           'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
                           'Accept-Language': 'zh-CN,zh;q=0.9', 'sec-ch-ua-platform': '"Windows"', 'Accept-Encoding': 'gzip, deflate, br',
                           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'}
                cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
                coo = requests.cookies.RequestsCookieJar()
                for k, v in cookies_dict.items():
                    coo.set(k, v)
                session.cookies.update(coo)
                headers.update({'Host': host2.split('/')[-1]})
                url = f'{host2}/hctrade/index.html'
                response = session.get(url, headers=headers)
                user_infos = re.findall('<p>(.*?)</p>', response.text)
                if len(user_infos) == 1:
                    break
            time.sleep(2)
        if not access_token:
            raise Exception("连续3次登陆失败，请重试")

    total_num = 0
    success = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xlsx')] + [n for n in os.listdir(current_path) if n.endswith('.xls')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '议价判断' in table.cell_value(i, 3):
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):
            if not table.cell_value(i, 3): continue
            total_num += 1
            try:
                ms_code = table.cell_value(i, 1).strip()
            except:
                ms_code = str(int(table.cell_value(i, 1)))
            hospital = table.cell_value(i, 2).strip()
            is_agree = table.cell_value(i, 3).strip()
            agree_value = table.cell_value(i, 4)
            if ms_code and is_agree:
                try:
                    time.sleep(1)
                    res = query_bargain(ms_code, hospital)
                    res = agree_bargain(is_agree, agree_value, res, continue_bargain, reject_bargain)
                    success += 1
                    logger.info(f"议价成功，产品代码：{ms_code}，医院名称：{hospital}，议价判断：{is_agree}，企业建议价格：{agree_value}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"议价失败，产品代码：{ms_code}，医院名称：{hospital}，议价判断：{is_agree}，企业建议价格：{agree_value}")
            else:
                logger.error(f"Excel表格中的数据不全，产品代码：{ms_code}，医院名称：{hospital}，议价判断：{is_agree}，企业建议价格：{agree_value}")
    logger.info(f"总数：{total_num}，议价成功：{success}，议价失败：{total_num - success}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
