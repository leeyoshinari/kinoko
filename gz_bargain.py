#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import traceback
import logging.handlers
import requests.packages.urllib3
import requests.cookies
import requests
import xlrd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://gpo.gzggzy.cn'   # 登陆host
host2 = 'https://gpo.gzggzy.cn'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.session()
coo = requests.cookies.RequestsCookieJar()
headers = {'Host': host1.split('/')[-1],
'Referer': host1,
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"',
'sec-ch-ua-platform': ''"Windows"''}
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


def login(caCert):
    try:
        url = f'{host1}'
        response = session.get(url, headers=headers)
        if response.status_code == 200 and 'CA登录' in response.text:
            headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            headers.update({'X-Requested-With': 'XMLHttpRequest'})
            url = f'{host1}/CetRandomByServer.servlet'
            response = session.post(url, data={'number': '5'}, headers=headers)
            if response.status_code == 200:
                url = f'{host1}/webPortal/systemHCCaLogin.html'
                login_params = {'caCert': caCert, 'caType': 'NETCA', 'isOrgKey': '1', 'confirmLogin': '0'}
                response = session.post(url, data=login_params, headers=headers)
                if response.status_code == 200:
                    res_json = json.loads(response.text)
                    if res_json['code'] == 1:
                        hcLoginToken = res_json['hcLoginToken']
                        response = session.get(res_json['msg'], headers=headers)
                        with open(cookie_path, 'w', encoding='utf-8') as f:
                            c = session.cookies.get_dict()
                            f.write(json.dumps(c))
                        logger.info("登陆成功 ~")
                        return response.status_code
                    else:
                        logger.error(f"登陆失败，响应值：{response.text}")
                else:
                    logger.error(f"登陆失败，状态码：{response.status_code}")
                    return None
            else:
                logger.error(f"登陆失败，状态码：{response.status_code}")
                return None
        else:
            logger.error(f"登陆失败，状态码：{response.status_code}")
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def query_bargain(bargain_id):
    try:
        url = f'{host2}/hcTrade/suppurBargain/getQYSuppurBargainData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'regCode': None, 'goodsName': None, 'procurecatalogId': None, 'goodsIds': None, 'bargainId': bargain_id, 'hospitalName': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) == 1:
                company_bargain = res_json['rows'][0]['companyBargain']
                company_bargain = company_bargain if company_bargain else 0
                return {"bargainApply": res_json['rows'][0]['bargainApply'], "companyBargain": company_bargain,
                        "bargainCount": res_json['rows'][0]['bargainCount'], "bargainId": bargain_id}
            else:
                logger.error(f"查询议价列表为空，议价号：{bargain_id}，响应值：{res_json['rows']}")
                raise
        else:
            logger.error(f"查询议价列表失败，议价号：{bargain_id}，状态码：{response.status_code}")
            raise
    except:
        raise


def agree_bargain(agree_val, res: dict):
    try:
        url = f'{host2}/hcTrade/suppurBargain/compSubSuppurBargain.html'
        if agree_val == '同意':
            data = {"bargainApply": res['bargainApply'], "companyBargain": 0,
                    "bargainStatus": 1, "bargainId": res['bargainId']}
        else:
            try:
                _ = float(agree_val)
                if res['bargainCount'] == 3:
                    raise Exception(f"当前为第 {res['bargainCount'] + 1} 轮议价,议价价格为 {agree_val} 元")
            except:
                raise Exception(f"回复议价填写不正确：当前值 {agree_val}")
            data = {"companyBargain": agree_val, "bargainStatus": 2, "bargainId": res['bargainId']}
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


def check_login():
    try:
        if os.path.exists(cookie_path):
            cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
            coo = requests.cookies.RequestsCookieJar()
            for k, v in cookies_dict.items():
                coo.set(k, v)
            session.cookies.update(coo)
            headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            headers.update({'X-Requested-With': 'XMLHttpRequest'})
            headers.update({'Host': host2.split('/')[-1]})
            headers.update({'Referer': host2})
            url = f'{host2}/hcTrade/chatUser/getChatInitInfo.html'
            response = session.get(url, headers=headers)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                if res_json['code'] == 0 and res_json['data']['mine']:
                    logger.info(f"免登陆成功，用户：{res_json['data']['mine']['username']}")
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
    caCert = ''
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'caCert' in lin:
                caCert = lin.split('caCert')[-1].strip()[1:].strip()

    coo.set('headerShow', 'false')
    coo.set('SESSION_FLAG', '1')
    session.cookies.update(coo)
    if not check_login():
        access_token = None
        for _ in range(2):
            headers.update({"Host": host1.split('/')[-1], "Referer": host1})
            access_token = login(caCert)
            if access_token:
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续2次登陆失败，请重试")

    total_num = 0
    success = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xlsx')] + [n for n in os.listdir(current_path) if n.endswith('.xls')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '回复议价' == table.cell_value(i, 2):
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):
            if not table.cell_value(i, 2): continue
            total_num += 1
            try:
                ms_code = table.cell_value(i, 1).strip()
            except:
                ms_code = str(int(table.cell_value(i, 1)))
            is_agree = str(table.cell_value(i, 2)).strip()
            if ms_code and is_agree:
                try:
                    time.sleep(1)
                    res = query_bargain(ms_code)
                    res = agree_bargain(is_agree, res)
                    success += 1
                    logger.info(f"议价成功，议价号：{ms_code}，回复议价：{is_agree}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"议价失败，议价号：{ms_code}，回复议价：{is_agree}")
            else:
                logger.error(f"Excel表格中的数据不全，议价号：{ms_code}，回复议价：{is_agree}")
    logger.info(f"总数：{total_num}，议价成功：{success}，议价失败：{total_num - success}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
