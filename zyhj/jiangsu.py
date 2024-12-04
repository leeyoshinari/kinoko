#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari
import os
import sys
import json
import time
import traceback
import urllib.parse
import logging.handlers
import requests.packages.urllib3
import requests.cookies
import requests
import hashlib
import xlrd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://ybj.jszwfw.gov.cn'   # 登陆host
host2 = 'http://223.111.68.66:8081'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 403, 500, 501, 502, 503, 504])
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
cookie_path = os.path.join(current_path, "cookie.txt")
region_dict = json.load(open(os.path.join(current_path, "jiangsu.txt"), 'r', encoding='utf-8'))     # 城市和编码数据


def login(username, password):
    try:
        url = f'{host1}/hsa-pss-cw/pss/web/empUser/login'
        data = {"username": username, "loginType": "7", "password": hash256(password)}
        headers.update({'Content-Type': 'application/json'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
            coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
            coo.set('service-mall-authCode', res_json['data']['authCode'])
            session.cookies.update(coo)
            headers.update({'Accesstoken': res_json['data']['accessToken']})
            headers.update({'Authorization': res_json['data']['accessToken']})
            headers.update({'Refreshtoken': res_json['data']['refreshToken']})
            headers.update({'Accounttype': '2'})
            with open(cookie_path, 'w', encoding='utf-8') as fp:
                fp.write(json.dumps({"accessToken": res_json['data']['accessToken'], "refreshToken": res_json['data']['refreshToken'], "authCode": res_json['data']['authCode']}))
            url = f'{host1}/hsa-pss-cw/pss/web/empUser/getTokenInfo'
            response = session.post(url, headers=headers)
            headers.update({'Host': host2.split('/')[-1]})
            headers.update({'Referer': host2})
            if response.status_code == 200:
                res_json = json.loads(response.text)
                logger.info(f"登陆成功：{res_json['data']['account']}")
                return response.status_code
            else:
                logger.info(f"登陆失败：状态码：{response.status_code}")
                return None
        else:
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def check_login():
    try:
        url = f'{host1}/hsa-pss-cw/pss/web/empUser/getTokenInfo'
        response = session.post(url, headers=headers)
        headers.update({'Host': host2.split('/')[-1]})
        headers.update({'Referer': host2})
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0:
                logger.info(f"免登陆成功：{res_json['data']['account']}")
                return response.status_code
            else:
                return None
        else:
            return None
    except:
        return None


def query_company(res: dict):
    try:
        url = f"{host2}/tps-local-bd/web/mcstrans/orgInfo/mcs/page"
        data = {"current": 1, "size": 10, "prodCode": res['prodCode'], "admdvs": res['admdvs'], "itemCodg": res['itemcode'], "orgName": res['orgName'], "pubonlnRsltId": res['pubonlnId']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] > 0:
                for c in res_json['data']['records']:
                    if res['orgName'] == c['orgName']:
                        return c
                logger.error(f"配送企业查询结果为空，配送企业：{res['orgName']}，响应值：{res_json}")
                raise
            else:
                logger.error(f"配送企业查询结果为空，配送企业：{res['orgName']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"配送企业查询失败，配送企业：{res['orgName']}，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def query_send_company(res: dict):
    try:
        url = f"{host2}/tps-local-bd/web/mcstrans/delventp/pageMcs"
        data = {"current": 1, "size": 10, "RegnCode": res['admdvs'], "delventpName": res['orgName'], "pubonlnRsltId": res['pubonlnId']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] == 0:
                return False
            else:
                for c in res_json['data']['records']:
                    if res['orgName'] == c['delventpName']:
                        return True
                return False
        else:
            logger.error(f"查询已配送的企业失败，配送企业：{res['orgName']}，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def query_delv(res: dict):
    try:
        headers.update({'Content-Type': 'application/json'})
        data = {"current": 1, "size": 10, "provinceId": res['provinceId'], "orders": []}
        url = f"{host2}/tps-local-bd/web/mcstrans/pub_online/mcs/query_delv"
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            try:
                res_json = json.loads(response.text)
                if res_json['data']:
                    if res_json['data']['total'] >= 1:
                        for r in res_json['data']['records']:
                            if r['provinceId'] == res['provinceId']:
                                res.update({'prodCode': r['prodCode']})
                                res.update({'itemcode': r['itemcode']})
                                res.update({'pubonlnId': r['pubonlnId']})
                                return res
                        logger.error(f"省平台编码查询结果为空，省平台编码：{res['provinceId']}，响应值：{response.text}")
                        raise
                    else:
                        logger.error(f"省平台编码查询结果为空，省平台编码：{res['provinceId']}，响应值：{response.text}")
                        raise
                else:
                    logger.error(f"省平台编码查询结果为空，省平台编码：{res['provinceId']}，响应值：{response.text}")
                    raise
            except:
                logger.error(f"省平台编码查询结果错误，省平台编码：{res['provinceId']}，响应值：{response.text}")
                logger.error(traceback.format_exc())
                raise
        else:
            logger.error(f"省平台编码查询失败，省平台编码：{res['provinceId']}，状态码：{response.status_code}")
            raise
    except:
        logger.error(f"省平台编码查询结果为空，省平台编码：{res['provinceId']}，res：{res}")
        raise


def query_area(res: dict):
    region = [r['admdvs'] for r in region_dict if r['admdvsName'] == res['admdvsName']]
    if len(region) == 0:
        logger.error(f"未找到配送区域，配送区域：{res['admdvsName']}")
        raise
    elif len(region) > 1:
        region_name = [r['admdvsName'] for r in region_dict if r['admdvsName'] == res['admdvsName']]
        logger.error(f"查找到多个配送区域，配送区域：{res['admdvsName']}, 查询结果：{','.join(region_name)}")
        raise
    else:
        res['admdvs'] = region[0]
        return res


def submit_c(res: dict, data: dict):
    try:
        data.update({"itemCodg": res['itemcode']})
        data.update({"prodCode": res['prodCode']})
        data.update({"pubonlnRsltId": res['pubonlnId']})
        data.update({"admdvs": res['admdvs']})
        url = f'{host2}/tps-local-bd/web/mcstrans/delventp/mcs/save'
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            logger.error(f"配送失败，配送企业：{res['delventpName']}，配送地区：{res['admdvsName']}，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise


def hash256(data: str):
    hash_obj = hashlib.sha256()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


try:
    # 读取用户名和密码
    username = ''
    password = ''
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()

    if time.time() > 1733833220:
        raise Exception("过期，请重试 ~")
    is_login = 0
    if os.path.exists(cookie_path):
        cookies = json.load(open(cookie_path, 'r', encoding='utf-8'))
        headers.update({'Content-Type': 'application/json'})
        headers.update({'Accesstoken': cookies['accessToken']})
        headers.update({'Authorization': cookies['accessToken']})
        headers.update({'Refreshtoken': cookies['refreshToken']})
        headers.update({'Accounttype': '2'})
        if check_login():
            is_login = 1

    if is_login == 0:
        # 登陆系统，获取token
        coo.set('headerShow', 'false')
        coo.set('SESSION_FLAG', '1')
        coo.set('headerStatus', '-1')
        session.cookies.update(coo)
        access_token = None
        for _ in range(2):
            headers.update({"Host": host1.split('/')[-1], "Referer": host1})
            access_token = login(username, password)
            if access_token:
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续2次登陆失败，请重试")

    total_num = 0
    success = 0
    has_send = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))  # 打开excel表格
        sheets = excel.sheet_names()  # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])  # 获取sheet中的单元格
        ind = 1
        for i in range(table.nrows):
            if '省平台产品编码' in table.cell_value(i, 1).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):  # 遍历所有非空单元格
            if not table.cell_value(i, 1): continue
            total_num += 1
            provinceId = table.cell_value(i, 1).strip()
            orgName = table.cell_value(i, 11).strip()
            admdvsName = table.cell_value(i, 12).strip()
            if provinceId and orgName and admdvsName:
                try:
                    time.sleep(1)
                    res = {'provinceId': provinceId, 'orgName': orgName, 'admdvsName': admdvsName}
                    res = query_area(res)
                    res = query_delv(res)
                    is_send = query_send_company(res)
                    if is_send:
                        has_send += 1
                        logger.warning(f"已经配送过了，省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}")
                        continue
                    res_1 = query_company(res)
                    res_dict = submit_c(res, res_1)
                    if res_dict['code'] == 0:
                        success += 1
                        logger.info(f"配送成功：省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}")
                    elif res_dict['code'] == 160003:
                        has_send += 1
                        logger.warning(f"已经配送过了，省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}，message: {res_dict['message']}")
                    else:
                        logger.error(f"配送失败：省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}，响应值：{res_dict}")
                except:
                    logger.error(f"配送失败：省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：省平台编码：{provinceId}，配送企业：{orgName}，配送地区：{admdvsName}")
    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num - success - has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
