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
import hashlib
import xlrd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://igi.hsa.gd.gov.cn'   # 登陆host
host2 = 'https://igi.hsa.gd.gov.cn'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.session()
coo = requests.cookies.RequestsCookieJar()
headers = {'Host': host1.split('/')[-1], 'Referer': host1,
           'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
           'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"', 'sec-ch-ua-platform': ''"Windows"''}
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


def login(username, password, company):
    try:
        data = {'loginType': '', 'username': username, 'password': hash256(password)}
        url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/empUser/login'
        headers.update({'Content-Type': 'application/json'})
        response = session.post(url, json=data, headers=headers)
        login_params = {}
        if response.status_code == 200:
            res_json = json.loads(response.text)
            coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
            coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
            session.cookies.update(coo)
            if res_json['data']['loginType'] == 'loginUnit':
                headers.update({'Accesstoken': res_json['data']['accessToken']})
                url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/empUser/getTokenInfo'
                response = session.post(url, headers=headers)
                headers.update({'Authorization': res_json['data']['accessToken']})
                headers.update({'Refreshtoken': res_json['data']['refreshToken']})
                headers.update({'Content-Type': 'application/json'})
                headers.update({'Accounttype': '2'})
                headers.update({'Isprovincial': 'undefined'})
                if response.status_code == 200:
                    user_info = json.loads(response.text)
                    if user_info['data']['account'] == username:
                        with open(cookie_path, 'w', encoding='utf-8') as f:
                            c = session.cookies.get_dict()
                            f.write(json.dumps(c))
                        logger.info(f"登陆成功：{user_info['data']['unitInfoDTO']['empName']} - {user_info['data']['account']}")
                        headers.update({'Host': host2.split('/')[-1]})
                        headers.update({'Referer': host2})
                        return response.status_code
                    else:
                        logger.error(f"登陆失败，用户名不一致：返回值中的用户名：{user_info['data']['account']}，配置文件中的用户名：{username}")
                        return None
            else:
                login_params.update({'accessToken': res_json['data']['accessToken'], 'refreshToken': res_json['data']['refreshToken']})
                headers.update({'Accesstoken': res_json['data']['accessToken']})
                url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/empUser/get_unit_info_list'
                response = session.post(url, headers=headers)
                if response.status_code == 200:
                    res_json = json.loads(response.text)
                    emp_list = [c for c in res_json['data'] if company == c['empName']]
                    if len(emp_list) == 0:
                        logger.error(f"登录失败，在可选择的登录单位中未找到 {company}，可选登录单位：{res_json['data']}")
                        raise
                    login_params.update({'empId': emp_list[0]['empId'], 'empNthlUact': emp_list[0]['empNthlUact']})
                    time.sleep(1)
                    url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/agentSelectUnitLogin'
                    response = session.post(url, json=login_params, headers=headers)
                    if response.status_code == 200:
                        res_json = json.loads(response.text)
                        coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
                        coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
                        session.cookies.update(coo)
                        headers.update({'Accesstoken': res_json['data']['accessToken']})
                        url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/empUser/getTokenInfo'
                        response = session.post(url, headers=headers)
                        headers.update({'Authorization': res_json['data']['accessToken']})
                        headers.update({'Refreshtoken': res_json['data']['refreshToken']})
                        headers.update({'Content-Type': 'application/json'})
                        headers.update({'Accounttype': '2'})
                        # headers.update({'X-Xsrf-Token': 'null'})
                        headers.update({'Isprovincial': 'undefined'})
                        if response.status_code == 200:
                            user_info = json.loads(response.text)
                            if user_info['data']['account'] == username:
                                with open(cookie_path, 'w', encoding='utf-8') as f:
                                    c = session.cookies.get_dict()
                                    f.write(json.dumps(c))
                                logger.info(f"登陆成功：{user_info['data']['unitInfoDTO']['empName']} - {user_info['data']['agentInfoDTO']['empOpterName']}")
                                headers.update({'Host': host2.split('/')[-1]})
                                headers.update({'Referer': host2})
                                return response.status_code
                            else:
                                logger.error(f"登陆失败，用户名不一致：返回值中的用户名：{user_info['data']['account']}，配置文件中的用户名：{username}")
                                return None
                        else:
                            logger.error(f"登陆失败，状态码：{response.status_code}")
                            return None
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


def query_code(ms_code, res: dict):
    try:
        url = f"{host2}/gpo/tps-local-bd/web/mcsTrade/suppurBargain/getQYSuppurBargainData"
        data = {"current": 1, "size": 10, "searchCount": True, "searchTime": [], "bargainId": str(ms_code)}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data'] and len(res_json['data']['records']) == 1:
                res.update({'bargainId': ms_code})
                res.update({'bargainApply': res_json['data']['records'][0]['bargainApply']})
                return res
            else:
                logger.error(f"议价列表查询结果为空或有多个，议价号：{ms_code}，查询结果：{res_json['data']}")
                raise
        else:
            logger.error(f"议价列表查询失败，议价号：{ms_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def agree_bargain(res: dict):
    try:
        url = f'{host2}/gpo/tps-local-bd/web/mcsTrade/suppurBargain/compSubSuppurBargain'
        response = session.post(url, json=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success'] or res_json['code'] != 0:
                logger.error(f"议价失败，响应值：{response.text}")
                raise Exception(res_json['msg'])
        else:
            logger.error(f"议价失败，状态码：{response.status_code}")
            raise
    except:
        raise


def hash256(data: str):
    hash_obj = hashlib.sha256()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def calc_md5(data: str) -> str:
    hash_obj = hashlib.md5()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def check_login(username, company_name):
    try:
        if os.path.exists(cookie_path):
            cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
            coo = requests.cookies.RequestsCookieJar()
            for k, v in cookies_dict.items():
                coo.set(k, v)
            session.cookies.update(coo)
            headers.update({'Accesstoken': cookies_dict['service-mall-accesstoken']})
            headers.update({'Authorization': cookies_dict['service-mall-accesstoken']})
            headers.update({'Content-Type': 'application/json'})
            headers.update({'Refreshtoken': cookies_dict['service-mall-refreshtoken']})
            headers.update({'Accounttype': '2'})
            headers.update({'Isprovincial': 'undefined'})
            url = f'{host1}/ggfw/custom_emp_chl/api/v1/ggfw_pss_cw_local/empUser/getTokenInfo'
            response = session.post(url, headers=headers)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                if res_json['data']['accountType'] == 'UNIT' and res_json['data']['account'] == username:
                    logger.info(f"免登陆成功：{res_json['data']['unitInfoDTO']['empName']} - {res_json['data']['account']}")
                    headers.update({'Host': host2.split('/')[-1]})
                    headers.update({'Referer': host2})
                    return True
                elif res_json['data']['accountType'] == 'AGENT' and res_json['data']['account'] == username and res_json['data']['unitInfoDTO']['empName'] == company_name:
                    logger.info(f"免登陆成功：{res_json['data']['unitInfoDTO']['empName']} - {res_json['data']['agentInfoDTO']['empOpterName']}")
                    headers.update({'Host': host2.split('/')[-1]})
                    headers.update({'Referer': host2})
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    except:
        return False


try:
    username = ''
    password = ''
    origin_org_name = ''
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()
            if 'company' in lin:
                origin_org_name = lin.split('=')[-1].strip()

    coo.set('headerShow', 'false')
    coo.set('SESSION_FLAG', '1')
    session.cookies.update(coo)
    if not check_login(username, origin_org_name):
        access_token = None
        for _ in range(2):
            headers.update({"Host": host1.split('/')[-1], "Referer": host1})
            access_token = login(username, password, origin_org_name)
            if access_token:
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续2次登陆失败，请重试")

    total_num = 0
    success = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '议价号' == table.cell_value(i, 1):
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):
            if not table.cell_value(i, 1): continue
            total_num += 1
            try:
                ms_code = table.cell_value(i, 1).strip()
            except:
                ms_code = str(int(table.cell_value(i, 1)))
            try:
                is_agree = table.cell_value(i, 2).strip()
            except:
                is_agree = str(table.cell_value(i, 2)).strip()
            if ms_code and is_agree:
                try:
                    time.sleep(2)
                    res = {}
                    if is_agree == '同意':
                        res = query_code(ms_code, res)
                        res.update({"bargainStatus": 1})
                        res.update({"companyBargain": 0})
                    else:
                        try:
                            new_price = float(is_agree)
                            res = {"bargainId": str(ms_code), "bargainStatus": 2, "companyBargain": f"{float(is_agree):g}"}
                        except ValueError:
                            logger.error(f"该操作暂不支持，议价号：{ms_code}，议价执行：{is_agree}")
                            continue
                    agree_bargain(res)
                    success += 1
                    logger.info(f"议价成功，议价号：{ms_code}，议价执行：{is_agree}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"议价失败，议价号：{ms_code}，议价执行：{is_agree}")
            else:
                logger.error(f"Excel表格中的数据不全，议价号：{ms_code}，议价执行：{is_agree}")
    logger.info(f"总数：{total_num}，议价成功：{success}，议价失败：{total_num - success}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
