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
from requests_toolbelt import MultipartEncoder
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://www.nmgybggfw.org.cn'   # 登陆host
host2 = 'http://60.31.22.187:9000'  # 配送 host
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
formatter = logging.Formatter('%(asctime)s - %(levelname)s - line:%(lineno)d - %(message)s')
logger.setLevel(level=logging.INFO)
file_handler = logging.handlers.TimedRotatingFileHandler(os.path.join(current_path, 'run.txt'), when='midnight', interval=1, backupCount=3)
file_handler.suffix = '%Y-%m-%d.txt'
console_handler = logging.StreamHandler()
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)
file_path = os.path.join(current_path, "文件")
cookie_path = os.path.join(current_path, "cookie.txt")


def login(username, password):
    try:
        url = f'{host1}/has-pss-cw/pss/web/empUser/login'
        data = {"username": username, "loginType": "7", "password": hash256(password)}
        headers.update({'Content-Type': 'application/json'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
            coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
            session.cookies.update(coo)
            headers.update({'Accesstoken': res_json['data']['accessToken']})
            headers.update({'Authorization': res_json['data']['accessToken']})
            headers.update({'Refreshtoken': res_json['data']['refreshToken']})
            headers.update({'Accounttype': '2'})
            with open(cookie_path, 'w', encoding='utf-8') as fp:
                fp.write(json.dumps({"accessToken": res_json['data']['accessToken'], "refreshToken": res_json['data']['refreshToken']}))
            url = f'{host1}/has-pss-cw/pss/web/empUser/getTokenInfo'
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
        url = f'{host1}/has-pss-cw/pss/web/empUser/getTokenInfo'
        response = session.post(url, headers=headers)
        headers.update({'Host': host2.split('/')[-1]})
        headers.update({'Referer': host2})
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0:
                logger.info(f"登陆成功：{res_json['data']['account']}")
                return response.status_code
            else:
                return None
        else:
            return None
    except:
        return None


def query_company(res: dict):
    try:
        url = f"{host2}/tps-local-bd/web/std/bidprcuOrgInfo/getMcsOrgInfoPage?current=1&size=10&searchCount=true&orgName={urllib.parse.quote(res['delventpName'])}&queryArea={res['admdvs']}&tenditmId={res['tenditmId']}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] > 0:
                for c in res_json['data']['records']:
                    if res['delventpName'] == c['orgName'] and 'uscc' in c:
                        res.update({'delventpCode': c['entpCode']})
                        return res
                logger.error(f"配送企业查询结果不正确，配送企业：{res['delventpName']}，响应值：{res_json}")
            # elif res_json['data']['total'] > 1:
            #     logger.error(f"配送企业查询到多条数据，配送企业：{res['delventpName']}，响应值：{response.text}")
                raise
            else:
                logger.error(f"配送企业查询结果为空，配送企业：{res['delventpName']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"配送企业查询失败，配送企业：{res['delventpName']}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_company_dai(res: dict):
    try:
        url = f"{host2}/tps-local-bd/web/std/bidprcuOrgInfo/getMcsAmountOrgInfoPage?current=1&size=10&searchCount=true&orgName={urllib.parse.quote(res['delventpName'])}&tenditmId={res['tenditmId']}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] > 0:
                for c in res_json['data']['records']:
                    if res['delventpName'] == c['orgName'] and 'uscc' in c:
                        res.update({'delventpCode': c['entpCode']})
                        return res
                logger.error(f"配送企业查询结果不正确，配送企业：{res['delventpName']}，响应值：{res_json}")
            # elif res_json['data']['total'] > 1:
            #     logger.error(f"配送企业查询到多条数据，配送企业：{res['delventpName']}，响应值：{response.text}")
                raise
            else:
                logger.error(f"配送企业查询结果为空，配送企业：{res['delventpName']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"配送企业查询失败，配送企业：{res['delventpName']}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_code(res: dict):
    try:
        headers.update({'Content-Type': 'application/json'})
        url = f"{host2}/tps-local-bd/web/trns/trnsProdMcs/getTrnsProdDrugByDelvRltlSetPage?current=1&size=10&searchCount=true&purcProdType={res['purcProdType']}&mcsRegno={urllib.parse.quote(res['mcsRegno'])}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            try:
                res_json = json.loads(response.text)
                if res_json['data']:
                    if res_json['data']['total'] >= 1:
                        for r in res_json['data']['records']:
                            if r['mcsRegno'] == res['mcsRegno']:
                                res.update({'tenditmId': r['tenditmId']})
                                res.update({'mcsRegcertName': r['mcsRegcertName']})
                                res.update({'tenditmName': r['tenditmName']})
                                res.update({'prodentpName': r['prodentpName']})
                                if 'regcertExpy' in r:
                                    res.update({'regcertExpy': r['regcertExpy']})
                                return res
                    # elif res_json['data']['total'] > 1:
                    #     logger.error(f"注册证号查询结果有多条，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                    #     raise
                    else:
                        logger.error(f"注册证号查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                        raise
                else:
                    logger.error(f"注册证号查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                    raise
            except:
                logger.error(f"注册证号查询结果错误，注册证号：{res['mcsRegno']}，res：{res}，响应值：{response.text}")
                logger.error(traceback.format_exc())
                raise
        else:
            logger.error(f"注册证号查询失败，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        logger.error(f"注册证号查询结果为空，注册证号：{res['mcsRegno']}，res：{res}")
        raise

def query_areas(res: dict):
    try:
        url = f'{host2}/tps-local-bd/web/std/admdvsInfo/list?prntAdmdvs=150000'
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for a in res_json['data']:
                if res['admdvsName'] == a['admdvsName']:
                    res.update({'admdvs': a['admdvs']})
                    return res
            logger.error(f"未找到配送地区，配送地区：{res['admdvsName']}，响应值：{response.text}")
            raise
        else:
            logger.error(f"查询配送地区失败，配送地区：{res['admdvsName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def submit_c(res: dict):
    try:
        url = f'{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/batchSaveTrnsDelvRltl'
        data = [res]
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            logger.error(f"配送失败，配送企业：{res['delventpName']}，配送地区：{res['admdvsName']}，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise


def batchSubmitByIds(res: dict):
    try:
        url = f'{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/batchSubmitByIds'
        headers.update({'Content-Type': 'application/json'})
        response = session.put(url, json=res, headers=headers)
        if response.status_code == 200:
            return json.loads(response.text)
        else:
            logger.error(f"配送失败，配送参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise


def upload_file(fileName: str) -> str:
    file_names = os.path.join(file_path, fileName)
    if not os.path.exists(file_names):
        logger.error(f'文件不存在，文件名：{fileName}')
        raise
    try:
        url = f'{host2}/tps-local/web/comp/file/upload'
        data = MultipartEncoder(fields={"file": (fileName, open(file_names, 'rb'), "application/octet-stream")},
                                boundary='------WebKitFormBoundaryipWHtQRBbfBM7i0g')
        headers.update({'Content-Type': data.content_type})
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['data']['fileId']
        else:
            logger.error(f"文件件上传失败，状态码：{response.status_code}，文件名：{fileName}")
            raise
    except:
        logger.error(f"文件上传失败，文件名：{fileName}")
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
            if '注册证号' in table.cell_value(i, 3).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):  # 遍历所有非空单元格
            if not table.cell_value(i, 3): continue
            total_num += 1
            mcs_code = table.cell_value(i, 3).strip()
            org_name = table.cell_value(i, 5).strip()
            area = table.cell_value(i, 6).strip()
            pdf_file = table.cell_value(i, 7).strip()
            excel_file = table.cell_value(i, 8).strip()
            log_str = ''
            if mcs_code and org_name and area:
                try:
                    time.sleep(1)
                    res = {'mcsRegno': mcs_code, 'delventpName': org_name, 'admdvsName': area, 'purcProdType': '0', 'delvRltlStas': '1'}
                    if pdf_file and excel_file:
                        res['purcProdType'] = '1'
                        res['delvRltlStas'] = '0'
                        log_str = f"，PDF文件：{pdf_file}，Excel文件：{excel_file}"
                    res = query_code(res)
                    res = query_areas(res)
                    if res['purcProdType'] == '1' and res['delvRltlStas'] == '0':
                        res = query_company_dai(res)
                        res.update({'queryArea': [res['admdvs']]})
                    else:
                        res = query_company(res)
                    res_dict = submit_c(res)
                    if res_dict['code'] == 0 and res_dict['data'] and res_dict['data']['idList'] and len(res_dict['data']['idList']) == 1:
                        if res['purcProdType'] == '1' and res['delvRltlStas'] == '0':
                            submit_data = {"drugDelvRltlIds": res_dict['data']['idList']}
                            pdfFileId = upload_file(pdf_file + ".pdf")
                            excelFileId = upload_file(excel_file + ".xlsx")
                            submit_data.update({"pdfFileId": pdfFileId, "excelFileId": excelFileId})
                            res_dict = batchSubmitByIds(submit_data)
                            if res_dict['code'] != 0:
                                logger.error(f"配送失败：配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}，响应值：{res_dict}")
                                continue
                        success += 1
                        logger.info(f"配送成功：配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}")
                    elif res_dict['code'] == 160003:
                        has_send += 1
                        logger.warning(f"已经配送过了，配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}，message: {res_dict['message']}")
                        continue
                    else:
                        logger.error(f"配送失败：配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}，响应值：{res_dict}")
                        continue
                except:
                    logger.error(f"配送失败：配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：配送企业：{org_name}，配送地区：{area}，注册证号：{mcs_code}{log_str}")
    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num - success - has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
