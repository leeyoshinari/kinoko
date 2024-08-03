#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari
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

host1 = 'https://ggfw.ybj.jiangxi.gov.cn'   # 登陆host
host2 = 'https://ypzc.ybj.jiangxi.gov.cn'  # 配送 host
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


def login(username, password, company):
    try:
        captcha_url = f'{host1}/hsa-local/hsa-pss-pw/web/pw/third/captchaImage'
        response = session.get(captcha_url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            data = {'imgCodeMsg': res_json['msgCode'], 'imgCodeUuid': res_json['uuid'], 'msgCode': '', 'loginType': '', 'username': username, 'password': hash256(password)}
            url = f'{host1}/hsa-local/hsa-pss-cw-local/pss/web/empUser/login'
            headers.update({'Content-Type': 'application/json'})
            response = session.post(url, json=data, headers=headers)
            login_params = {}
            if response.status_code == 200:
                res_json = json.loads(response.text)
                coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
                coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
                session.cookies.update(coo)
                login_params.update({'accessToken': res_json['data']['accessToken'], 'refreshToken': res_json['data']['refreshToken']})
                headers.update({'Accesstoken': res_json['data']['accessToken']})
                url = f'{host1}/hsa-local/hsa-pss-cw-local/pss/web/empUser/getUnitInfoList'
                response = session.post(url, headers=headers)
                if response.status_code == 200:
                    res_json = json.loads(response.text)
                    emp_list = [c for c in res_json['data'] if company == c['empName']]
                    if len(emp_list) == 0:
                        logger.error(f"登录失败，在可选择的登录单位中未找到 {company}，可选登录单位：{res_json['data']}")
                        raise
                    login_params.update({'empId': emp_list[0]['empId'], 'empNthlUact': emp_list[0]['empNthlUact']})
                    time.sleep(1)
                    url = f'{host1}/hsa-local/hsa-pss-cw-local/pss/web/empUser/agentSelectUnitLogin'
                    response = session.post(url, json=login_params, headers=headers)
                    if response.status_code == 200:
                        res_json = json.loads(response.text)
                        coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
                        coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
                        session.cookies.update(coo)
                        headers.update({'Accesstoken': res_json['data']['accessToken']})
                        url = f'{host1}/hsa-local/hsa-pss-cw-local/pss/web/empUser/getTokenInfo'
                        response = session.post(url, headers=headers)
                        headers.update({'Authorization': res_json['data']['accessToken']})
                        headers.update({'Refreshtoken': res_json['data']['refreshToken']})
                        headers.update({'Content-Type': 'application/json'})
                        headers.update({'Accounttype': '2'})
                        headers.update({'X-Xsrf-Token': 'null'})
                        headers.update({'Chooseuserorgcode': ''})
                        url = f"{host2}/tps-local/index?accessToken={res_json['data']['accessToken']}&accountType=2&refreshToken={res_json['data']['refreshToken']}"
                        headers.update({'Host': host2.split('/')[-1]})
                        headers.update({'Referer': host2})
                        if response.status_code == 200:
                            res_json = json.loads(response.text)
                            if res_json['data']['account'] == username:
                                logger.info(f"登陆成功：{res_json['data']['unitInfoDTO']['empName']} - {res_json['data']['agentInfoDTO']['empOpterName']}")
                            _ = session.get(url, headers=headers)
                            return response.status_code
                        else:
                            logger.error(f"登陆失败，状态码：{response.status_code}")
                            return None
                    else:
                        logger.error(f"登陆失败，状态码：{response.status_code}")
                        return None
                else:
                    return None
            else:
                return None
        else:
            return None
    except:
        logger.error(traceback.format_exc())
        return None

def step1(area: str, batch: str, res: dict) -> dict:
    try:
        url = f'{host2}/tps-local/web/tender/delv/schm/prod/list'
        data = {"admdvsName":area,"delvEntpName":"","schmCnfmStas":"","tenditmName":batch,"current":1,"size":10,"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] > 0:
                res.update({'admdvs': res_json['data']['records'][0]['admdvs']})
                res.update({'admdvsName': res_json['data']['records'][0]['admdvsName']})
                res.update({'tenditmId': res_json['data']['records'][0]['tenditmId']})
                return res
            else:
                logger.error(f'配送方案点选列表未找到数据，配送地区：{area}，动态批次：{batch}，响应值：{response.text}')
                raise
        else:
            logger.error(f'配送方案点选列表查询失败，配送地区：{area}，动态批次：{batch}，状态码：{response.status_code}')
            raise
    except:
        raise

def query_company(res: dict, type = 0) -> dict:
    try:
        if type == 0:   # 可选
            url = f'{host2}/tps-local/web/tender/delv/schm/prod/optlDelvlist'
        else:   # 已选
            url = f'{host2}/tps-local/web/tender/delv/schm/prod/prcdDelvlist'
        data = {"tenditmId":res['tenditmId'],"admdvs":res['admdvs'],"delvSchmId":"","admdvsName":res['admdvsName'],
                "delvEntpName":res['delvEntpName'],"schmCnfmStas":"","current":1,"size":10,"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] == 1:
                if type == 1:
                    res.update({'submitStatus': res_json['data']['records'][0]['schmCnfmStas']})
                    res.update({'delvSchmId': res_json['data']['records'][0]['delvSchmId']})
                    res.update({"delvEntpCode": res_json['data']['records'][0]['delvEntpCode']})
                    return res
                else:
                    res.update({'drtDelvFlag': res_json['data']['records'][0]['drtDelvFlag']})
                    res.update({"delvEntpCode": res_json['data']['records'][0]['delvEntpCode']})
                    return res
            elif res_json['data']['total'] > 1:
                logger.error(f"{['可选', '已选'][type]}配送企业列表中查询到多个企业，配送企业：{res['delvEntpName']}，查询结果：{response.text}")
                raise
            else:
                if type == 0:
                    logger.warning(f"可选配送企业列表中找不到企业，即将去已选配送企业中查找，配送企业：{res['delvEntpName']}，动态批次：{res['tenditmName']}，配送地区：{res['admdvsName']}")
                    return res
                else:
                    logger.error(f"已选配送企业列表中找不到企业，配送企业：{res['delvEntpName']}")
                    raise
        else:
            logger.error(f"{['可选', '已选'][type]}配送企业列表查询失败，企业名称：{res['delvEntpName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_company_bak(res: dict) -> dict:
    try:
        url = f'{host2}/tps-local/web/tender/delv/adjm/queryList'
        data = {"cntrCode": "", "delvEntpName": res['delvEntpName'], "tenditmName": res['tenditmName'], "admdvsName": res['admdvsName'],
         "cntrSignStas": "", "current": 1, "size": 10, "tenditmType": res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] == 1:
                res.update({'cntrId': res_json['data']['records'][0]['cntrId']})
                res.update({'cntrCode': res_json['data']['records'][0]['cntrCode']})
                res.update({'prodEntpName': res_json['data']['records'][0]['prodEntpName']})
                return res
            elif res_json['data']['total'] > 1:
                logger.error(f"配送签约调整列表中查询到多个企业，配送企业：{res['delvEntpName']}，查询结果：{response.text}")
                raise
            else:
                logger.info(f"配送签约调整列表中找不到企业，配送企业：{res['delvEntpName']}")
                raise
        else:
            logger.error(f"配送签约调整列表配送企业查询失败，企业名称：{res['delvEntpName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_adjmId(res: dict) -> dict:
    try:
        url = f'{host2}/tps-local/web/tender/delv/adjm/saveAdjmId'
        data = {"cntrId": res['cntrId'], "tenditmType": res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['success']:
                res.update({'adjmId': res_json['data']})
                return res
            else:
                logger.error(f"查询配送企业的 adjmId 失败，企业名称：{res['delvEntpName']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"查询配送企业的 adjmId 失败，企业名称：{res['delvEntpName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def add_choiceDelv(res: dict):
    try:
        url = f"{host2}/tps-local/web/tender/delv/schm/prod/choiceDelv"
        data = {"admdvs":res['admdvs'],"delvEntpCode":res['delvEntpCode'],"delvEntpName":res['delvEntpName'],"tenditmId":res['tenditmId'],
                "drtDelvFlag":res['drtDelvFlag'],"admdvsName":res['admdvsName'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['success']
        else:
            logger.error(f"添加到已选配送企业失败，配送企业：{res['delvEntpName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_code(res: dict, type = 1):
    try:
        if type == 1:
            url = f"{host2}/tps-local/web/tender/delv/schm/prod/prcdMCSList"
        else:
            url = f'{host2}/tps-local/web/tender/delv/schm/prod/optlMCSList'
        data = {"mcsRegcertName":"","mcsRegno":res['mcsRegno'],"current":1,"size":10,"delvSchmId":res['delvSchmId'],
                "admdvs":res['admdvs'],"tenditmId":res['tenditmId'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if type == 1:
                if res_json['data']:
                    return res_json['data']['total']
                else:
                    return 0
            else:
                if res_json['data']:
                    if res_json['data']['total'] > 0:
                        return res_json['data']['total']
                    else:
                        logger.error(f"{['可', '已'][type]}添加注册证查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                        raise
                else:
                    logger.error(f"{['可', '已'][type]}添加注册证查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                    raise
        else:
            logger.error(f"{['可', '已'][type]}添加注册证查询失败，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_code_bak(res: dict, type = 1):
    try:
        url = f'{host2}/tps-local/web/tender/delv/adjm/prod/mcsList'
        data = {"mcsRegno":res['mcsRegno'],"mcsRegcertName":"","prodEntpName":"","chooseFlag":str(type),"current":1,"size":10,
                "tenditmId":res['tenditmId'],"cntrId":res['cntrId'],"adjmId":res['adjmId'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if type == 1:
                if res_json['data']:
                    return res_json['data']['total']
                else:
                    return 0
            else:
                if res_json['data']:
                    if res_json['data']['total'] > 0:
                        return res_json['data']['total']
                    else:
                        logger.error(f"配送签约调整：{['可', '已'][type]}添加注册证查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                        raise
                else:
                    logger.error(f"配送签约调整：{['可', '已'][type]}添加注册证查询结果为空，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                    raise
        else:
            logger.error(f"配送签约调整：{['可', '已'][type]}添加注册证查询失败，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise

def add_code(res: dict, type = 1):
    try:
        if type == 1:
            url = f"{host2}/tps-local/web/tender/delv/schm/prod/delProdList"
        else:
            url = f'{host2}/tps-local/web/tender/delv/schm/prod/addProdList'
        data = {"productCode":[res['mcsRegno']],"delvSchmId":res['delvSchmId'],"delvEntpCode":res['delvEntpCode'],"delvEntpName":res['delvEntpName'],
                "admdvs":res['admdvs'],"admdvsName":res['admdvsName'],"tenditmId":res['tenditmId'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"{['添加', '取消'][type]}注册证失败，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"{['添加', '取消'][type]}注册证失败，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise

def add_code_bak(res: dict, type = 1):
    try:
        url = f'{host2}/tps-local/web/tender/delv/adjm/prod/chooseList'
        data = {"adjmProdCode": res['mcsRegno'], "invdFlag": str(type), "cntrId": res['cntrId'],
                "adjmId": res['adjmId'], "tenditmId": res['tenditmId'], "tenditmType": res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"配送签约调整：{['添加', '取消'][type]}注册证失败，注册证号：{res['mcsRegno']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"配送签约调整：{['添加', '取消'][type]}注册证失败，注册证号：{res['mcsRegno']}，状态码：{response.status_code}")
            raise
    except:
        raise

def submit_company(res: dict):
    try:
        url = f'{host2}/tps-local/web/tender/delv/schm/prod/submit'
        data = {"delvSchmId":res['delvSchmId'],"tenditmId":res['tenditmId'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"提交配送企业失败，配送企业：{res['delvEntpName']}，动态批次：{res['tenditmName']}，响应值：{response.text}")
                raise Exception(res_json['message'])
        else:
            logger.error(f"提交配送企业失败，配送企业：{res['delvEntpName']}，动态批次：{res['tenditmName']}，状态码：{response.status_code}")
            raise
    except:
        raise

def submit_company_bak(res: dict):
    try:
        url = f'{host2}/tps-local/web/tender/delv/adjm/updateAppyAdjm'
        data = {"tenditmName":res['tenditmName'],"initDelvProdCount":999,"admdvsName":res['admdvsName'],"prodEntpName":res['prodEntpName'],
                "cntrCode":res['cntrCode'],"delvEntpName":res['delvEntpName'],"cntrAdjmType":"2","cntrAdjmRea":"","adjmFileCode":"",
                "adjmId":res['adjmId'],"cntrId":res['cntrId'],"tenditmId":res['tenditmId'],"tenditmType":res['tenditmType']}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"配送签约调整：提交审核失败，配送企业：{res['delvEntpName']}，动态批次：{res['tenditmName']}，响应值：{response.text}")
                raise Exception(res_json['message'])
        else:
            logger.error(f"配送签约调整：提交审核失败，配送企业：{res['delvEntpName']}，动态批次：{res['tenditmName']}，状态码：{response.status_code}")
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


def parse_excel():
    res_dict = {}
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))  # 打开excel表格
        sheets = excel.sheet_names()  # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])  # 获取sheet中的单元格
        ind = 1
        i = 0
        for i in range(table.nrows):
            if '注册证号' == table.cell_value(i, 5).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):  # 遍历所有非空单元格
            if not table.cell_value(i, 1) and not table.cell_value(i, 2) and not table.cell_value(i, 5) and not table.cell_value(i, 6): continue
            org_name = table.cell_value(i, 1).strip()
            org_name_md5 = calc_md5(org_name)
            orders = str(table.cell_value(i, 2)).strip()
            order_md5 = calc_md5(orders)
            mcs_code = str(table.cell_value(i, 5)).strip()
            area = table.cell_value(i, 6).strip()
            area_md5 = calc_md5(area)
            if org_name_md5 in res_dict:
                if order_md5 in res_dict[org_name_md5]['v']:
                    if area_md5 in res_dict[org_name_md5]['v'][order_md5]['v']:
                        res_dict[org_name_md5]['v'][order_md5]['v'][area_md5]['v'].append(mcs_code)
                    else:
                        res_dict[org_name_md5]['v'][order_md5]['v'].update({area_md5: {'k': area, 'v': [mcs_code]}})
                else:
                    res_dict[org_name_md5]['v'].update({order_md5: {'k': orders, 'v': {area_md5: {'k': area, 'v': [mcs_code]}}}})
            else:
                res_dict.update({org_name_md5: {'k': org_name, 'v': {order_md5: {'k': orders, 'v': {area_md5: {'k': area, 'v': [mcs_code]}}}}}})
        logger.info(f'总共有 {i - ind + 1} 条待配送的数据')
        return res_dict, i - ind + 1

def read_company_from_excel():
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))  # 打开excel表格
        sheets = excel.sheet_names()  # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])  # 获取sheet中的单元格
        return table.cell_value(1, 4).strip()


try:
    username = ''
    password = ''
    origin_org_name = read_company_from_excel()
    logger.info(f"从 Excel 表格中读取到的生产企业名称是：{origin_org_name}.")
    company_json = json.load(open(os.path.join(current_path, 'company.txt'), 'r', encoding='utf-8'))
    for c in company_json:
        if c['company'] == origin_org_name:
            username = c['username']
            password = c['password']
            break
    if not username and not password:
        raise Exception("Excel 表格中的生产企业名称不在配置文件里，请去配置文件里新增数据。")

    coo.set('headerShow', 'false')
    coo.set('SESSION_FLAG', '1')
    session.cookies.update(coo)
    excel_data, total_num = parse_excel()
    access_token = None
    for _ in range(2):
        headers.update({"Host": host1.split('/')[-1], "Referer": host1})
        access_token = login(username, password, origin_org_name)
        if access_token:
            break
        time.sleep(2)
    if not access_token:
        raise Exception("连续2次登陆失败，请重试")

    success = 0
    summary = []
    success_result = []
    for _, v1 in excel_data.items():
        org_name = v1['k']
        for _, v2 in v1['v'].items():
            batch = v2['k']
            for _, v3 in v2['v'].items():
                try:
                    i3 = 0
                    s3 = 0
                    area = v3['k']
                    res = {"admdvsName": area, "delvEntpName": org_name, "tenditmName": batch, "tenditmType": "2"}
                    res = step1(area, batch, res)   # 查询地区编码和动态批次Id
                    res = query_company(res, 0) # 查询可选配送企业
                    if 'drtDelvFlag' in res:
                        logger.info(f"{org_name} - {batch} - {area} 未添加过，现在开始配送方案点选...")
                        a = add_choiceDelv(res)     # 添加到已选配送企业
                        time.sleep(0.5)
                    res = query_company(res, 1)   # 查询已选配送企业
                    if res['submitStatus'] != '0' and res['submitStatus'] != '2':
                        summary.append({"type": 0, 'c': org_name, 'b': batch, 'a': area})
                        logger.error(f"当前配送方案的状态不可进行配送方案点选或配送签约调整，请手动检查确认。配送企业：{org_name}，动态批次：{batch}，配送地区：{area}")
                        continue
                    if res['submitStatus'] == '2':
                        logger.info(f"{org_name} - {batch} - {area} 已经提交过，现在开始配送签约调整...")
                        res = query_company_bak(res)  # 查询配送签约调整企业列表
                        res = query_adjmId(res)     # 查询 adjmId
                    for mcs_code in v3['v']:
                        try:
                            res.update({'mcsRegno': mcs_code})
                            i3 += 1
                            del_str = ''
                            if res['submitStatus'] == '0':
                                if query_code(res, 1) > 0:  # 查询已添加注册证
                                    add_code(res, 1)    # 取消已添加的注册证
                                    del_str = '取消并重新'
                                    time.sleep(0.5)
                                _ = query_code(res, 0)  # 查询可添加注册证
                                add_code(res, 0)    # 添加注册证
                                logger.info(f"配送方案点选：{del_str}添加注册证成功：配送企业：{org_name}，动态批次：{batch}，配送地区：{area}，注册证号：{mcs_code}")
                            else:
                                if query_code_bak(res, 1) > 0:  # 查询已添加注册证
                                    add_code_bak(res, 1)    # 删除已添加的注册证
                                    del_str = '删除并重新'
                                    time.sleep(0.5)
                                _ = query_code_bak(res, 0) # 查询可添加注册证
                                add_code_bak(res, 0)    # 添加注册证
                                logger.info(f"配送签约调整：{del_str}添加注册证成功：配送企业：{org_name}，动态批次：{batch}，配送地区：{area}，注册证号：{mcs_code}")
                            success += 1
                            s3 += 1
                            time.sleep(1)
                        except:
                            logger.error(traceback.format_exc())
                            if res['submitStatus'] == '0':
                                summary.append({"type": 1, 'c': org_name, 'b': batch, 'a': area, 'z': mcs_code})
                                logger.error(f"配送方案点选：添加注册证失败：配送企业：{org_name}，动态批次：{batch}，配送地区：{area}，注册证号：{mcs_code}")
                            else:
                                summary.append({"type": 2, 'c': org_name, 'b': batch, 'a': area, 'z': mcs_code})
                                logger.error(f"配送签约调整：添加注册证失败：配送企业：{org_name}，动态批次：{batch}，配送地区：{area}，注册证号：{mcs_code}")
                    if res['submitStatus'] == '0':
                        try:
                            submit_company(res)
                            success_result.append(f"配送方案点选,{org_name},{batch},{area},{i3},{s3},{i3 - s3}")
                            logger.info(f"配送方案点选：提交成功，{org_name} - {batch} - {area}，总共配送 {i3} 个注册证号，成功 {s3} 个，失败 {i3 - s3} 个")
                        except:
                            summary.append({"type": 3, 'c': org_name, 'b': batch, 'a': area})
                            logger.error(traceback.format_exc())
                            logger.error(f"配送方案点选：提交失败，配送企业：{org_name}，动态批次：{batch}，配送地区：{area}")
                    else:
                        try:
                            submit_company_bak(res)
                            success_result.append(f"配送签约调整,{org_name},{batch},{area},{i3},{s3},{i3 - s3}")
                            logger.info(f"配送签约调整：提交审核成功，{org_name} - {batch} - {area}，总共配送 {i3} 个注册证号，成功 {s3} 个，失败 {i3 - s3} 个")
                        except:
                            summary.append({"type": 4, 'c': org_name, 'b': batch, 'a': area})
                            logger.error(traceback.format_exc())
                            logger.error(f"配送签约调整：提交审核失败，配送企业：{org_name}，动态批次：{batch}，配送地区：{area}")
                except:
                    summary.append({"type": 5, 'c': org_name, 'b': batch, 'a': area})
                    logger.error(traceback.format_exc())
                    logger.error(f"在配送企业列表中找不到企业：配送企业：{org_name}，动态批次：{batch}，配送地区：{area}")
    if len(summary) > 0:
        logger.info("-" * 69)
        logger.info("所有报错数据汇总：")
        logger.info("-" * 69)
        for c in summary:
            if c['type'] == 0:
                logger.error(f"当前配送方案的状态不可进行配送方案点选或配送签约调整，请手动检查确认。配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}")
            if c['type'] == 1:
                logger.error(f"配送方案点选：添加注册证失败：配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}，注册证号：{c['z']}")
            if c['type'] == 2:
                logger.error(f"配送签约调整：添加注册证失败：配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}，注册证号：{c['z']}")
            if c['type'] == 3:
                logger.error(f"配送方案点选：提交失败，配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}")
            if c['type'] == 4:
                logger.error(f"配送签约调整：提交审核失败，配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}")
            if c['type'] == 5:
                logger.error(f"在配送企业列表中找不到企业：配送企业：{c['c']}，动态批次：{c['b']}，配送地区：{c['a']}")
        logger.info("-" * 69)
    logger.info(f"总共配送 {total_num} 个注册证号，其中成功 {success} 个，失败 {total_num - success} 个")
    file_name = time.strftime('%Y-%m-%d %H%M%S') + '.txt'
    with open(os.path.join(current_path, file_name), 'w', encoding='utf-8') as f:
        f.write(f"生产企业,类型,配送企业,动态批次,配送地区,配送注册证号总数,配送注册证号成功数,配送注册证号失败数\n")
        for s in success_result:
            f.write(f"{origin_org_name},{s}\n")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
