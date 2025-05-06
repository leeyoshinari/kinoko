#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import random
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
area_code = json.load(open(os.path.join(current_path, 'guangdong.json'), 'r', encoding='utf-8'))
resubmit_num = 0


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


def query_company(company, res: dict):
    try:
        url = f'{host2}/gpo/tps_local_bd/web/mcsTrade/distributionArea/getmcsdelvpscomppageNew'
        admdvsList = [adm['admdvs'] for adm in res['admdvsDtoList']]
        areas = [adm['admdvsName'] for adm in res['admdvsDtoList']]
        druglist = ["undefined-undefined"]  # ["undefined-" + dru['tenditmId'] for dru in res['drugDtoList']]
        data = {"admdvsList": admdvsList, "druglist": druglist, "distributionType": res["distributionType"], "orgName": company}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data'] and len(res_json['data']['records']) > 0:
                for rr in res_json['data']['records']:
                    if rr['orgName'] == company:
                        res.update({"delventpCode": rr['uscc']})
                        res.update({"delventpname": rr['orgName']})
                        return res
                logger.error(f"配送企业查询到多个，配送企业：{company}，配送地区：{','.join(areas)}，查询结果：{res_json['data']['records']}")
                raise
            else:
                logger.error(f"配送企业查询为空，配送企业：{company}，配送地区：{','.join(areas)}，响应值：{res_json['data']}")
                raise
        else:
            logger.error(f"配送企业查询失败，企业名称：{company}，配送地区：{','.join(areas)}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_send_list(ms_code, company, city):
    try:
        url = f'{host2}/gpo/tps_local_bd/web/mcsTrade/distributionArea/getDelvAreaDrugInfo'
        data = {"current": 1, "size": 10, "searchCount": True, "searchTime": [], "goodsId": str(ms_code), "admdvsName": city, "delvEntpName": company, "isGroup": "1"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            if '重新登录' in response.text and '其他设备' in response.text:
                atoken = login(username, password, origin_org_name)
                if atoken:
                    response = session.post(url, json=data, headers=headers)
                else:
                    raise Exception('登陆状态已失效')
            if '过期' in response.text and 'oken' in response.text:
                atoken = login(username, password, origin_org_name)
                if atoken:
                    response = session.post(url, json=data, headers=headers)
                else:
                    raise Exception('登陆状态已失效')
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data'] and len(res_json['data']['records']) == 1:
                if res_json['data']['records'][0]['prodAsocStatus'] == '99':
                    logger.info(f"当前配送关系状态为 已作废，正在重新提交。产品ID：{ms_code}，配送企业：{company}，配送区域：{city}")
                    return -1   # res_json['data']['records'][0]['schmProdId']
                else:
                    prodAsocStatus = min(int(res_json['data']['records'][0]['prodAsocStatus']), 3)
                    logger.warning(f"当前配送关系状态为 {['生产未提交', '生产已提交', '已生效', '配送已拒绝'][prodAsocStatus]}，跳过不处理。产品ID：{ms_code}，配送企业：{company}，配送区域：{city}")
                    return -2
            elif res_json['code'] == 0 and len(res_json['data']['records']) > 1:
                logger.warning(f"配送关系列表查询到多个，产品ID：{ms_code}，配送企业：{company}，配送区域：{city}，查询结果：{res_json['data']['records']}")
                return -1
            elif res_json['code'] == 0 and len(res_json['data']['records']) == 0:
                return -1
            else:
                logger.warning(f"配送关系列表查询异常，产品ID：{ms_code}，配送企业：{company}，配送区域：{city}，查询结果：{res_json}")
                return -1
        else:
            logger.warning(f"配送关系列表查询失败，产品ID：{ms_code}，企业名称：{company}，配送区域：{city}，状态码：{response.status_code}")
            return -1
    except:
        logger.error(traceback.format_exc())
        return -1


def resubmit(schmProdId):
    try:
        url = f'{host2}/gpo/tps_local_bd/web/mcsTrade/distributionArea/updateStatusByProdId'
        data = {"prodAsocStatus": "1", "schmProdId": schmProdId}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0 and not res_json['success']:
                logger.error(f"配送关系重新提交失败，schmProdId：{schmProdId}，响应值：{response.text}")
                raise Exception(res_json['message'])
        else:
            logger.error(f"配送关系重新提交失败，schmProdId：{schmProdId}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_areas(city, district, distributionType, res: dict):
    try:
        res.update({"admdvsDtoList": []})
        res.update({"distributionType": distributionType})
        for area in area_code:
            if area['label'] == city:
                if distributionType == 0:
                    res["admdvsDtoList"].append({"admdvs": area['value'], "admdvsName": area['label']})
                    break
                else:
                    if district:
                        district_raw = district.split(',')
                        for distr in area['children']:
                            if distr['label'] in district_raw:
                                res["admdvsDtoList"].append({"admdvs": distr['value'], "admdvsName": distr['label']})
                        break
                    else:
                        logger.error("区县数据为空，请检查excel表格数据")
                        raise
        if len(res["admdvsDtoList"]) == 0:
            logger.error(f"配送地区查询失败，所属市：{city}，所属区县：{district}")
            raise
        return res
    except:
        raise


def query_code(ms_code, company, res: dict):
    try:
        url = f"{host2}/gpo/tps_local_bd/web/mcsTrade/distributionArea/getTrnsProdMcsScPage"
        schmProdId = query_send_list(ms_code, company, res['admdvsDtoList'][0]['admdvsName'])
        if schmProdId == -2:
            logger.warning(f"当前配送关系已提交，跳过不处理。产品ID：{ms_code}，配送企业：{company}，配送地区：{res['admdvsDtoList'][0]['admdvsName']}")
            return None
        if schmProdId != -1:
            try:
                resubmit(schmProdId)
                global resubmit_num
                resubmit_num += 1
                logger.info(f"配送关系重新提交成功，产品ID：{ms_code}，配送企业：{company}，配送地区：{res['admdvsDtoList'][0]['admdvsName']}")
            except:
                logger.error(traceback.format_exc())
                logger.error(f"配送关系重新提交失败，产品ID：{ms_code}，配送企业：{company}，配送地区：{res['admdvsDtoList'][0]['admdvsName']}")
            finally:
                return None
        data = {"current": 1, "size": 10, "searchCount": True, "goodsName": None, "ybCode": None, "tenditmName": None, "goodsId": str(ms_code), "procurecatalogId": "", "purchaseType": "2", "group": 0, "isUsing": 1}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data'] and len(res_json['data']['records']) == 1:
                res.update({"drugDtoList": [{"procurecatalogId": res_json['data']['records'][0]['procurecatalogId']}]})
                return res
            else:
                if res_json['code'] != 0:
                    logger.error(f"产品ID查询结果为空，产品ID：{ms_code}，查询结果：{response.text}")
                    raise
                else:
                    logger.error(f"产品ID查询结果为空或有多个，产品ID：{ms_code}，查询结果：{res_json['data']['records']}")
                    raise
        else:
            logger.error(f"产品ID查询查询失败，产品ID：{ms_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def submit_c(res: dict):
    try:
        url = f'{host2}/gpo/tps_local_bd/web/mcsTrade/distributionArea/saveDrugDelvPost'
        res.update({'remarks': ''})
        res.update({'status': '1'})
        response = session.post(url, json=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0 and not res_json['success']:
                areas1 = [adm['admdvsName'] for adm in res['admdvsDtoList']]
                logger.error(f"配送提交失败，商品ID：{res['drugDtoList'][0]['procurecatalogId']}，配送企业：{res['delventpname']}，配送地区：{','.join(areas1)}，响应值：{response.text}")
                raise Exception(res_json['message'])
        else:
            areas1 = [adm['admdvsName'] for adm in res['admdvsDtoList']]
            logger.error(f"配送提交失败，商品ID：{res['drugDtoList'][0]['procurecatalogId']}，配送企业：{res['delventpname']}，配送地区：{','.join(areas1)}，状态码：{response.status_code}")
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
    res_dict = []
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xlsx')] + [n for n in os.listdir(current_path) if n.endswith('.xls')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '药交ID' in table.cell_value(i, 7):
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):
            if not table.cell_value(i, 7): continue
            try:
                ms_code = table.cell_value(i, 7).strip()
            except:
                ms_code = str(int(table.cell_value(i, 7)))
            company = table.cell_value(i, 2).strip()
            is_city = table.cell_value(i, 3).strip()
            city = table.cell_value(i, 4).strip()
            district = None if is_city == '地市' else table.cell_value(i, 5).strip()
            res_dict.append({'company': company, 'ms_code': ms_code, 'is_city': is_city, 'city': city, 'district': district})
    return res_dict


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
    excel_data = parse_excel()
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

    success = 0
    for r in excel_data:
        company = r['company']
        is_city = r['is_city']
        city = r['city']
        district = r['district']
        ms_code = r['ms_code']
        distributionType = 0 if is_city == '地市' else 1
        if ms_code and company and is_city and city:
            try:
                res = {"distributionType": distributionType}
                res = query_areas(city, district, distributionType, res)
                res = query_code(ms_code, company, res)
                if not res:
                    resubmit_num += 1
                    continue
                res = query_company(company, res)
                areas = [adm['admdvsName'] for adm in res['admdvsDtoList']]
                submit_c(res)
                success += 1
                logger.info(f"配送成功，产品ID：{ms_code}，配送企业：{company}，配送地区：{','.join(areas)}")
            except:
                logger.error(traceback.format_exc())
                areas = city if is_city == '地市' else district
                logger.error(f"配送失败，产品ID：{ms_code}，配送企业：{company}，配送地区：{areas}")
        else:
            areas = city if is_city == '地市' else district
            logger.error(f"Excel表格中的数据不全，产品ID：{ms_code}，配送企业：{company}，配送地区：{areas}")
    logger.info(f"总数：{len(excel_data)}，配送成功：{success + resubmit_num}，配送失败：{len(excel_data) - success - resubmit_num}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
