#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import threading
import traceback
import logging.handlers
import urllib.parse
import requests.packages.urllib3
import requests.cookies
import requests
import hashlib
import win32gui
import win32con
import xlrd
from pywinauto import Application, Desktop
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://zwfw.shaanxi.gov.cn'   # 登陆host
host2 = 'http://112.46.88.200:8082'  # 配送 host
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
window_title = '登录'
button_title = '确定'


def request_ca(url, data):
    try:
        header_tmp = {"Content-Type": "text/plain;charset=UTF-8", "credentials": "omit"}
        response = requests.post(url, data=data, headers=header_tmp, verify=False)
        if response.status_code == 200:
            return response.text
    except:
        logger.error(traceback.format_exc())
        raise


def login():
    try:
        url = f'{host1}/ggfw/has-pss-cw/gm300RandomService/getRandom'
        res = session.post(url, headers=headers)
        if res.status_code == 200:
            res_json = json.loads(res.text)
            original = res_json['data']['original']
            url = 'https://127.0.0.1:10087/'
            data = 'QueryService'
            url = request_ca(url, data)
            data = "P7SignString:{\"strValue\":\"" + original + "\",\"isDetach\":true,\"isIncludeCert\":true}"
            res = request_ca(url, data)
            res_json = json.loads(res)
            url = f"{host1}/ggfw/has-pss-cw/pss/web/empUser/caLogin"
            data = {"caType": "GM3000", "authMode": "cert", "original": original, "signed_data": res_json['value']}
            res = session.post(url, json=data, headers=headers)
            if res.status_code == 200:
                res_json = json.loads(res.text)
                if res_json['code'] == 0:
                    coo.set('service-mall-accesstoken', res_json['data']['accessToken'])
                    coo.set('service-mall-refreshtoken', res_json['data']['refreshToken'])
                    session.cookies.update(coo)
                    headers.update({'Authorization': res_json['data']['accessToken']})
                    headers.update({'Accesstoken': res_json['data']['accessToken']})
                    headers.update({'Refreshtoken': res_json['data']['refreshToken']})
                    headers.update({'Content-Type': 'application/json'})
                    # headers.update({'Encryptflag': 'true'})
                    cookie_dict = {"service-mall-accesstoken": res_json['data']['accessToken'],"service-mall-refreshtoken": res_json['data']['refreshToken']}
                    url = f'{host1}/ggfw/has-pss-cw/pss/web/empUser/getUnitInfo'
                    response = session.post(url, headers=headers)
                    if response.status_code == 200:
                        res_json = json.loads(response.text)
                        if res_json['code'] == 0:
                            logger.info(f"登陆成功：{res_json['data']['empName']} - {res_json['data']['empUact']}")
                            headers.update({'Host': host2.split('/')[-1]})
                            headers.update({'Referer': host2})
                            headers.update({'Uscc': res_json['data']['uscc']})
                            headers.update({'Accounttype': '2'})
                            headers.update({'X-Xsrf-Token': 'null'})
                            headers.update({'Chooseuserorgcode': ''})
                            cookie_dict.update({'uscc': res_json['data']['uscc']})
                            with open(cookie_path, 'w', encoding='utf-8') as fp:
                                fp.write(json.dumps(cookie_dict))
                            tmp_url = f"{host2}/tps-local/#/?accessToken={cookie_dict['service-mall-accesstoken']}&accountType=2&refreshToken={cookie_dict['service-mall-refreshtoken']}&uscc={cookie_dict['uscc']}"
                            _ = session.get(tmp_url, headers=headers)
                            return True
                        else:
                            logger.error(f"登陆失败，响应值：{res_json}")
                            return None
                    else:
                        logger.error(f"登陆失败，状态码：{response.status_code}")
                        return None
                else:
                    logger.error(f"登陆失败，响应值：{res_json}")
                    return None
            else:
                logger.error(f"登陆失败，状态码：{res.status_code}")
                return None
        else:
            logger.error(f"登陆失败，状态码：{res.status_code}")
            return None
    except:
        logger.error(traceback.format_exc())
        raise


def getTrnsDelvRltlListByScOrZx(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/getTrnsDelvRltlListByScOrZx?current=1&size=10&searchCount=true&prodCode={res['prodCode']}&delventpName={urllib.parse.quote(res['orgName'])}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['prodCode'] == res['prodCode'] and r['delventpName'] == res['orgName']:
                    res.update({"drugDelvRltlId": r['drugDelvRltlId']})
                    res.update({"delvRltlStas": r['delvRltlStas']})
                    return res
        return False
    except:
        logger.error(traceback.format_exc())
        return False


def query_send_relation(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsProdMcs/getTrnsProdDrugByDelvRltlSetPage?current=1&size=10&searchCount=true&prodCode={res['prodCode']}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['prodCode'] == res['prodCode']:
                    res.update({"mcsProdId": r['mcsProdId']})
                    res.update({"dclaEntpName": r['dclaEntpName']})
                    res.update({"dclaEntpCode": r['dclaEntpCode']})
                    res.update({"prodentpName": r['prodentpName']})
                    res.update({"pubonlnStas": r['pubonlnStas']})
                    res.update({"tenditmId": r['tenditmId']})
                    return res
            logger.error(f"未找到医保耗材代码，查询结果：{response.text}")
            raise
        else:
            logger.error(f"查询配送关系列表失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def getSettingDelventpNewPage(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsMcsHospList/getSettingDelventpNewPage?current=1&size=10&searchCount=true&prodCode={res['prodCode']}&isNotice=1&isSetting=1"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['prodCode'] == res['prodCode']:
                    res.update({"prodId": r['prodId']})
                    res.update({"dclaEntpName": r['dclaEntpName']})
                    res.update({"dclaEntpCode": r['dclaEntpCode']})
                    res.update({"prodentpName": r['prodentpName']})
                    res.update({"pubonlnStas": r['pubonlnStas']})
                    return res
            logger.error(f"未找到医保耗材代码，查询结果：{response.text}")
            raise
        else:
            logger.error(f"查询配送关系列表失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def query_hospital(res):
    try:
        url = f"{host2}/tps-local-bd/web/std/bidprcuOrgInfo/pageList?current=1&size=10&searchCount=true&orgName={urllib.parse.quote(res['orgName'])}&orgTypeCode=2"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['orgName'] == res['orgName']:
                    res.update({"entpCode": r['entpCode']})
                    return res
            logger.error(f"未找到医疗机构，查询结果：{response.text}")
            raise
        else:
            logger.error(f"查询医疗机构失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def query_company_relation(res):
    try:
        url = f"{host2}/tps-local-bd/web/std/bidprcuOrgInfo/getMcsOrgInfoPage?current=1&size=10&searchCount=true&orgName={urllib.parse.quote(res['orgName'])}&tenditmId={res['tenditmId']}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['orgName'] == res['orgName']:
                    res.update({"entpCode": r['entpCode']})
                    return res
            logger.error(f"未找到配送企业，查询结果：{response.text}")
            raise
        else:
            logger.error(f"查询配送企业失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def getEntityNew(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/getEntityNew?current=1&size=10&searchCount=true&delventpName={urllib.parse.quote(res['delventpName'])}&prodId={res['prodId']}&medinsCode={res['entpCode']}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for r in res_json['data']['records']:
                if r['delventpName'] == res['delventpName']:
                    res.update({"delventpCode": r['delventpCode']})
                    res.update({"crteOptinsNo": r['crteOptinsNo']})
                    res.update({"drugDelvRltlId": r['drugDelvRltlId']})
                    if 'hospDelvId' in r:
                        res.update({"hospDelvId": r['hospDelvId']})
                    return res
            logger.error(f"未找到配送企业，查询结果：{response.text}")
            raise
        else:
            logger.error(f"查询配送企业失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def batchSubmitByIds(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/batchSubmitByIds"
        post_data = {"drugDelvRltlIds": [res['drugDelvRltlId']]}
        response = session.post(url, json=post_data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0:
                return True
            else:
                logger.error(res_json['message'])
                raise
        else:
            logger.error(f"配送关系提交失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def batchSaveTrnsDelvRltl(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/trnsMcsDelvRltl/batchSaveTrnsDelvRltl"
        post_data = [{"prodId":res['mcsProdId'],"tenditmId":res['tenditmId'],"prodentpName":res['prodentpName'],"dclaEntpCode":res['dclaEntpCode'],"dclaEntpName":res['dclaEntpName'],"pubonlnStas":res['pubonlnStas'],"delventpCode":res['entpCode'],"delventpName":res['orgName']}]
        response = session.post(url, json=post_data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] in (0, 160003):
                return res_json['code']
            else:
                logger.error(res_json['message'])
                raise
        else:
            logger.error(f"配送关系设置失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def setHospDelv(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/TrnsMcsHospDelvController/trnsHospDelv/setHospDelv"
        post_data = {"prodId":res['prodId'],"medinsCode":res['entpCode'],"medinsName":res['orgName'],"dclaEntpCode":res['crteOptinsNo'],"delventpCode":res['delventpCode'],"delventpName":res['delventpName'],"mcsDelvRltlId":res['drugDelvRltlId']}
        response = session.post(url, json=post_data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] in (0, 160003):
                return res_json['code']
            else:
                logger.error(res_json['message'])
                raise
        else:
            logger.error(f"配送失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def trnsHospDelvdeleteById(res):
    try:
        url = f"{host2}/tps-local-bd/web/trns/TrnsMcsHospDelvController/trnsHospDelv/deleteById/{res['hospDelvId']}"
        response = session.delete(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0:
                logger.error(res_json['message'])
                raise
        else:
            logger.error(f"删除配送失败，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def is_open_window():
    windows = Desktop().windows()
    return any(window.window_text() == window_title for window in windows)


def is_exist_window():
    hwnd = win32gui.FindWindow(None, window_title)
    return hwnd != 0


def deal_sign_window(pwd: str):
    while True:
        if is_open_window():
            try:
                window = Application().connect(title=window_title).window(title=window_title)
                window.child_window(class_name='Edit', top_level_only=False, found_index=0).type_keys(pwd)
                time.sleep(0.5)
                window.child_window(title=button_title).click()
                time.sleep(1)
                if is_open_window():
                    time.sleep(1)
                    if is_exist_window():
                        hwnd = win32gui.FindWindow(None, window_title)
                        win32gui.SetForegroundWindow(hwnd)
                        edit_window = []

                        def enum_child_windows_callback(child_hwnd, lParam):
                            child_class_name = win32gui.GetClassName(child_hwnd)
                            if child_class_name == 'Edit':
                                edit_window.append(child_hwnd)
                            return True

                        win32gui.EnumChildWindows(hwnd, enum_child_windows_callback, 0)
                        win32gui.SendMessage(edit_window[1], win32con.WM_SETTEXT, 0, pwd)
                        button_hwnd = win32gui.FindWindowEx(hwnd, 0, None, button_title)
                        time.sleep(0.5)
                        win32gui.SendMessage(button_hwnd, win32con.BM_CLICK, 0, 0)
                        time.sleep(1)
                        if is_exist_window():
                            win32gui.SendMessage(button_hwnd, win32con.BM_CLICK, 0, 0)
                time.sleep(2)
            except:
                logger.error(traceback.format_exc())
        else:
            time.sleep(2)


def check_login():
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
            headers.update({'Uscc': cookies_dict['uscc']})
            headers.update({'Accounttype': '2'})
            headers.update({'X-Xsrf-Token': 'null'})
            headers.update({'Chooseuserorgcode': ''})
            url = f'{host1}/ggfw/has-pss-cw/pss/web/empUser/getUnitInfo'
            response = session.post(url, headers=headers)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                logger.info(f"免登陆成功：{res_json['data']['empName']} - {res_json['data']['empUact']}")
                headers.update({'Host': host2.split('/')[-1]})
                headers.update({'Referer': host2})
                tmp_url = f"{host2}/tps-local/#/?accessToken={cookies_dict['service-mall-accesstoken']}&accountType=2&refreshToken={cookies_dict['service-mall-refreshtoken']}&uscc={cookies_dict['uscc']}"
                _ = session.get(tmp_url, headers=headers)
                return True
            else:
                return False
        else:
            return False
    except:
        return False


try:
    sign_pwd = '88888888'
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'password' in lin:
                sign_pwd = lin.split('=')[-1].strip()

    coo.set('headerShow', 'false')
    coo.set('SESSION_FLAG', '1')
    session.cookies.update(coo)
    if not check_login():
        t = threading.Thread(target=deal_sign_window, args=(sign_pwd,), daemon=True)
        t.start()
        access_token = None
        for _ in range(2):
            headers.update({"Host": host1.split('/')[-1], "Referer": host1})
            access_token = login()
            if access_token:
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续2次登陆失败，请重试")

    total_num1 = 0
    success1 = 0
    has_send1 = 0
    total_num2 = 0
    success2 = 0
    has_send2 = 0
    total_delete = 0
    delete_num2 = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))  # 打开excel表格
        sheets = excel.sheet_names()  # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])  # 获取sheet中的单元格
        ind = 1
        for i in range(table.nrows):
            if '医保耗材代码' in table.cell_value(i, 4).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):  # 遍历所有非空单元格
            if not table.cell_value(i, 4): continue
            total_num1 += 1
            prod_code = str(table.cell_value(i, 4)).strip()
            org_name = table.cell_value(i, 5).strip()
            if prod_code and org_name:
                try:
                    data = {"prodCode": prod_code, "orgName": org_name}
                    res = getTrnsDelvRltlListByScOrZx(data)
                    if res:
                        if res['delvRltlStas'] == '0':
                            if batchSubmitByIds(res):
                                success1 += 1
                                logger.info(f"配送关系提交成功，医用耗材代码：{prod_code}，配送企业：{org_name}")
                            else:
                                logger.error(f"配送关系提交失败，医用耗材代码：{prod_code}，配送企业：{org_name}")
                        else:
                            has_send1 += 1
                            logger.warning(f"配送关系已经设置过了，医用耗材代码：{prod_code}，配送企业：{org_name}")
                    else:
                        data = query_send_relation(data)
                        data = query_company_relation(data)
                        result = batchSaveTrnsDelvRltl(data)
                        if result == 0:
                            time.sleep(1)
                            res = getTrnsDelvRltlListByScOrZx(data)
                            if res:
                                if res['delvRltlStas'] == '0':
                                    if batchSubmitByIds(res):
                                        success1 += 1
                                        logger.info(f"配送关系设置成功，医用耗材代码：{prod_code}，配送企业：{org_name}")
                                    else:
                                        logger.error(f"配送关系设置失败，医用耗材代码：{prod_code}，配送企业：{org_name}")
                                else:
                                    has_send1 += 1
                                    logger.warning(f"配送关系已经设置过了，医用耗材代码：{prod_code}，配送企业：{org_name}")
                            else:
                                logger.error(f"配送关系设置失败，医用耗材代码：{prod_code}，配送企业：{org_name}")
                        else:
                            has_send1 += 1
                            logger.warning(f"配送关系已经设置过了，医用耗材代码：{prod_code}，配送企业：{org_name}")
                except:
                    logger.error(f"配送关系设置失败，医用耗材代码：{prod_code}，配送企业：{org_name}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：医用耗材代码：{prod_code}，配送企业：{org_name}")

        table = excel.sheet_by_name(sheets[1])  # 获取sheet中的单元格
        ind = 1
        for i in range(table.nrows):
            if '医保耗材代码' in table.cell_value(i, 4).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):  # 遍历所有非空单元格
            if not table.cell_value(i, 4): continue
            total_num2 += 1
            prod_code = str(table.cell_value(i, 4)).strip()
            org_name = table.cell_value(i, 5).strip()
            delventp_name = table.cell_value(i, 6).strip()
            is_send = table.cell_value(i, 7)
            if prod_code and org_name and delventp_name:
                try:
                    data = {"prodCode": prod_code, "orgName": org_name, "delventpName": delventp_name}
                    data = getSettingDelventpNewPage(data)
                    data = query_hospital(data)
                    data = getEntityNew(data)
                    if is_send and is_send.strip() and is_send.strip() == '是':
                        total_delete += 1
                        try:
                            if 'hospDelvId' in data:
                                trnsHospDelvdeleteById(data)
                                delete_num2 += 1
                                logger.info(f"删除配送成功，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                            else:
                                logger.warning(f"还未配送过，无法删除，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                        except:
                            logger.error(f"删除配送失败，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                    else:
                        result = setHospDelv(data)
                        if result == 0:
                            success2 += 1
                            logger.info(f"配送成功，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                        else:
                            has_send2 += 1
                            logger.warning(f"已经配送过了，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                except:
                    logger.error(f"配送失败，医用耗材代码：{prod_code}，医疗机构：{org_name}，配送企业：{delventp_name}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：医用耗材代码：{prod_code}，配送企业：{org_name}")

    logger.info(f"配送关系设置总数：{total_num1}，设置成功：{success1}，设置失败：{total_num1 - success1 - has_send1}，已经设置过：{has_send1}")
    logger.info(f"配送总数：{total_num2}，配送成功：{success2}，配送失败：{total_num2 - success2 - has_send2 - total_delete}，已经配送过：{has_send2}，删除成功：{delete_num2}，删除失败：{total_delete - delete_num2}")

except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
