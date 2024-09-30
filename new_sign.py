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
from websocket import create_connection
from websocket._exceptions import WebSocketBadStatusException
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://igi.hsa.gd.gov.cn'   # 登陆host
host2 = 'https://igi.hsa.gd.gov.cn'  # 配送 host
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
window_title = '密码输入对话框'
button_title = '确定'
request_id = 1
request_origin = "45B45638-A006-4cf1-A298-816B376D867E"
certCode = ''
sealImageBase64 = ''
pos_data = {"yp_point":{"1":{"xPos":-180,"yPos":550},"2":{"xPos":200,"yPos":550},"4":{"xPos":-50,"yPos":550},"7":{"xPos":500,"yPos":600},"pageNum":8},"hc_point":{"1":{"xPos":240,"yPos":470},"2":{"xPos":500,"yPos":470},"4":{"xPos":240,"yPos":585},"7":{"xPos":500,"yPos":470},"pageNum":6},"ht_point":{"1":{"xPos":130,"yPos":550},"2":{"xPos":350,"yPos":550},"4":{"xPos":240,"yPos":550},"pageNum":3},"hcht_point":{"1":{"xPos":130,"yPos":720},"2":{"xPos":350,"yPos":720},"4":{"xPos":240,"yPos":720},"pageNum":4}}


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


def query_protocol_list(ms_code, res: dict):
    try:
        url = f'{host2}/tps_local_bd/web/mcstrans/ttpCntrSummary/prodentp/query_page'
        data = {"cntrStas": "", "current": 1, "medinsCode": "", "itemName": "", "prodName": "", "prodCode": "",
                "prodType": "2", "size": 10, "tenditmType": "1", "ttpCntrCode": ms_code, "isComb": "0"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data'] and len(res_json['data']['records']) == 1:
                res.update({"fileId": res_json['data']['records'][0]['fileId']})
                res.update({"cntrId": res_json['data']['records'][0]['cntrId']})
                return res
            elif res_json['code'] == 0 and res_json['data']['total'] > 1:
                logger.error(f"交易协议列表查询到多个，协议编号：{ms_code}，查询结果：{res_json['data']['records']}")
                raise
            else:
                logger.error(f"交易协议列表查询为空，协议编号：{ms_code}，响应值：{response.text}")
                raise
        else:
            logger.error(f"交易协议列表查询失败，协议编号：{ms_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def download_file(file_id):
    try:
        url = f"{host2}/tps_local_bd/web/mcstrade/comp/file/downBase64?fileId={file_id}"
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['data']:
                return res_json['data']
            else:
                logger.error(f"PDF文件下载失败，文件Id：{file_id}，查询结果：{res_json}")
                raise
        else:
            logger.error(f"PDF文件下载失败，文件Id：{file_id}，状态码：{response.status_code}")
            raise
    except:
        raise


def sign_name(pdf_base64):
    try:
        global request_id
        request_data = json.dumps({"requestVersion":1,"requestOrigin":request_origin,"requestId":request_id,"requestQuery":{"appName":"SignatureCreator","function":"SignatureCreatorSignSealEx","param":{"srcFile":"","srcBytes":pdf_base64,"destFile":"","certEncode":certCode,"selMode":1,"signFieldText":"","sealImageEncode":sealImageBase64,"revInfoIncludeFlag":False,"SealKeyWord":{"keyWord":"配送企业签章","startPage":1,"endPage":-1,"keyWordIndex":1,"width":100,"height":100,"offsetX":0,"offsetY":55},"Tsa":{"tsaUrl":"","tsaUsr":"","tsaPwd":"","tsaHashAlgo":""}}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        if res_json['responseResult']['msg'] != "成功":
            logger.error(f"CA签章失败")
            raise
        destFileEncode = res_json['responseEntity']['destFileEncode']
        # destFileId = res_json['responseEntity']['id']
        return destFileEncode
    except:
        raise


def update_sign_status(res: dict, pdfBase64):
    try:
        url = f'{host2}/tps_local_bd/web/mcstrans/ttpCntrSummary/update_sign_status'
        data = {"fileId": res['fileId'], "orgType": 4, "caType": "1", "cntrId": res['cntrId'], "pdfBase64": urllib.parse.quote_plus(pdfBase64)}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0 and not res_json['success']:
                logger.error(f"签章失败，响应值：{response.text}")
                raise
    except:
        raise


def batch_audit_not_pass(res: dict, reason_text):
    try:
        url = f'{host2}/tps_local_bd/web/mcstrans/ttpCntrSummary/batch_audit_not_pass'
        data = {"refusedReason": reason_text, "cntrId": res['cntrId'], "orgType": 4}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0 and not res_json['success']:
                logger.error(f"签章失败，响应值：{response.text}")
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
                window.child_window(class_name='Edit', top_level_only=False, found_index=1).type_keys(pwd)
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
            time.sleep(0.8)


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
    sign_pwd = '12345678'
    socket_port = 10443
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()
            if 'company' in lin:
                origin_org_name = lin.split('=')[-1].strip()
            if 'sign_pwd' in lin:
                sign_pwd = lin.split('=')[-1].strip()
            if 'socket_port' in lin:
                socket_port = lin.split('=')[-1].strip()

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

    try:
        ws = create_connection(f'wss://127.0.0.1:{socket_port}', subprotocols=['crypto-jsonrpc-protocol'])
        request_data = json.dumps({"requestVersion":1,"requestOrigin":request_origin,"requestId":request_id,"requestQuery":{"function":"GetCertStringAttribute","param":{"cert":{"encode":None,"type":"{\"UIFlag\":\"default\", \"InValidity\":true,\"Type\":\"signature\", \"Method\":\"device\",\"Value\":\"any\"}","condition":"IssuerCN~'NETCA' && InValidity='True' && CertType='Signature'"},"id":-1}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        certCode = res_json['responseEntity']['certCode']
        request_data = json.dumps({"requestVersion":1,"requestOrigin":request_origin,"requestId":request_id,"requestQuery":{"function":"GetNetcaSealImage","param":{"cert":{"encode":certCode}}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        sealImageBase64 = res_json['responseEntity']['sealImageBase64']
        request_data = json.dumps({"requestVersion": 1, "requestOrigin": request_origin, "requestId": request_id, "requestQuery": {"function": "ClearPwdCache", "param": {}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        if res_json['responseResult']['msg'] != "成功":
            logger.info(f"清除密码缓存失败，ClearPwdCache，{res_json['responseResult']['msg']}")
            # raise Exception(f"清除密码缓存失败，ClearPwdCache")
    except (WebSocketBadStatusException, TimeoutError):
        logger.error(traceback.format_exc())
        raise Exception('无法连接 CA，请正确插入CA证书')

    t = threading.Thread(target=deal_sign_window, args=(sign_pwd,), daemon=True)
    t.start()
    total_num = 0
    success = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xlsx')] + [n for n in os.listdir(current_path) if n.endswith('.xls')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '协议编号' == table.cell_value(i, 1):
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
            is_sign = table.cell_value(i, 2).strip()
            if ms_code and is_sign:
                try:
                    time.sleep(1)
                    res = {}
                    res = query_protocol_list(ms_code, res)
                    if is_sign != '签章':
                        batch_audit_not_pass(res, is_sign)
                        success += 1
                        logger.info(f"拒绝成功，协议编号：{ms_code}，合同执行：{is_sign}")
                        continue
                    pdf_bs64 = download_file(res['fileId'])
                    fileEncode = sign_name(pdf_bs64)
                    update_sign_status(res, fileEncode)
                    success += 1
                    logger.info(f"签章成功，协议编号：{ms_code}，合同执行：{is_sign}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"签章失败，协议编号：{ms_code}，合同执行：{is_sign}")
            else:
                logger.error(f"Excel表格中的数据不全，协议编号：{ms_code}，合同执行：{is_sign}")
    logger.info(f"总数：{total_num}，签章成功：{success}，签章失败：{total_num - success}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
