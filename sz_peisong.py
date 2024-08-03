#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import sys
import json
import time
import base64
import threading
import traceback
import logging.handlers
import requests.packages.urllib3
import requests.cookies
import requests
import hashlib
import ddddocr
import win32gui
import win32con
import xlrd
from pywinauto import Application, Desktop
from websocket import create_connection
from websocket._exceptions import WebSocketBadStatusException
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://yyhc.szggzy.com:9000'   # 登陆host
host2 = 'https://yyhc.szggzy.com:9000'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
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
window_title = '密码输入对话框'
button_title = '确定'
request_id = 1
request_origin = "45B45638-A006-4cf1-A298-816B376D867E"
certCode = ''


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


def query_company(company, agreement_type, res: dict):
    headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
    headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
    headers.update({'Sec-Fetch-Site': 'same-origin'})
    headers.update({'Sec-Fetch-Dest': 'empty'})
    headers.update({'Sec-Fetch-Mode': 'cors'})
    try:
        url = f'{host2}/hctrade/suppurDistributionRelation/getCompanyTbGoodsList.html'
        data = {'_search': False, 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'isNeedReAgree': None,
                'companyNameTb': None, 'areaId': None,'companyNamePs': company, 'confirmStatusSc': None,
                'confirmStatusPs': None, 'agreementStatus': None, 'agreementType': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) > 0:
                agreetype = [str(agre['agreementType']) for agre in res_json['rows']]
                if agreement_type in agreetype:
                    agree_index = agreetype.index(agreement_type)
                else:
                    logger.error(f"配送协议类型不正确，配送企业：{company}")
                    raise
                if res_json['rows'][agree_index]['confirmStatusSc'] == 1 and res_json['rows'][agree_index]['confirmStatusPs'] == 1:
                    res.update({"agreementId": res_json['rows'][agree_index]['agreementId']})
                    # res.update({"agreementType": res_json['rows'][agree_index]['agreementType']})
                    company_dict.update({calc_md5(company + agreement_type): res_json['rows'][agree_index]['agreementId']})
                    return res
                else:
                    logger.error(f"配送协议签定状态不一致，生产企业签定状态：{['待签定','已签定'][res_json['rows'][agree_index]['confirmStatusSc']]}，配送企业签定状态：{['待签定','','已签定','已拒绝'][res_json['rows'][agree_index]['confirmStatusPs']]}，配送企业：{company}")
                    raise
            else:
                logger.error(f"配送协议查询为空，配送企业：{company}，响应值：{response.text}")
                raise
        else:
            logger.error(f"配送协议查询失败，企业名称：{company}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_hospital(hospital, res: dict):
    try:
        url = f'{host2}/hctrade/suppurDistributionRelation/getStdHospitalData.html?companyIdPs='
        data = {"rows": 1000, "page": 1, "hospitalAddress": None, "hospitalName": hospital}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) > 0:
                hospitals = [hos['hospitalName'] for hos in res_json['rows']]
                if hospital in hospitals:
                    res.update({'hospitalIds': res_json['rows'][hospitals.index(hospital)]['hospitalId']})
                    return res
                else:
                    logger.error(f"医疗机构名字不匹配，医疗机构：{hospital}，查询到的医疗机构：{','.join(hospitals)}")
                    raise
            else:
                logger.error(f"医疗机构查询为空，医疗机构：{hospital}，响应值：{response.text}")
                raise
        else:
            logger.error(f"医疗机构查询失败，企业名称：{hospital}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_code(ms_code, agreement_type, agreement_id, res: dict):
    try:
        url = f"{host2}/hctrade/suppurDistributionRelation/getGoodsListData.html"
        data = {'_search': False, 'rows': 20, 'page': 1, 'sidx': None, 'sord': 'asc', 'agreementType': agreement_type,
                'procurecatalogId': ms_code, 'regCode': None, 'goodsName': None, 'agreementId': agreement_id}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) == 1:
                res.update({"procurecatalogIds": res_json['rows'][0]['procurecatalogId']})
                return res
            else:
                if res_json['code'] != 0:
                    logger.error(f"产品代码查询结果为空，产品代码：{ms_code}，查询结果：{response.text}")
                else:
                    logger.error(f"产品代码查询结果为空或有多个，产品代码：{ms_code}，查询结果：{res_json['rows']}")
                raise
        else:
            logger.error(f"产品代码查询查询失败，产品代码：{ms_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def upload_file(file_name: str) -> str:
    fileName = file_name + '.pdf'
    file_path = os.path.join(auth_file_path, fileName)
    if not os.path.exists(file_path):
        logger.error(f'授权文件不存在，文件名：{fileName}')
        raise
    try:
        global request_id
        request_data = json.dumps({"requestVersion": 1, "requestOrigin": request_origin, "requestId": request_id, "requestQuery": {"function": "GetCertStringAttribute", "param": {"cert": {"encode": None, "type": "{\"UIFlag\":\"default\", \"InValidity\":true,\"Type\":\"signature\", \"Method\":\"device\",\"Value\":\"any\"}","condition": "IssuerCN~'NETCA' && InValidity='True' && CertType='Signature'"},"id": -1}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        certCode = res_json['responseEntity']['certCode']
        with open(file_path, 'rb') as f:
            pdf_base64 = base64.b64encode(f.read()).decode('utf-8')
        request_data = json.dumps({"requestVersion": 1, "requestOrigin": request_origin, "requestId": request_id, "requestQuery": {"function": "Custom_PdfSignAndUploadByBytes", "param": {"signPdfBytes": pdf_base64, "certEncode": certCode,"pageNum":-1,"x":150,"y":150,"uploadPdfUrl":f"{host1}/hctrade/RecvFile.servlet"}}})
        ws.send(request_data)
        response = ws.recv()
        request_id += 1
        res_json = json.loads(response)
        if res_json['responseResult']['msg'] != "成功":
            logger.error(f"CA签章失败")
            raise
        destFileEncode = res_json['responseEntity']['UploadFileRespon']
        auth_file_url.update({calc_md5(file_name): destFileEncode})
        return destFileEncode
    except:
        logger.error(f"授权文件上传失败，文件名：{file_name}")
        raise


def submit_c(res: dict):
    try:
        headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        url = f'{host2}/hctrade/suppurDistributionRelation/addDistributionRelationBid.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success'] or res_json['code'] != 0:
                if '已经存在产品配送关系' not in res_json['msg']:
                    logger.error(f"确定并添加失败，响应值：{response.text}")
                    raise Exception(res_json['msg'])
        else:
            logger.error(f"确定并添加失败，状态码：{response.status_code}")
            raise
    except:
        raise


def submit_finally(rela_id, good_id):
    try:
        url = f'{host2}/hctrade/suppurDistributionRelationBid/updateDistributionRelationBid.html'
        rr = {'dataList':json.dumps([{'id': rela_id, 'procurecatalogId': good_id}], ensure_ascii=False), 'confirmStatus': 1}
        response = session.post(url, data=rr, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success'] or res_json['code'] != 0:
                logger.error(f"配送关系提交失败，响应值：{response.text}")
                raise Exception(res_json['msg'])
        else:
            logger.error(f"配送关系提交失败，状态码：{response.status_code}")
            raise
    except:
        raise


def query_submit_list(goods_id, agreement_id, company, hospital):
    headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
    headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
    headers.update({'Sec-Fetch-Site': 'same-origin'})
    headers.update({'Sec-Fetch-Dest': 'empty'})
    headers.update({'Sec-Fetch-Mode': 'cors'})
    try:
        url = f'{host2}/hctrade/suppurDistributionRelationBid/getDistributionRelationBidData.html?agreementId={agreement_id}'
        data = {'_search': False, 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'hospitalName': hospital, 'procurecatalogId': goods_id, 'goodsName': None, 'confirmStatus': None,
                'startTime': None, 'endTime': None, 'regCode': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and len(res_json['rows']) == 1:
                if res_json['rows'][0]['confirmStatus'] == 0:
                    return res_json['rows'][0]['id']
                else:
                    return res_json['rows'][0]['confirmStatus']
            else:
                all_data = [d for d in res_json['rows'] if d['confirmStatus'] != 4]
                if len(all_data) == 1:
                    if all_data[0]['confirmStatus'] == 0:
                        return all_data[0]['id']
                    else:
                        return all_data[0]['confirmStatus']
                else:
                    logger.error(f"配送关系查询结果为空或有多个，产品代码：{goods_id}，配送企业：{company}，响应值：{res_json['rows']}")
                    raise
        else:
            logger.error(f"配送关系查询失败，产品代码：{goods_id}，配送企业：{company}，状态码：{response.status_code}")
            raise
    except:
        raise


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


def check_login():
    try:
        if os.path.exists(cookie_path):
            return False
            # cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
            # coo = requests.cookies.RequestsCookieJar()
            # for k, v in cookies_dict.items():
            #     coo.set(k, v)
            # session.cookies.update(coo)
            # headers.update({'Host': host2.split('/')[-1]})
            # url = f'{host2}/hctrade/index.html'
            # response = session.get(url, headers=headers)
            # if response.status_code == 200:
            #     user_infos = re.findall('<p>(.*?)</p>', response.text)
            #     if len(user_infos) == 1:
            #         logger.info(f"免登陆成功，用户：{user_infos[0]}")
            #         return True
            #     else:
            #         return False
            # else:
            #     return False
        else:
            return False
    except:
        logger.error(traceback.format_exc())
        return False


try:
    username = ''
    password = ''
    sign_pwd = '12345678'
    socket_port = 10443
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()
            if 'sign_pwd' in lin:
                sign_pwd = lin.split('=')[-1].strip()
            if 'socket_port' in lin:
                socket_port = lin.split('=')[-1].strip()

    if not check_login():
        # coo = requests.cookies.RequestsCookieJar()
        # session.cookies = coo
        access_token = None
        for _ in range(3):
            headers.update({"Host": host1.split('/')[-1]}) #, "Referer": host1})
            access_token = login(username, password)
            if access_token:
                headers = {'Host': host2.split('/')[-1], 'Sec-Fetch-User': '?1', 'Sec-Fetch-Site': 'none', 'Sec-Fetch-Mode': 'navigate', 'Upgrade-Insecure-Requests': '1', 'Sec-Fetch-Dest': 'document', 'Sec-Ch-Ua-Mobile': '?0', 'Cache-Control': 'max-age=0', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36', 'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"', 'Accept-Language': 'zh-CN,zh;q=0.9', 'sec-ch-ua-platform': '"Windows"', 'Accept-Encoding': 'gzip, deflate, br, zstd', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'}
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续3次登陆失败，请重试")

    try:
        ws = create_connection(f'wss://127.0.0.1:{socket_port}', subprotocols=['crypto-jsonrpc-protocol'])
    except (WebSocketBadStatusException, TimeoutError):
        logger.error(traceback.format_exc())
        raise Exception('无法连接 CA，请正确插入CA证书')

    t = threading.Thread(target=deal_sign_window, args=(sign_pwd,), daemon=True)
    t.start()
    total_num = 0
    success = 0
    has_send = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xlsx')] + [n for n in os.listdir(current_path) if n.endswith('.xls')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))
        sheets = excel.sheet_names()
        table = excel.sheet_by_name(sheets[0])
        ind = 1
        for i in range(table.nrows):
            if '交易产品代码' in table.cell_value(i, 7):
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):
            if not table.cell_value(i, 7): continue
            total_num += 1
            try:
                ms_code = table.cell_value(i, 7).strip()
            except:
                ms_code = str(int(table.cell_value(i, 7)))
            auth_file = table.cell_value(i, 1).strip()
            company = table.cell_value(i, 3).strip()
            hospital = table.cell_value(i, 4).strip()
            is_jicai = table.cell_value(i, 6).strip()
            if ms_code and auth_file and company and hospital and is_jicai:
                try:
                    if is_jicai == '限价协议':
                        agreementType = '5'
                    elif is_jicai == '备选协议':
                        agreementType = '1'
                    elif is_jicai == '肝功生化试剂联盟集采':
                        agreementType = '23'
                    else:
                        raise Exception('协议类型不正确，仅支持 限价协议、备选协议 和 肝功生化试剂联盟集采')
                    res = {}
                    company = company.replace(' ', '')
                    company_md5 = calc_md5(company + agreementType)
                    if company_md5 in company_dict:
                        res.update({'agreementId': company_dict[company_md5]})
                    else:
                        res = query_company(company, agreementType, res)
                    res = query_hospital(hospital, res)
                    res = query_code(ms_code, agreementType, res["agreementId"], res)
                    if agreementType == '23':
                        auth_md5 = calc_md5(auth_file)
                        if auth_md5 in auth_file_url:
                            res.update({'authorUrl': auth_file_url[auth_md5]})
                        else:
                            res.update({'authorUrl': upload_file(auth_file)})
                    submit_c(res)
                    time.sleep(2)
                    relation_id = query_submit_list(ms_code, res['agreementId'], company, hospital)
                    if relation_id:
                        if relation_id in [1, 2, 3, 4, 5, 6]:
                            has_send += 1
                            if relation_id in [1, 2]:
                                logger.warning(f"已经配送过了，配送关系的状态为：{['', '已提交待配送方确认', '双方同意'][relation_id]}，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                            else:
                                logger.warning(f"配送关系的状态为：{['待提交', '已提交待配送方确认', '双方同意', '配送方拒绝', '已撤废', '启用待确定', '撤废待确定'][relation_id]}，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                            continue
                        submit_finally(relation_id, ms_code)
                        success += 1
                        logger.info(f"配送成功，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                    else:
                        logger.error(f"配送关系状态不正确，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"配送失败，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
            else:
                logger.error(f"Excel表格中的数据不全，产品代码：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num - success - has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
