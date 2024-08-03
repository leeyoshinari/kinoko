#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari

import time
import os
import sys
import logging.handlers
import urllib.parse
import json
import hashlib
import base64
import traceback
import requests
import xlrd
from requests_toolbelt import MultipartEncoder
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import ddddocr

retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 403, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.session()
headers = {'Host': 'yphcgl.ylbz.gansu.gov.cn', 'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'zh-CN,zh;q=0.9',
'Referer': 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/', 'Refreshtoken': '', 'X-Xsrf-Token': 'null', 'Authorization': '',
'Upgrade-Insecure-Requests': '1', 'Sec-Ch-Ua-Platform': 'Windows', 'Sec-Ch-Ua-Mobile': '?0', 'Connection': 'keep-alive',
'Sec-Ch-Ua': '"Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115"', 'Accept-Encoding': 'gzip, deflate, br',
'Origin': 'https://yphcgl.ylbz.gansu.gov.cn', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
'accountType': '', 'prodType': '2'}
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


def deal_excel():
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    datas = {}
    yijia = []
    excel = xlrd.open_workbook(os.path.join(current_path, file_names[0]))   # 打开excel表格
    sheets = excel.sheet_names()        # 获取excel中所有的sheet
    if len(sheets) != 3:
        logger.error(f"{file_names[0]} 表格中只有 {len(sheets)} 个 sheet 页。")
        raise Exception()
    table = excel.sheet_by_name(sheets[0])
    ind = 1
    for i in range(table.nrows):
        if '授权区县' == table.cell_value(i, 3).strip() and '申请公司名称' == table.cell_value(i, 8).strip():
            break
        else:
            ind += 1
    for i in range(ind, table.nrows):     # 遍历所有非空单元格
        if not table.cell_value(i, 8): continue
        shi = table.cell_value(i, 2).strip()
        xian = table.cell_value(i, 3).strip()
        xian = xian if xian else None
        org_name = table.cell_value(i, 8).strip()
        auth_time = str(table.cell_value(i, 5)).strip()
        auth_file = str(table.cell_value(i, 12)).strip()
        if shi and org_name and auth_time and auth_file:
            if org_name in datas:
                if shi in datas[org_name]['area'] and xian not in datas[org_name]['area'][shi]:
                    datas[org_name]['area'][shi].append(xian)
                else:
                    datas[org_name]['area'].update({shi: [xian]})
                datas[org_name]['auth_time'].append(auth_time)
                datas[org_name]['auth_file'].append(auth_file)
            else:
                datas.update({org_name: {'orgname': org_name, 'code': [], 'area': {shi: [xian]}, 'project_name': [],
                                         'auth_time': [auth_time], 'auth_file': [auth_file]}})
    for k, v in datas.items():
        a = list(set(v['auth_time']))
        b = list(set(v['auth_file']))
        if len(a) != 1:
            logger.error(f"Excel中授权时间不一致，当前授权时间有：{', '.join(a)}")
            raise
        if len(b) != 1:
            logger.error(f"Excel中授权文件名不一致，当前授权文件名有：{', '.join(b)}")
            raise
        datas[k]['auth_time'] = a[0]
        datas[k]['auth_file'] = b[0]
    table = excel.sheet_by_name(sheets[1])
    ind = 1
    for i in range(table.nrows):
        if '二渠道名称' == table.cell_value(i, 4).strip() and '产品编码' == table.cell_value(i, 5).strip():
            break
        else:
            ind += 1
    for i in range(ind, table.nrows):  # 遍历所有非空单元格
        if not table.cell_value(i, 5): continue
        org_name = table.cell_value(i, 4).strip()
        zu_code = str(table.cell_value(i, 5)).strip()
        project_name = table.cell_value(i, 7).strip()
        if zu_code and org_name and project_name:
            if org_name in datas:
                datas[org_name]['code'].append(zu_code)
                datas[org_name]['project_name'].append(project_name)
            else:
                logger.error(f'产品点选表格中的产品编码 和 区域点选表格中的配送企业 匹配不上，配送企业：{org_name}，产品编码：{zu_code}，项目名称：{project_name}')
    table = excel.sheet_by_name(sheets[2])
    ind = 1
    for i in range(table.nrows):
        if 'CODE编码' == table.cell_value(i, 0).strip() and '医疗机构' == table.cell_value(i, 1).strip():
            break
        else:
            ind += 1
    for i in range(ind, table.nrows):  # 遍历所有非空单元格
        if not table.cell_value(i, 0): continue
        org_name = table.cell_value(i, 1).strip()
        zu_code = table.cell_value(i, 0).strip()
        try:
            price = float(str(table.cell_value(i, 2)).strip())
        except ValueError:
            logger.error(f"Excel表格中的医院当前报价不正确，CODE编码：{zu_code}，医疗机构：{org_name}，当前报价：{table.cell_value(i, 2)}")
            raise
        if org_name and zu_code:
            yijia.append([zu_code, org_name, price])
    return datas, yijia


def get_code(t_):
    try:
        response = requests.get(f'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/comp/vcode/image/gen?codeSign={t_}&key={t_}&timestamp={t_}', headers=headers)
        if response.status_code == 200:
            res_data = json.loads(response.text)
            img_bytes = base64.b64decode(res_data['data'])
            ocr = ddddocr.DdddOcr(show_ad=False)
            return ocr.classification(img_bytes)
        else:
            raise Exception('获取验证码失败')
    except:
        logger.error(traceback.format_exc())


def login(username, password, code, t):
    try:
        data = {"loginId":username,"userPass":hash256(password),"vcode":code,"key":t}
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/auth/user/login'
        headers.update({'Content-Type': 'application/json;charset=UTF-8'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            response_json = json.loads(response.text)
            if response_json['code'] == 0:
                headers.update({'Authorization': response_json['data']['token']})
                headers.update({'Accounttype': ''})
                logger.info(f"登陆成功：{username} - {response_json['data']['orgName']}")
                return response_json['data']['token']
            else:
                logger.error(f"登陆失败：{response.text}")
                return None
        else:
            logger.error(f"登陆失败：{response.status_code}")
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def query_zu(zu_code: str, tenditmId) -> dict:
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/auth/delv/queryProdPage'
        data = {"prodCode":zu_code,"prodName":"","aprvno":"","aprvnoName":"","current":1,"size":10,"tenditmType":"2", "tenditmId":tenditmId}
        headers.update({'Content-Type': 'application/json;charset=UTF-8'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['data']['total'] == 1:
                return res_json['data']['records'][0]
            else:
                logger.error(f"查询产品编号为空或有多个，产品编号：{zu_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询产品编号失败，产品编号：{zu_code}，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def query_project_name(project_name: str):
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/item/list_select'
        data = {"itemname": project_name, "prodType": 2, "tenditmType": "2"}
        headers.update({'Content-Type': 'application/json;charset=UTF-8'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['data']) == 1:
                return res_json['data'][0]['value']
            else:
                logger.error(f"查询项目名称为空或有多个，项目名称：{project_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询项目名称失败，项目名称：{project_name}，状态码：{response.status_code}")
            raise
    except:
        logger.error(traceback.format_exc())
        raise


def upload_file(fileName: str) -> str:
    file_names = [n for n in os.listdir(current_path) if n.startswith(fileName)]
    if len(file_names) != 1:
        logger.error(f'共找到 {len(file_names)} 个本地授权文件，文件名：{fileName}')
        raise
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trade/comp/file/upload'
        data = MultipartEncoder(fields={"file": (file_names[0], open(file_names[0], 'rb'), "application/octet-stream")},
                                boundary='------WebKitFormBoundaryipWHtQRBbfBM7i0g')
        headers.update({'Content-Type': data.content_type})
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['data']['fileId']
        else:
            logger.error(f"授权文件上传失败，状态码：{response.status_code}，文件名：{file_names[0]}")
            raise
    except:
        logger.error(f"授权文件上传失败，文件名：{file_names[0]}")
        raise


def query_org(orgName: str, res: dict):
    # 查询企业
    try:
        url = f'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/puragreement/query_delv_org?entpName={urllib.parse.quote(orgName)}&current=1&size=10&tenditmType=2&timestamp={int(time.time() * 1000)}'
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            orgs = res_json['data']
            if len(orgs) == 0:
                logger.error(f'未查询到配送企业：{orgName}')
                raise
            if len(orgs) == 1:
                if orgName in orgs[0]['orgName']:
                    res.update({"delvOrgInfoList": [{"orgName": orgs[0]['orgName'], "orgCode": orgs[0]['entpCode']}]})
                    return res
                else:
                    logger.error(f'未查询到配送企业：{orgName}，查询结果：{orgs}')
                    raise
            if len(orgs) > 1:
                pass
        else:
            logger.error(f'查询配送企业失败：{orgName}，状态码：{response.status_code}')
            raise
    except:
        raise


def query_areas(area:dict, res:dict):
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/puragreement/query_admdvs'
        data = {"tenditmType":"2"}
        area_list = []
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            citys = res_json['data']['citys']
            for k, v in area.items():
                for c in citys:
                    if k == c['admdvsName']:
                        if len(c['citys']) == 0:
                            area_list.append(c)
                        for b in v:
                            for d in c['citys']:
                                if d['admdvsName'] == b:
                                    area_list.append(d)
                                    break
            res.update({"delvAreaList": area_list})
            return res
        else:
            logger.error(f"查询配送地区失败，状态码：{response.status_code}")
            raise
    except:
        raise


def submit(res: dict):
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/auth/delv/submitAgreement'
        res.update({'tenditmType':'2'})
        response = session.post(url, json=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"提交失败：配送企业：{res['delvOrgInfoList'][0]['orgName']}，响应值：{response.text}")
                raise
        else:
            logger.error(f"提交失败：配送企业：{res['delvOrgInfoList'][0]['orgName']}，状态码：{response.status_code}")
            raise
    except:
        logger.error(f"提交失败：配送企业：{res['delvOrgInfoList'][0]['orgName']}")
        raise


def query_history(orgName: str, res: dict):
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/basesys/queryord'
        data = {"orgTypeCode":"2","orgName":orgName,"tenditmType":"2"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            orgs = res_json['data']
            if len(orgs) == 1:
                if orgName in orgs[0]['orgName']:
                    res.update({"medinsCode": orgs[0]['entpCode']})
                    res.update({"orgName": orgs[0]['orgName']})
                    return res
                else:
                    logger.error(f'议价：未查询到医疗机构：{orgName}，查询结果：{orgs}')
                    raise
            else:
                logger.error(f'议价：未查询到医疗机构 或 查询到多个医疗机构：{orgName}，响应值：{response.text}')
                raise
        else:
            logger.error(f'议价：查询医疗机构失败：{orgName}，状态码：{response.status_code}')
            raise
    except:
        raise


def query_code_list(sn: str, origin_price: float, res: dict):
    try:
        sta = ['', '', '待医疗机构确认', '双方达成一致', '作废', '待配送企业确认', '待生产企业确认']
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/nego_prc/mcs/delv/query'
        data = {"negoPricStas":"","prodName":"","regno":"","regcert":"","dosform":"","prodSpec":"","prodentpCode":"","dclaEntpCode":"","itemname":"","current":1,"size":10,"tenditmType":"2"}
        data.update({'sn': sn})
        data.update(res)
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            records = res_json['data']['records']
            if len(records) == 1:
                if records[0]['negoPricStas'] == '6':
                    online_price = float(records[0]['hospNegoPric'])
                    if origin_price != online_price:
                        logger.error(f"医院当前报价不相等，CODE编码：{sn}，医疗机构：{res['orgName']}，Excel中的报价：{origin_price}，页面上的报价：{online_price}")
                        raise
                    res.update({"negoPricId": records[0]['negoPricId']})
                    res.update({"sn": records[0]['sn']})
                    res.update({"medinsName": records[0]['medinsName']})
                    return res
                else:
                    logger.warning(f"当前议价状态是 {sta[int(records[0]['negoPricStas'])]}，CODE编码：{sn}，医疗机构：{res['orgName']}")
                    raise
            else:
                logger.error(f"议价管理列表结果为空或有多条数据，CODE编码：{sn}，医疗机构：{res['orgName']}，数据条数：{len(records)}")
                raise
        else:
            logger.error(f"查询议价管理列表失败，CODE编码：{sn}，医疗机构：{res['orgName']}")
            raise
    except:
        raise


def accept(res: dict):
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/nego_prc/delv/accept'
        data = {"negoPricId":res['negoPricId'], "tenditmType":"2"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['success']:
                logger.info(f"同意议价成功：CODE编码：{res['sn']}，医疗机构：{res['orgName']}")
            else:
                logger.error(f"同意议价失败：CODE编码：{res['sn']}，医疗机构：{res['orgName']}，响应值：{response.text}")
        else:
            logger.error(f"同意议价失败：CODE编码：{res['sn']}，医疗机构：{res['orgName']}，状态码：{response.status_code}")
    except:
        logger.error(f"同意议价失败：CODE编码：{res['sn']}，医疗机构：{res['orgName']}")
        raise


def hash256(data: str):
    hash_obj = hashlib.sha256()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def re_login():
    ctoken = None
    for _ in range(3):
        t_ = int(time.time() * 1000)
        code = get_code(t_)
        logger.info(f'验证码识别结果：{code}')
        ctoken = login(username, password, code, t_)
        if ctoken:
            with open(os.path.join(current_path, 'token.txt'), 'w', encoding='utf-8') as f:
                f.write(ctoken)
            headers.update({'Authorization': ctoken})
            break
        time.sleep(1)
    if not ctoken:
        raise Exception("连续3次登陆失败，请重试")


def check_login():
    try:
        url = 'https://yphcgl.ylbz.gansu.gov.cn/tps-local/web/trans/basesys/queryord'
        data = {"orgTypeCode":"2","orgName":'',"tenditmType":"2"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] != 0 and '重新登录' in res_json['message']:
                logger.info(res_json['message'])
                re_login()
                return False
            else:
                return True
        else:
            re_login()
            return False
    except:
        raise

try:
    # 读取用户名和密码
    username = ''
    password = ''
    aaa = 2
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()

    # 登陆系统，获取token
    access_token = None
    datas, yijia = deal_excel()
    for k, v in datas.items():
        tota = 0
        for kk, vv in v['area'].items():
            tota += len(vv)
        logger.info(f"{k} 共配送 {len(v['area'])} 个市，{tota} 个区县，配送产品编号 {len(v['code'])} 个，授权时间：{v['auth_time']}，授权文件名：{v['auth_file']}")
    logger.info(f"共有 {len(yijia)} 个待议价的数据")
    token_path = os.path.join(current_path, 'token.txt')
    if os.path.exists(token_path):
        with open(token_path, 'r', encoding='utf-8') as f:
            access_token = f.read().strip()
        headers.update({'Authorization': access_token})
    else:
        re_login()

    for i in range(3):
        if check_login():
            break
        time.sleep(2)

    for k, v in datas.items():
        try:
            if len(v['code']) > 0:
                res = {}
                res = query_org(k, res)
                res = query_areas(v['area'], res)
                res.update({"authFileId": upload_file(v['auth_file'])})
                res.update({"authEndTime": v['auth_time'].replace('年', '-').replace('月', '-').replace('日', '').replace('号', '') + ' 00:00:00'})
                pubonlnProdList = []
                for c, p in zip(v['code'], v['project_name']):
                    try:
                        project_name_id = query_project_name(p)
                        pubonlnProdList.append(query_zu(c, project_name_id))
                        logger.info(f"产品编号添加成功，配送企业：{k}，产品编码：{c}，项目名称：{p}")
                        time.sleep(1)
                    except:
                        logger.error(f"产品编号添加失败，配送企业：{k}，产品编码：{c}，项目名称：{p}")
                res.update({"pubonlnProdList": pubonlnProdList})
                submit(res)
                logger.info(f"提交成功，配送企业：{k}，共配送 {len(res['delvAreaList'])} 个地区，共配送成功 {len(res['pubonlnProdList'])} 个产品编号，失败 {len(v['code']) - len(res['pubonlnProdList'])} 个产品编号")
            else:
                logger.error(f"{k} 共有配送产品编号 {len(v['code'])} 个")
        except:
            logger.error(f"失败：配送企业：{k}，授权期限：{v['auth_time']}，授权文件名：{v['auth_file']}，配送区域：{v['area']}")
            logger.error(traceback.format_exc())

    for cc in yijia:
        try:
            res = {}
            res = query_history(cc[1], res)
            res = query_code_list(cc[0], cc[2], res)
            accept(res)
        except:
            logger.error(traceback.format_exc())
        time.sleep(1)
except:
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
