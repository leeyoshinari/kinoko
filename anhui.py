#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari
import time
import os
import sys
import logging.handlers
import urllib.parse
import json
import base64
import traceback
import requests
import ddddocr
import xlrd

session = requests.session()
headers = {'Host': 'sjsb.ahyycg.cn', 'Accept': 'application/json, text/plain, */*', 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
'Referer': 'http://sjsb.ahyycg.cn/', 'from': 'Y',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58'}
#session.verify = False

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


def get_code(t_):
    try:
        response = requests.get(f'http://sjsb.ahyycg.cn/code/code?codeSign={t_}&randomStr={t_}&timestamp={t_}', headers=headers)
        if response.status_code == 200:
            res_data = json.loads(response.text)
            bs64_text = res_data['data'].split('base64,')[-1]
            img_bytes = base64.b64decode(bs64_text)
            ocr = ddddocr.DdddOcr(show_ad=False)
            return ocr.classification(img_bytes)
        else:
            raise Exception('获取验证码失败')
    except:
        logger.error(traceback.format_exc())

def login(username, password, code, t):
    try:
        # c_ = int(time.time() * 1000)
        # url = f'http://sjsb.ahyycg.cn/code/upms/login/check/username?username={username}&timestamp={c_}'
        # _ = session.get(url, headers=headers)
        url = f'http://sjsb.ahyycg.cn/code/auth/oauth/token?username={username}&password={urllib.parse.quote(password)}&code={code}&randomStr={t}&grant_type=password&scope=server'
        headers.update({'Authorization': 'Basic aHhtZWM6aHhtZWM='})
        headers.update({'Origin': 'http://sjsb.ahyycg.cn'})
        response = session.post(url, headers=headers)
        if response.status_code == 200:
            response_json = json.loads(response.text)
            if response_json['code'] == 0:
                refresh_token = response_json['data']['refresh_token']
                url = f'http://sjsb.ahyycg.cn/code/auth/oauth/token?grant_type=refresh_token&scope=server&refresh_token={refresh_token}'
                response = session.post(url, headers=headers)
                if response.status_code == 200:
                    response_json = json.loads(response.text)
                    access_token = response_json['data']['access_token']
                    logger.info("登陆成功")
                    return access_token
                else:
                    logger.error(f"获取access_token失败：{response.status_code}")
                    return None
            else:
                logger.error(f"登陆失败：{response.text}")
                return None
        else:
            logger.error(f"登陆失败：{response.status_code}")
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def query_type(access_token: str, mcsCode: str, res: dict):
    # 根据流水号查询
    try:
        url = 'http://sjsb.ahyycg.cn/code/hsaReagent/tps-local/web/trans/prodDelv/mcs/queryPubonlnPage'
        data = {"mcsCode":mcsCode,"mcsName":"","mcsRegcertName":"","mcsRegno":"","reagentType":"","reagentTypeName":"","mcsTypeLv2Name":"","prodentpName":"","mcsSpec":"","listAttrCode":"","tab1":"0","current":1,"size":10,"tenditmType":"3"}
        headers.update({'Content-Type': 'application/json;charset=UTF-8'})
        headers.update({'Authorization': f'Bearer {access_token}'})
        headers.update({'prodType': '3'})
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            records = res_json['data']['records'][0]
            res.update({'prodCode': records['mcsCode']})
            res.update({'tenditmId': records['tenditmId']})
            return res
        else:
            logger.error(f"根据流水号查询失败，流水号：{mcsCode}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_hospital(orgName: str, res: dict):
    # 查询医院
    try:
        url = 'http://sjsb.ahyycg.cn/code/hsaReagent/tps-local/web/trans/basesys/queryord'
        data = {"orgTypeCode":"2","orgName":orgName,"tenditmType":"3"}
        response = session.post(url, json=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            orgs = res_json['data']
            if len(orgs) == 0:
                logger.error(f'未查询到医院：{orgName}')
                raise
            if len(orgs) == 1:
                if orgName in orgs[0]['orgName']:
                    res.update({'medinsInfos': [{'orgCode': orgs[0]['entpCode'], 'orgName': orgs[0]['orgName']}]})
                    return res
                else:
                    logger.error(f'未查询到医院：{orgName}，{orgs}')
                    raise
            if len(orgs) > 1:
                for o in orgs:
                    if orgName == o['orgName']:
                        res.update({'medinsInfos': [{'orgCode': o['entpCode'], 'orgName': o['orgName']}]})
                        return res
                logger.error(f'未查询到医院：{orgName}，{orgs}')
                raise
    except:
        raise

def query_org(orgName: str, res: dict):
    # 查询企业
    try:
        url = 'http://sjsb.ahyycg.cn/code/hsaReagent/tps-local/web/trans/basesys/queryord'
        data = {"orgTypeCode":"4","orgName":orgName,"tenditmType":"3"}
        response = session.post(url, json=data, headers=headers)
        res_json = json.loads(response.text)
        orgs = res_json['data']
        if len(orgs) == 0:
            logger.error(f'未查询到配送企业：{orgName}')
            raise
        if len(orgs) == 1:
            if orgName in orgs[0]['orgName']:
                res.update({'delventpCode': orgs[0]['entpCode']})
                res.update({'delventpName': orgs[0]['orgName']})
                return res
            else:
                logger.error(f'未查询到配送企业：{orgName}，{orgs}')
                raise
        if len(orgs) > 1:
            pass
    except:
        raise


def addProdDelv(res: dict):
    # 添加配送关系
    try:
        url = 'http://sjsb.ahyycg.cn/code/hsaReagent/tps-local/web/trans/prodDelv/addProdDelv'
        res.update({'tenditmType':'3'})
        res.update({'cityCode': ''})
        response = session.post(url, json=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['code']
        else:
            logger.error(f"配送失败：{response.text}")
            return -1
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
            if 'aaa' in lin:
                aaa = int(lin.split('=')[-1].strip()) - 1

    # 登陆系统，获取token
    access_token = None
    for _ in range(3):
        t_ = int(time.time() * 1000)
        code = get_code(t_)
        logger.info(f'验证码识别结果：{code}')
        access_token = login(username, password, code, t_)
        if access_token:
            break
        time.sleep(1)
    if not access_token:
        raise Exception("连续3次登陆失败，请重试")

    total_num = 0
    success = 0
    has_send = 0
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))   # 打开excel表格
        sheets = excel.sheet_names()        # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])      # 获取sheet中的单元格
        ind = 1
        for i in range(table.nrows):
            if '流水号' == table.cell_value(i, 5).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):     # 遍历所有非空单元格
            if not table.cell_value(i, 5): continue
            #if total_num > aaa: continue
            total_num += 1
            try:
                mcs_code = str(int(table.cell_value(i, 5)))
            except ValueError:
                mcs_code = table.cell_value(i, 5).strip()
            org_name = table.cell_value(i, 6).replace('"', "").strip()
            hospital = table.cell_value(i, 7).replace('"', "").strip()
            if mcs_code and org_name and hospital:
                try:
                    time.sleep(1)
                    res = {}
                    res = query_type(access_token, mcs_code, res)
                    res = query_hospital(hospital, res)
                    res = query_org(org_name, res)
                    r = addProdDelv(res)
                    if r == 160003:
                        has_send += 1
                        logger.warning(f"已经配送过了，流水号：{mcs_code}，配送企业：{org_name}，医院：{hospital}")
                        continue
                    elif r == 0:
                        success += 1
                        logger.info(f"配送成功：流水号：{mcs_code}，配送企业：{org_name}，医院：{hospital}")
                    else:
                        logger.error(f"配送失败：流水号：{mcs_code}，配送企业：{org_name}，医院：{hospital}")
                        continue
                except:
                    logger.error(f"配送失败：流水号：{mcs_code}，配送企业：{org_name}，医院：{hospital}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：流水号：{mcs_code}，配送企业：{org_name}，医院：{hospital}")

    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num-success-has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

g = input("按回车键继续...")
