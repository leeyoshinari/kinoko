#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari
import re
import os
import sys
import json
import time
import traceback
import urllib.parse
import logging.handlers
import requests
import requests.cookies
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import ddddocr
import xlrd

retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 403, 404, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
host1 = 'https://jyjy.hnsggzy.com:5443'   # 登陆host
host2 = 'https://jyjy.hnsggzy.com:6004'  # 授权 host
host3 = 'https://jyjy.hnsggzy.com:6003'  # 配送 host
addr = {'hunan': {'host1': 'https://jyjy.hnsggzy.com:5443', 'host2': 'https://jyjy.hnsggzy.com:6004', 'host3': 'https://jyjy.hnsggzy.com:6003'},
        'chenzhou': {'host1': 'http://59.110.175.165:8013'}}
session = requests.session()
headers = {'Host': host1.split('/')[-1], 'Accept': 'application/json, text/javascript, */*; q=0.01', 'Accept-Encoding': 'gzip, deflate, br',
'Referer': host1, 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', 'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors',
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.54',
'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"', 'Sec-Ch-Ua-Mobile': '?0',
'sec-ch-ua-platform': ''"Windows"'', 'Sec-Fetch-Site': 'same-origin', 'X-Requested-With': 'XMLHttpRequest'}
session.verify = False
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


def get_code():
    try:
        response = session.get(f'{host1}/VerifyCode.ashx', headers=headers)
        if response.status_code == 200:
            img_bytes = response.content
            ocr = ddddocr.DdddOcr(show_ad=False)
            return ocr.classification(img_bytes)
        else:
            raise Exception('获取验证码失败')
    except:
        logger.error(traceback.format_exc())

def login(username, password, code):
    try:
        #data = {'VerifyCode': code, 'mub': username, 'mbbasds': password}
        url = f'{host1}/LoginAction.aspx?mub={username}&mbbasds={password}&VerifyCode={code}'
        # headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        response = session.get(url, headers=headers)
        response_text = response.text
        if '交易系统' in response_text:
            cookies = re.findall("SID=(.*?)'>", response_text)
            if len(cookies) > 1:
                headers.update({"Host": host2.split('/')[-1], "Referer": host1})
                url = f'{host2}/SET_CK?SID={cookies[0]}'
                response = session.get(url, headers=headers)
                if response.status_code == 200:
                    logger.info("登陆成功")
                    return response.status_code
                else:
                    logger.error("登陆失败")
                    return None
            else:
                return None
        else:
            return None
    except:
        logger.error(traceback.format_exc())
        return None

def login_CA(url):
    if host1 in url:
        try:
            response = session.get(url, headers=headers)
            response_text = response.text
            if '交易系统' in response_text:
                cookies = re.findall("SID=(.*?)'>", response_text)
                if len(cookies) > 1:
                    headers.update({"Host": host2.split('/')[-1], "Referer": host1})
                    url = f'{host2}/SET_CK?SID={cookies[0]}'
                    response = session.get(url, headers=headers)
                    if response.status_code == 200:
                        logger.info("登陆成功")
                        return response.status_code
                    else:
                        logger.error("登陆失败")
                        return None
                else:
                    return None
            else:
                return None
        except:
            logger.error(traceback.format_exc())
            return None
    else:
        logger.error('CA 登录复制的地址不对，请确认后重新复制粘贴到 config.txt 中')
        raise


def query_company(org_name: str, res: dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/DistributionController/QueryCom.HSNN?COMID=&type=2&COMNAME={urllib.parse.quote(org_name)}'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc'}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] > 0:
                res.update({'cid': res_json['rows'][0]['COMID']})
                return res
            else:
                logger.error(f"查询企业结果为空，企业名称：{org_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询企业失败，企业名称：{org_name}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_zu(zu_code: str, res: dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/DistributionController/QueryGpart.HSNN?PROCURECATALOGID={zu_code}&GPARTNAME=&REGCARDNM=&COMNAME_SC=&GTYPENAME=&SORTNAME='
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc'}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] > 0:
                res.update({'pid': res_json['rows'][0]['PROCURECATALOGID']})
                return res
            else:
                logger.error(f"查询组件编号为空，组件编号：{zu_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询组件编号失败，组件编号：{zu_code}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_send_result(res: dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/DistributionController/QueryAreaByComgpart.HSNN?cid={res["cid"]}&pid={res["pid"]}'
        response = session.post(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['retval']
        else:
            logger.error(f"查询配送结果失败，组件编号：{res['pid']}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_areas(area:str):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/AreaController/QueryAreaCity.HSNN'
        data = {'fareaID': 430000}
        ids = None
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for a in res_json:
                if area == a['name']:
                    ids = a['id']
                    break
            if ids:
                return ids
            else:
                logger.error(f"未找到配送地区，配送地区：{area}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询配送地区失败，配送地区：{area}，状态码：{response.status_code}")
            raise
    except:
        raise


def sends(res: dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/DistributionController/SetDistributionByCom.HSNN?cid={res["cid"]}&pid={res["pid"]}&ids={res["ids"]}&oldids={res["oldids"]}'
        response = session.post(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['retcode']
        else:
            logger.error(f"配送失败，参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise

def check_login():
    try:
        url = f'{host3}/Index.aspx'
        h = {'Host': host3.split('/')[-1], 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                   'Accept-Encoding': 'gzip, deflate, br',
                   'Referer': host3, 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8', 'Sec-Fetch-Dest': 'document',
                   'Sec-Fetch-Mode': 'navigate', 'Upgrade-Insecure-Requests': '1',
                   'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.54',
                   'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"',
                   'Sec-Ch-Ua-Mobile': '?0', 'Sec-Fetch-User': '?1',
                   'sec-ch-ua-platform': ''"Windows"'', 'Sec-Fetch-Site': 'none'}
        response = session.get(url, headers=h, allow_redirects=True)
        if response.status_code == 200:
            if '配送关系设置' in response.text:
                return True
            else:
                return False
        else:
            return False
    except:
        logger.error(traceback.format_exc())
        return False

try:
    # 读取用户名和密码
    username = ''
    password = ''
    CALogin = ''
    region = 'hunan'
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'username' in lin:
                username = lin.split('=')[-1].strip()
            if 'password' in lin:
                password = lin.split('assword')[-1].strip()[1:].strip()
            if 'region' in lin:
                region = lin.split('=')[-1].strip()
            if 'ca_url' in lin:
                CALogin = lin.split('ca_url')[-1].strip()[1:].strip()

    # 检查配置
    if region in addr:
        host1 = addr[region]['host1']
        host2 = addr[region]['host2']
        host3 = addr[region]['host3']
    else:
        raise Exception(f"地区配置错误，当前配置为 {region}，请按要求配置 ~")

    # 登陆系统，获取token
    access_token = None
    cookie_path = os.path.join(current_path, 'cookie.txt')
    if os.path.exists(cookie_path):
        with open(cookie_path, 'r', encoding='utf-8') as f:
            access_token = json.loads(f.read().strip())
        coo = requests.cookies.RequestsCookieJar()
        for k, v in access_token.items():
            coo.set(k, v)
        session.cookies.update(coo)
        is_s = check_login()
        if not is_s:
            session.cookies.clear()
            if username and password and not CALogin:
                logger.info("使用账号登录")
                for _ in range(3):
                    headers.update({"Host": host1.split('/')[-1], "Referer": host1})
                    code = get_code()
                    logger.info(f'验证码识别结果：{code}')
                    access_token = login(username, password, code)
                    if access_token:
                        with open(cookie_path, 'w', encoding='utf-8') as f:
                            c = session.cookies.get_dict()
                            f.write(json.dumps(c))
                        break
                    time.sleep(1)
                if not access_token:
                    raise Exception("连续3次登陆失败，请重试")
            elif not username and not password and CALogin:
                logger.info("使用 CA 证书登录")
                access_token = login_CA(CALogin)
                if access_token:
                    with open(cookie_path, 'w', encoding='utf-8') as f:
                        c = session.cookies.get_dict()
                        f.write(json.dumps(c))
                time.sleep(1)
                if not access_token:
                    raise Exception("CA 证书登录失败，请重试")
            else:
                raise Exception("无法确定是使用账号登录，还是使用 CA 证书登录，请确认后重试 ~")
    else:
        if username and password and not CALogin:
            logger.info("使用账号登录")
            for _ in range(3):
                headers.update({"Host": host1.split('/')[-1], "Referer": host1})
                code = get_code()
                logger.info(f'验证码识别结果：{code}')
                access_token = login(username, password, code)
                if access_token:
                    with open(cookie_path, 'w', encoding='utf-8') as f:
                        c = session.cookies.get_dict()
                        f.write(json.dumps(c))
                    break
                time.sleep(1)
            if not access_token:
                raise Exception("连续3次登陆失败，请重试")
        elif not username and not password and CALogin:
            logger.info("使用 CA 证书登录")
            access_token = login_CA(CALogin)
            if access_token:
                with open(cookie_path, 'w', encoding='utf-8') as f:
                    c = session.cookies.get_dict()
                    f.write(json.dumps(c))
            time.sleep(1)
            if not access_token:
                raise Exception("CA 证书登录失败，请重试")
        else:
            raise Exception("无法确定是使用账号登录，还是使用 CA 证书登录，请确认后重试 ~")

    total_num = 0
    success = 0
    has_send = 0
    headers.update({"Host": host3.split('/')[-1], "Referer": host3})
    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))   # 打开excel表格
        sheets = excel.sheet_names()        # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])      # 获取sheet中的单元格
        ind = 1
        for i in range(table.nrows):
            if '配送公司' in table.cell_value(i, 3).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):     # 遍历所有非空单元格
            if not table.cell_value(i, 7): continue
            total_num += 1
            try:
                mcs_code = str(int(table.cell_value(i, 7)))
            except ValueError:
                mcs_code = table.cell_value(i, 7).strip()
            org_name = table.cell_value(i, 3).replace('"', "").strip()
            area = table.cell_value(i, 6).replace('"', "").strip()
            if mcs_code and org_name and area:
                try:
                    time.sleep(2)
                    res = {}
                    headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
                    res = query_company(org_name, res)
                    res = query_zu(mcs_code, res)
                    retval = query_send_result(res)
                    ids = query_areas(area)
                    if retval:
                        if ids in retval:
                            has_send += 1
                            logger.warning(f"已经配送过了，企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")
                            continue
                        else:
                            res.update({"ids": f"{ids},{retval}", "oldids": retval})
                    else:
                        res.update({"ids": ids, "oldids": None})

                    r = sends(res)
                    if r == 'ok':
                        success += 1
                        logger.info(f"配送成功：企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")
                    else:
                        logger.error(f"配送失败：企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")
                        continue
                except:
                    logger.error(f"配送失败：企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")
                    logger.error(traceback.format_exc())
                    time.sleep(3)
            else:
                logger.error(f"Excel 数据不完整：企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")

    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num-success-has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

g = input("按回车键继续...")
