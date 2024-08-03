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
import ddddocr
import xlrd

host1 = 'https://www.hbyxjzcg.cn:804'   # 登陆host
host2 = 'https://hbyxjzcg.cn:8011'  # 授权 host
host3 = 'https://hbyxjzcg.cn:8015'  # 配送 host
session = requests.session()
headers = {'Host': host1.split('/')[-1],
'Referer': host1,
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"',
'sec-ch-ua-platform': ''"Windows"''}
session.verify = False

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
        data = {'VerifyCode': code, 'mub': username, 'mbbasds': password}
        url = f'{host1}/LoginAction.aspx'
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        response = session.post(url, data=data, headers=headers)
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


def query_company(org_name: str, res: dict):
    try:
        url = f'{host3}//HSNN/CM/Trade/Web/Controller/DistributionController/QueryCom.HSNN?COMID=&type=2&COMNAME={urllib.parse.quote(org_name)}'
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

def query_areas(area:str, res:dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/AreaController/QueryArea.HSNN'
        data = {'gname': '', 'cid': res['cid'], 'pid': res['pid'], 'type': 2}
        ids = None
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(json.loads(response.text))
            for a in res_json:
                if area == a['name']:
                    ids = a['id']
                    break
            if ids:
                return ids
            else:
                logger.error(f"未找到配送地区，配送地区：{area}，所有地区：{response.text}")
                raise
        else:
            logger.error(f"查询配送地区失败，配送地区：{area}，状态码：{response.status_code}")
            raise
    except:
        raise


def sends(res: dict):
    try:
        url = f'{host3}/HSNN/CM/Trade/Web/Controller/DistributionController/SetDistributionByCom_NEW.HSNN?cid={res["cid"]}&pid={res["pid"]}&ids={res["ids"]}&oldids={res["oldids"]}'
        response = session.post(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            return res_json['retcode']
        else:
            logger.error(f"配送失败，参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise

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

    # 登陆系统，获取token
    access_token = None
    for _ in range(3):
        headers.update({"Host": host1.split('/')[-1], "Referer": host1})
        code = get_code()
        logger.info(f'验证码识别结果：{code}')
        access_token = login(username, password, code)
        if access_token:
            break
        time.sleep(1)
    if not access_token:
        raise Exception("连续3次登陆失败，请重试")

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
            if '组件编码' in table.cell_value(i, 0).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):     # 遍历所有非空单元格
            if not table.cell_value(i, 0): continue
            total_num += 1
            try:
                mcs_code = str(int(table.cell_value(i, 0)))
            except ValueError:
                mcs_code = table.cell_value(i, 0).strip()
            org_name = table.cell_value(i, 2).replace('"', "").strip()
            area = table.cell_value(i, 4).replace('"', "").strip()
            if mcs_code and org_name and area:
                try:
                    time.sleep(1)
                    res = {}
                    res = query_company(org_name, res)
                    res = query_zu(mcs_code, res)
                    retval = query_send_result(res)
                    ids = query_areas(area, res)
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
            else:
                logger.error(f"Excel 数据不完整：企业：{org_name}，组件编码：{mcs_code}，配送城市：{area}")

    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num-success-has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

g = input("按回车键继续...")
