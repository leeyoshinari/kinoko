#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: leeyoshinari
import os
import sys
import json
import time
import traceback
import logging.handlers
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import xlrd

addr = {"loudi":{"host1": "www.ldhccg.com", "areaId": 431300, "areaName": '娄底市', 'sx': 'ld'},
        "zhuzhou":{"host1": "www.hnyycg.net", "areaId": 430200, "areaName": '株洲市', 'sx': ''},
        "yongzhou":{"host1": "www.yzyycg.com", "areaId": 431100, "areaName": '永州市', 'sx': 'yz'},
        "zhangjiajie":{"host1": "www.zjjhccg.com", "areaId": 430800, "areaName": '张家界市', 'sx': 'zjj'},
        "yueyang":{"host1": "www.hnyyjc.cn", "areaId": 430600, "areaName": '岳阳市', 'sx': 'yy'},
        "changde":{"host1": "www.hnyyjc.cn", "areaId": 430700, "areaName": '常德市', 'sx': 'cd'},
        "shaoyang":{"host1": "www.hnyyjc.cn", "areaId": 430500, "areaName": '邵阳市', 'sx': 'sy'}}
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 403, 404, 500, 501, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.session()
headers = {'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
'Upgrade-Insecure-Requests': '1', 'Cache-Control': "max-age=0",
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'}
#session.verify = False
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

def login(request_body, city):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hcstd/login.html'
        if city in ['yueyang', 'shaoyang', 'changde']:
            url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}cg/login.html'
        _ = session.get(url, headers=headers)
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hcstd/CAloginAuth.html'
        if city == 'yueyang':
            url = f'http://{addr[city]["host1"]}/yycg/CAloginAuth.html'
        headers.update({'Content-Type': 'application/x-www-form-urlencoded'})
        response = session.post(url, data=request_body, headers=headers)
        if response.status_code == 200:
            if '系统切换' in response.text:
                logger.info(f"登陆成功，当前城市：{addr[city]['areaName']}")
                return response.status_code
            else:
                logger.error("登陆失败")
                return None
        else:
            logger.error("登陆失败")
            return None
    except:
        logger.error(traceback.format_exc())
        return None

def query_company(org_name: str, res: dict, city: str):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/suppurDistributionRelation/getSuppurCompanyData.html'
        data = {'companyType': 2, 'companyName': org_name, '_search': False, 'nd': int(time.time() * 1000), 'rows': 20, 'page': 1, 'sidx': None, 'sord': 'asc'}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['records'] == 1:
                res.update({'companyId': res_json['rows'][0]['companyId']})
                res.update({'companyName': res_json['rows'][0]['companyName']})
                return res
            else:
                logger.error(f"查询配送企业结果为空，配送企业：{org_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询配送企业失败，配送企业：{org_name}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_zu(zu_code: str, res: dict, city: str):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/suppurDistributionRelation/getSuppurProcurecatalogList.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 20, 'page': 1, 'sidx': None, 'sord': 'asc', 'goodsId': zu_code,
                'gclassTypeName': None, 'productName': None, 'purchaseType': None, 'regCode': None, 'goodsName': None, 'outlookc': None,
                'goodsType': None, 'goodOrigin': None, 'companyNameSc': None, 'largeclassType': None, 'smallclassType': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['records'] > 0:
                if str(res_json['rows'][0]['goodsId']) == zu_code:
                    res.update({'procurecatalogId': res_json['rows'][0]['procurecatalogId']})
                    res.update({'goodsId': res_json['rows'][0]['goodsId']})
                    res.update({'goodsName': res_json['rows'][0]['goodsName']})
                    res.update({'procurecatalogIds': json.dumps([{"procurecatalogId": res_json['rows'][0]['procurecatalogId'],
                                                       "goodsName": res_json['rows'][0]['goodsName'],
                                                       "goodsId": res_json['rows'][0]['goodsId']}], ensure_ascii=False)})
                    return res
                else:
                    logger.error(f"查询产品编码不正确，产品编码：{zu_code}，查询结果：{response.text}")
                    raise
            else:
                logger.error(f"查询产品编码为空，产品编码：{zu_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询产品编码失败，产品编码：{zu_code}，状态码：{response.status_code}")
            raise
    except:
        raise

def query_send_result(res: dict, flag: bool, city: str):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/suppurDistributionRelation/getSuppurDistributionRelationData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 20, 'page': 1, 'sidx': 't.add_time', 'sord': 'desc',
                'goodsId': res['goodsId'], 'exportSelectList': None, 'productName': None, 'purchaseType': None, 'regCode': None, 'goodsName': res['goodsName'], 'outlookc': None,
                'goodsType': None, 'goodOrigin': None, 'companyNameSc': None, 'confirmState': None, 'companyNamePs': res['companyName'],
                'largeclassType': None, 'smallclassType': None}
        if city == 'loudi':
            data.update({'areaId': res['areaId']})
        if city == 'zhuzhou':
            data.update({'areaId': addr[city]["areaId"]})
            data.update({'area2': res['areaId']})
        if city in ['yongzhou', 'zhangjiajie', 'yueyang', 'shaoyang', 'changde']:
            data.update({'area2': res['areaId']})
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['records'] > 0:
                for r in res_json['rows']:
                    if str(r['goodsId']) == str(res['code']) and res['area'] in r['areaName'] and res['org_name'] == r['companyNamePs'].replace(' ', ''):
                        if r['submitState'] == 0:
                            return r['relationId']
                        elif r['submitState'] == 1:
                            return -1
                        else:
                            logger.error(f"配送关系列表提交状态未知，返回值：{response.text}")
                            raise
                if flag:
                    logger.error(f"配送关系列表中没有找到刚添加的配送关系，返回值：{response.text}")
                    raise
                else:
                    return 0
            else:
                if flag:
                    logger.error(f"配送关系列表中未查到数据，返回值：{response.text}")
                    raise
                else:
                    return 0
        else:
            logger.error(f"查询配送关系列表失败，状态码：{response.status_code}")
            raise
    except:
        raise

def query_areas(area:str, res:dict, city: str):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/selectController/getAreaByDistribution.html?ID={addr[city]["areaId"]}&areaName={addr[city]["areaName"]}'
        response = session.get(url, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for a in res_json:
                if a['text'].endswith(area):
                    res.update({'areaId': a['value']})
                    res.update({'areaName': a['text']})
                    res.update({'areaIds': json.dumps([{"areaId": a['value'],"areaName": a['text']}], ensure_ascii=False)})
                    return res
            logger.error(f"未找到配送地区，配送地区：{area}，所有地区：{response.text}")
            raise
        else:
            logger.error(f"查询配送地区失败，配送地区：{area}，状态码：{response.status_code}")
            raise
    except:
        raise

def sends(res: dict, city: str):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/suppurDistributionRelation/addDistributionRelationByCompPs.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'新增配送关系失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"新增配送关系失败，参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise

def submitted(ids, city):
    try:
        url = f'http://{addr[city]["host1"]}/{addr[city]["sx"]}hctrade/suppurDistributionRelation/updateProtocolSignBySc.html'
        data = {'list': json.dumps([{"relationId":f"{ids}"}])}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'提交配送关系失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"提交配送关系失败，参数：{data}，状态码：{response.status_code}")
            raise
    except:
        raise

try:
    # 读取用户名和密码
    request_body = ''
    city = ""
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'parameters' in lin:
                request_body = lin.split('parameters')[-1].strip()[1:].strip()
            if 'city' in lin:
                city = lin.split('=')[-1].strip()

    if city not in addr:
        logger.error(f"地市名称输入错误，当前输入是 {city}，请确认后重试 ~")
        raise Exception("地市名称输入错误")
    # 登陆系统，获取token
    access_token = None
    for _ in range(3):
        access_token = login(request_body, city)
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
            if '配送CODE编号' in table.cell_value(i, 6).strip():
                break
            else:
                ind += 1
        for i in range(ind, table.nrows):     # 遍历所有非空单元格
            if not table.cell_value(i, 6): continue
            total_num += 1
            try:
                mcs_code = str(int(table.cell_value(i, 6)))
            except ValueError:
                mcs_code = table.cell_value(i, 6).strip()
            org_name = table.cell_value(i, 2).replace('"', "").strip()
            area = table.cell_value(i, 5).replace('"', "").strip()
            if mcs_code and org_name and area:
                try:
                    time.sleep(0.5)
                    res = {'code': mcs_code, 'org_name': org_name, 'area': area.split('-')[-1].strip()}
                    res = query_company(org_name, res, city)
                    res = query_zu(mcs_code, res, city)
                    res = query_areas(area.split('-')[-1].strip(), res, city)
                    retval = query_send_result(res, False, city)
                    if retval == -1:
                        has_send += 1
                        logger.warning(f"已经配送过了，配送企业：{org_name}，产品编码：{mcs_code}，配送地区：{area}")
                        continue

                    sends(res, city)
                    time.sleep(0.3)
                    retval = query_send_result(res, True, city)
                    if retval > 1:
                        submitted(retval, city)
                        success += 1
                        logger.info(f"配送成功：配送企业：{org_name}，产品编码：{mcs_code}，配送地区：{area}")
                    else:
                        logger.error(f"配送失败：配送企业：{org_name}，产品编码：{mcs_code}，配送地区：{area}")
                        continue
                except:
                    logger.error(f"配送失败：配送企业：{org_name}，产品编码：{mcs_code}，配送地区：{area}")
                    logger.error(traceback.format_exc())
            else:
                logger.error(f"Excel 数据不完整：配送企业：{org_name}，产品编码：{mcs_code}，配送地区：{area}")

    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num-success-has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

g = input("按回车键继续...")
