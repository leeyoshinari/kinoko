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
import ddddocr
import xlrd
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

host1 = 'http://ypnew.hnggzyjy.cn:9080'
session = requests.session()
headers = {'Host': host1.split('/')[-1],
'Referer': host1,
'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58',
'sec-ch-ua': '"Chromium";v="112", "Microsoft Edge";v="112", "Not:A-Brand";v="99"',
'sec-ch-ua-platform': ''"Windows"''}
#session.verify = False

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


def get_code():
    try:
        _ = session.get(f'{host1}/std/login.html', headers=headers)
        response = session.get(f'{host1}/std/captchaImg', headers=headers)
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
        data = {'username': encrypt_data(username), 'password': encrypt_data(password), 'answer': encrypt_data(code), 'activeType': encrypt_data('ptLogin')}
        url = f'{host1}/std/loginAuth.html'
        headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f"登陆失败：{res_json['msg']}")
                return None
            with open(cookie_path, 'w', encoding='utf-8') as f:
                c = session.cookies.get_dict()
                f.write(json.dumps(c))
            logger.info("登陆成功")
            return res_json['success']
        else:
            logger.error("登陆失败")
            return None
    except:
        logger.error(traceback.format_exc())
        return None


def query_company(org_name: str, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getCompanyList.html'
        data = {'companyName': org_name, 'companyAccountCode': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] > 0:
                flag = True
                for r in res_json['rows']:
                    CN = r['companyName'].split('(')[0]
                    if org_name == CN:
                        res.update({'companyIds': r['companyId']})
                        res.update({'companyNames': f"{r['companyName']}({r['companyAccountCode']})"})
                        flag = False
                        break
                if flag:
                    logger.error(f"查询配送企业失败，配送企业：{org_name}, 查询结果：{res_json['rows']}")
                    raise
                #     res.update({'companyIds': res_json['rows'][0]['companyId']})
                #     res.update({'companyNames': f"{res_json['rows'][0]['companyName']}({res_json['rows'][0]['companyAccountCode']})"})
                return res
            else:
                logger.error(f"查询配送企业结果为空，配送企业：{org_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询配送企业失败，配送企业：{org_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_zu(zu_code: str, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getGoodsListData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'notPurchaseType': '0,3,4,5',
                'type': 0, 'procurecatalogId': None, 'goodsId': zu_code, 'regCode': None, 'goodsName': None, 'companyNameSc': None, 'areaId': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] > 0:
                if str(res_json['rows'][0]['goodsId']) == zu_code:
                    res.update({'procurecatalogId': res_json['rows'][0]['procurecatalogId']})
                    res.update({'goodsId': res_json['rows'][0]['goodsId']})
                    res.update({'companyIdTb': res_json['conditions']['companyIdTb']})
                    return res
                else:
                    logger.error(f"查询省标号不正确，省标号：{zu_code}，查询结果：{response.text}")
                    raise
            else:
                logger.error(f"查询省标号为空，省标号：{zu_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询省标号失败，省标号：{zu_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_goods_id(zu_code: str, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getGoodsListData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'notPurchaseType': '2,1',
                'type': 1, 'procurecatalogId': None, 'goodsId': zu_code, 'regCode': None, 'goodsName': None, 'companyNameSc': None, 'areaId': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] > 0:
                if str(res_json['rows'][0]['goodsId']) == zu_code:
                    res.update({'procurecatalogId': res_json['rows'][0]['procurecatalogId']})
                    res.update({'goodsId': res_json['rows'][0]['goodsId']})
                    res.update({'companyIdTb': res_json['conditions']['companyIdTb']})
                    return res
                else:
                    logger.error(f"查询产品代码不正确，产品代码：{zu_code}，查询结果：{response.text}")
                    raise
            else:
                logger.error(f"查询产品代码为空，产品代码：{zu_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询产品代码失败，产品代码：{zu_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_send_result(res: dict, flag: bool):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getDrugpurDistributionRelationData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'notPurchaseType': '0,3,4,5', 'area1': '410000', 'area2': res['areaIds[]'], 'companyNamePs': res['org_name'],
                'type': 0, 'procurecatalogId': None, 'goodsId': res['goodsId'], 'submitTimeEnd': None, 'companyNameTb': None,
                'submitStatus': None, 'submitTimeStart': None, 'companyIdPs': None, 'confirmStatus': None}#, 'companyIdTb':res['']}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['total'] == 1:
                if str(res_json['rows'][0]['goodsId']) == str(res['code']) and res_json['rows'][0]['areaName'] == res['area'] and res['org_name'] in res_json['rows'][0]['companyNamePs']:
                    if res_json['rows'][0]['submitStatus'] == 0:
                        return res_json['rows'][0]['id']
                    elif res_json['rows'][0]['submitStatus'] == 1 and res_json['rows'][0]['confirmStatus'] == 4:
                        logger.warning(f"确认状态为已撤废，正在重新添加配送关系，代理商：{res['org_name']}，省标号：{res['code']}，配送城市：{res['area']}")
                        return res_json['rows'][0]['id']
                    elif res_json['rows'][0]['submitStatus'] == 1 and res_json['rows'][0]['confirmStatus'] < 4:
                        return -1
                    else:
                        logger.error(f"配送关系列表提交状态未知，返回值：{response.text}")
                        raise
                else:
                    logger.error(f"配送关系列表中没有找到刚添加的配送关系，返回值：{response.text}")
                    raise
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


def query_areas(area:str, res:dict):
    try:
        url = f'{host1}/sjtrade/selectController/getArea.html'
        data = {'ID': '410000'}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            for a in res_json:
                if area == a['text']:
                    res.update({'areaIds[]': a['value']})
                    res.update({'areaNames[]': a['text']})
                    return res
            logger.error(f"未找到配送城市，配送城市：{area}，所有地市：{response.text}")
            raise
        else:
            logger.error(f"查询配送城市失败，配送城市：{area}，状态码：{response.status_code}")
            raise
    except:
        raise


def sends(res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/addDistributionRelation.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'添加配送关系失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"添加配送关系失败，参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise


def submitted(ids):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/updateProtocolSignByYGGWSc.html'
        data = {'list': json.dumps([{"id":f"{ids}"}])}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'配送关系提交失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"配送关系提交失败，参数：{data}，状态码：{response.status_code}")
            raise
    except:
        raise


def encrypt_data(msg):
    with open('publicKey') as f:
        public_key = f.read()
        cipher = PKCS1_cipher.new(RSA.importKey(public_key))
        encrypt_text = base64.b64encode(cipher.encrypt(msg.encode()))
        return encrypt_text.decode()


def check_login():
    if os.path.exists(cookie_path):
        cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
        coo = requests.cookies.RequestsCookieJar()
        for k, v in cookies_dict.items():
            coo.set(k, v)
        session.cookies.update(coo)
        headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        url = f'{host1}/sjtrade/home/getWaitData.html'
        response = session.post(url, headers=headers)
        if response.status_code == 200:
            try:
                res_json = json.loads(response.text)
                if res_json['code'] == 0:
                    logger.info(f"免登陆成功~")
                    return True
                else:
                    return False
            except:
                return False
        else:
            return False
    else:
        return False


def query_has_register(reg_code, org_name, hospital, good_name, reg_id):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegDistributionRelationData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'regCode': reg_code, 'id': reg_id, 'notPurchaseType': '2,1', 'companyNamePs': org_name, 'area1': None,
                'area2': None, 'area3': None, 'confirmStatus': None, 'hospitalName': hospital}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                for rr in res_json['rows']:
                    if rr['regCode'] == reg_code and rr['hospitalName'] == hospital and good_name == rr['goodsName'] and org_name in rr['companyNamePs']:
                        return rr['confirmStatus']
                return None
            else:
                return None
        else:
            logger.error(f"查询配送关系列表失败，注册证号：{reg_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_has_register_goods_id(reg_code, org_name, hospital, reg_id):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegDistributionRelationData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'procurecatalogId': reg_id, 'notPurchaseType': '2,1', 'companyNamePs': org_name, 'area1': None,
                'area2': None, 'area3': None, 'confirmStatus': None, 'hospitalName': hospital}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                for rr in res_json['rows']:
                    if rr['hospitalName'] == hospital and org_name in rr['companyNamePs']:
                        return rr['confirmStatus']
                return None
            else:
                return None
        else:
            logger.error(f"查询配送关系列表失败，产品代码：{reg_code}，配送企业：{org_name}，医院名称：{hospital}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_has_register_by_category(org_name, hospital, reg_id):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegDistributionRelationData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'regCode': None, 'id': reg_id, 'notPurchaseType': '2,1', 'companyNamePs': org_name, 'area1': None,
                'area2': None, 'area3': None, 'confirmStatus': None, 'hospitalName': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                for rr in res_json['rows']:
                    if rr['hospitalName'] == hospital and good_name == rr['goodsName'] and org_name in rr['companyNamePs']:
                        return rr['confirmStatus']
                return None
            else:
                return None
        else:
            logger.error(f"查询配送关系列表失败，注册证号：{org_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_register_no(reg_code, good_name, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegGoodsListData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'notPurchaseType': '2,1',
                'type': 1, 'sourceId': None, 'regCode': reg_code, 'goodsName': good_name, 'companyNameSc': None, 'areaId': None,
                'packetNum': None, 'catalogName':None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                if len(res_json['rows']) == 1 and res_json['rows'][0]['regCode'] == reg_code:
                    res.update({'id': res_json['rows'][0]['id']})
                    return res
                else:
                    logger.error(f"查询注册证号不正确，注册证号：{reg_code}，查询结果：{res_json['rows'][0]}")
                    raise
            else:
                logger.error(f"查询注册证号为空，注册证号：{reg_code}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询注册证号失败，注册证号：{reg_code}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_register_no_by_category(category_name, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegGoodsListData.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc', 'notPurchaseType': '2,1',
                'type': 1, 'sourceId': None, 'regCode': None, 'goodsName': None, 'companyNameSc': None, 'areaId': None, 'packetNum': None,
                'catalogName': category_name}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                for r in res_json['rows']:
                    if r['catalogName'] == category_name:
                        res.update({'id': res_json['rows'][0]['id']})
                        return res
                logger.error(f"查询目录名称不正确，目录名称：{category_name}，查询结果：{res_json['rows']}")
                raise
            else:
                logger.error(f"查询目录名称为空，目录名称：{category_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询目录名称失败，目录名称：{category_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_register_company(org_name, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getCompanyList.html'
        data = {'companyName': org_name, 'loginUserName': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                for r in res_json['rows']:
                    if org_name == r['companyName']:
                        res.update({'companyIds': r['companyId']})
                        res.update({'companyNames': f"{r['companyName']}({r['companyAccountCode']})"})
                        return res
                companys = [rr['companyName'] for rr in res_json['rows']]
                logger.error(f"无法匹配配送企业，配送企业：{org_name}，查询结果：{'，'.join(companys)}")
                raise
            else:
                logger.error(f"查询配送企业结果为空，配送企业：{org_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询配送企业失败，配送企业：{org_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_reg_hospital(hospital_name, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getRegHospitalList.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'hospitalName': hospital_name, 'regId': res['id'], 'area1': 410000, 'area2': None, 'area3': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                c_num = [rr['hospitalId'] for rr in res_json['rows'] if hospital_name == rr['hospitalName']]
                if len(c_num) != 1:
                    logger.error(f"无法匹配医院名称，医院名称：{hospital_name}，医院Id：{', '.join(c_num)}")
                    raise
                for r in res_json['rows']:
                    if hospital_name == r['hospitalName']:
                        res.update({'hospitalIds[]': r['hospitalId']})
                        res.update({'hospitalNames[]': r['hospitalName']})
                        return res
                companys = [rr['hospitalName'] for rr in res_json['rows']]
                logger.error(f"无法匹配医院名称，医院名称：{hospital_name}，查询结果：{'，'.join(companys)}")
                raise
            else:
                logger.error(f"查询医院名称为空，医院名称：{hospital_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询医院名称失败，医院名称：{hospital_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def query_hospital_list(hospital_name, res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/getHospitalList.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'hospitalName': hospital_name, 'procurecatalogId': res['procurecatalogId'], 'area1': 410000, 'area2': None, 'area3': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if len(res_json['rows']) > 0:
                c_num = [rr['hospitalId'] for rr in res_json['rows'] if hospital_name == rr['hospitalName']]
                if len(c_num) != 1:
                    logger.error(f"无法匹配医院名称，医院名称：{hospital_name}，医院Id：{', '.join(c_num)}")
                    raise
                for r in res_json['rows']:
                    if hospital_name == r['hospitalName']:
                        res.update({'hospitalIds[]': r['hospitalId']})
                        res.update({'hospitalNames[]': r['hospitalName']})
                        return res
                companys = [rr['hospitalName'] for rr in res_json['rows']]
                logger.error(f"无法匹配医院名称，医院名称：{hospital_name}，查询结果：{'，'.join(companys)}")
                raise
            else:
                logger.error(f"查询医院名称为空，医院名称：{hospital_name}，查询结果：{response.text}")
                raise
        else:
            logger.error(f"查询医院名称失败，医院名称：{hospital_name}，状态码：{response.status_code}")
            raise
    except:
        raise


def submitted_reg(res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/addRegDistributionRelationDl.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'新建配送关系失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"新建配送关系失败，参数：{res}，状态码：{response.status_code}")
            raise
    except:
        raise


def submitted_drl(res: dict):
    try:
        url = f'{host1}/sjtrade/suppurDistributionRelation/addDistributionRelationDl.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success']:
                logger.error(f'新建配送关系失败，返回值：{response.text}')
                raise
        else:
            logger.error(f"新建配送关系失败，参数：{res}，状态码：{response.status_code}")
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
    if not check_login():
        coo = requests.cookies.RequestsCookieJar()
        session.cookies = coo
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

    file_names = [n for n in os.listdir(current_path) if n.endswith('.xls')] + [n for n in os.listdir(current_path) if n.endswith('.xlsx')]
    for file_name in file_names:
        excel = xlrd.open_workbook(os.path.join(current_path, file_name))   # 打开excel表格
        sheets = excel.sheet_names()        # 获取excel中所有的sheet
        table = excel.sheet_by_name(sheets[0])      # 获取sheet中的单元格
        ind = 1
        is_type = None
        total_num = 0
        success = 0
        has_send = 0
        for i in range(1, table.nrows):
            is_type = table.cell_value(i, 0).strip()
            if is_type == '点配送':
                if not table.cell_value(i, 2): continue
                total_num += 1
                try:
                    mcs_code = table.cell_value(i, 2).strip()
                except:
                    mcs_code = str(int(table.cell_value(i, 2)))
                org_name = table.cell_value(i, 8).replace('"', "").strip()
                area = table.cell_value(i, 9).replace('"', "").strip()
                if mcs_code and org_name and area:
                    try:
                        time.sleep(0.5)
                        res = {'code': mcs_code, 'org_name': org_name, 'area': area}
                        res = query_company(org_name, res)
                        res = query_zu(mcs_code, res)
                        res = query_areas(area, res)
                        retval = query_send_result(res, False)
                        if retval == -1:
                            has_send += 1
                            logger.warning(f"已经配送过了，代理商：{org_name}，省标号：{mcs_code}，配送城市：{area}")
                            continue

                        sends(res)
                        time.sleep(0.5)
                        retval = query_send_result(res, True)
                        if retval > 1:
                            submitted(retval)
                            success += 1
                            logger.info(f"配送成功：代理商：{org_name}，省标号：{mcs_code}，配送城市：{area}")
                        else:
                            logger.error(f"配送失败：代理商：{org_name}，省标号：{mcs_code}，配送城市：{area}")
                            continue
                    except:
                        logger.error(f"配送失败：代理商：{org_name}，省标号：{mcs_code}，配送城市：{area}")
                        logger.error(traceback.format_exc())
                else:
                    logger.error(f"Excel 数据不完整：代理商：{org_name}，省标号：{mcs_code}，配送城市：{area}")
            # logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num - success - has_send}，已经配送：{has_send}")

            if is_type == '发光':
                if not table.cell_value(i, 2): continue
                total_num += 1
                try:
                    mcs_code = table.cell_value(i, 2).strip()
                except:
                    mcs_code = str(int(table.cell_value(i, 2)))
                org_name = table.cell_value(i, 7).strip()
                hospital = table.cell_value(i, 5).strip()
                if mcs_code and org_name and hospital:
                    try:
                        time.sleep(1.2)
                        res = {}
                        res = query_goods_id(mcs_code, res)
                        res = query_register_company(org_name, res)
                        res = query_hospital_list(hospital, res)
                        submitted_drl(res)
                        success += 1
                        logger.info(f"新建 发光 配送关系成功：产品代码：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}")
                    except:
                        logger.error(f"新建 发光 配送关系失败：产品代码：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}")
                        logger.error(traceback.format_exc())

            if is_type == '肝功':
                if not table.cell_value(i, 2): continue
                total_num += 1
                try:
                    mcs_code = table.cell_value(i, 2).strip()
                except:
                    mcs_code = str(int(table.cell_value(i, 2)))
                org_name = table.cell_value(i, 8).strip()
                good_name = table.cell_value(i, 3).strip()
                hospital = table.cell_value(i, 7).strip()
                if mcs_code and org_name and hospital:
                    try:
                        time.sleep(1.2)
                        res = {}
                        res = query_register_no(mcs_code, good_name, res)
                        has_reg = query_has_register(mcs_code, org_name, hospital, good_name, res['id'])
                        if has_reg in [0, 1, 2, 3, 4]:
                            has_send += 1
                            logger.warning(f"已有配送关系，配送关系状态为{['待提交', '已提交待配送方确认', '双方同意', '配送方拒绝', '已撤废'][has_reg]}，注册证号：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}，产品名称：{good_name}")
                            continue
                        res = query_register_company(org_name, res)
                        res = query_reg_hospital(hospital, res)
                        submitted_reg(res)
                        success += 1
                        logger.info(f"新建 肝功 配送关系成功：注册证号：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}，产品名称：{good_name}")
                    except:
                        logger.error(f"新建 肝功 配送关系失败：注册证号：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}，产品名称：{good_name}")
                        logger.error(traceback.format_exc())
                else:
                    logger.error(f"Excel 数据不完整：注册证号：{mcs_code}，医院名称：{hospital}，配送企业：{org_name}，产品名称：{good_name}")

            if is_type == '肾功':
                if not table.cell_value(i, 1): continue
                total_num += 1
                category_name = table.cell_value(i, 1).strip()
                org_name = table.cell_value(i, 5).strip()
                hospital = table.cell_value(i, 3).strip()
                if category_name and org_name and hospital:
                    try:
                        time.sleep(1.2)
                        res = {}
                        res = query_register_no_by_category(category_name, res)
                        res = query_register_company(org_name, res)
                        res = query_reg_hospital(hospital, res)
                        submitted_reg(res)
                        success += 1
                        logger.info(f"新建 肾功 配送关系成功：目录名称：{category_name}，医院名称：{hospital}，配送企业：{org_name}")
                    except:
                        logger.error(f"新建 肾功 配送关系失败：目录名称：{category_name}，医院名称：{hospital}，配送企业：{org_name}")
                        logger.error(traceback.format_exc())
                else:
                    logger.error(f"Excel 数据不完整：目录名称：{category_name}，医院名称：{hospital}，配送企业：{org_name}")

        logger.info(f"总数：{total_num}，成功数：{success}，失败数：{total_num-success-has_send}，已有配送关系数：{has_send}")

except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

g = input("按回车键继续...")
