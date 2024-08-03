#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import traceback
import logging.handlers
import requests.packages.urllib3
from requests_toolbelt import MultipartEncoder
import requests.cookies
import requests
import hashlib
import xlrd
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

host1 = 'https://gpo.gzggzy.cn'   # 登陆host
host2 = 'https://gpo.gzggzy.cn'  # 配送 host
retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[400, 401, 403, 500, 501, 502, 503, 504])
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
auth_file_path = os.path.join(current_path, '授权文件')
auth_file_url = {}
company_dict = {}


def login(caCert):
    try:
        url = f'{host1}'
        response = session.get(url, headers=headers)
        if response.status_code == 200 and 'CA登录' in response.text:
            headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            headers.update({'X-Requested-With': 'XMLHttpRequest'})
            url = f'{host1}/CetRandomByServer.servlet'
            response = session.post(url, data={'number': '5'}, headers=headers)
            if response.status_code == 200:
                url = f'{host1}/webPortal/systemHCCaLogin.html'
                login_params = {'caCert': caCert, 'caType': 'NETCA', 'isOrgKey': '1', 'confirmLogin': '0'}
                response = session.post(url, data=login_params, headers=headers)
                if response.status_code == 200:
                    res_json = json.loads(response.text)
                    if res_json['code'] == 1:
                        hcLoginToken = res_json['hcLoginToken']
                        response = session.get(res_json['msg'], headers=headers)
                        with open(cookie_path, 'w', encoding='utf-8') as f:
                            c = session.cookies.get_dict()
                            f.write(json.dumps(c))
                        logger.info("登陆成功 ~")
                        return response.status_code
                    else:
                        logger.error(f"登陆失败，响应值：{response.text}")
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


def query_company(company, agreement_type, res: dict):
    try:
        url = f'{host2}/hcTrade/suppurDistributionRelation/getCompanyTbGoodsList.html'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'companyNameTb': None, 'areaId': None,'companyNamePs': company,'addTimeStart': None, 'addTimeEnd': None, 'confirmStatusSc': None,
                'confirmStatusPs': None, 'agreementStatus': None, 'agreementType': None}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) > 0:
                agreetype = [agre['agreementType'] for agre in res_json['rows']]
                if agreement_type in agreetype:
                    agree_index = agreetype.index(agreement_type)
                else:
                    logger.error(f"配送协议类型不正确，配送企业：{company}")
                    raise
                if res_json['rows'][agree_index]['confirmStatusSc'] == 1 and res_json['rows'][agree_index]['confirmStatusPs'] == 2:
                    res.update({"agreementId": res_json['rows'][agree_index]['agreementId']})
                    res.update({"agreementType": res_json['rows'][agree_index]['agreementType']})
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
        url = f'{host2}/hcTrade/suppurDistributionRelation/getStdHospitalData.html'
        data = {"rows": 1000, "page": 1, "areaId": None, "hospitalName": hospital}
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


def query_code(ms_code, agreement_type, res: dict):
    try:
        url = f"{host2}/hcTrade/suppurDistributionRelation/getGoodsListData2.html?agreementType={agreement_type}"
        data = {'_search': False, 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'goodsIds': ms_code, 'regCode': None, 'goodsName': None, 'nd': int(time.time() * 1000)}
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if res_json['code'] == 0 and res_json['rows'] and len(res_json['rows']) == 1:
                res.update({"procurecatalogIds": res_json['rows'][0]['procurecatalogId']})
                return res
            else:
                if res_json['code'] != 0:
                    logger.error(f"产品ID查询结果为空，产品ID：{ms_code}，查询结果：{response.text}")
                else:
                    logger.error(f"产品ID查询结果为空或有多个，产品ID：{ms_code}，查询结果：{res_json['rows']}")
                raise
        else:
            logger.error(f"产品ID查询查询失败，产品ID：{ms_code}，状态码：{response.status_code}")
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
        url = f"{host2}/hcTrade/common/uploadFile.html"
        data = MultipartEncoder(fields={"file": (fileName, open(file_path, 'rb'), "application/pdf")},
                                boundary='------WebKitFormBoundaryMrOkEnKbZTB1aBfy')
        headers.update({'Content-Type': data.content_type})
        response = session.post(url, data=data, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            auth_file_url.update({calc_md5(file_name): res_json['url']})
            return res_json['url']
        else:
            logger.error(f"授权文件上传失败，文件名：{file_name}，状态码：{response.status_code}")
            raise
    except:
        logger.error(f"授权文件上传失败，文件名：{file_name}")
        raise


def submit_c(res: dict):
    try:
        headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
        url = f'{host2}/hcTrade/suppurDistributionRelation/addDistributionRelationBid.html'
        response = session.post(url, data=res, headers=headers)
        if response.status_code == 200:
            res_json = json.loads(response.text)
            if not res_json['success'] or res_json['code'] != 0:
                if '撤废的产品配送关系' not in res_json['msg']:
                    logger.error(f"确定并添加失败，响应值：{response.text}")
                    raise Exception(res_json['msg'])
        else:
            logger.error(f"确定并添加失败，状态码：{response.status_code}")
            raise
    except:
        raise


def submit_finally(rela_id):
    try:
        url = f'{host2}/hcTrade/suppurDistributionRelationBid/updateDistributionRelationBid.html'
        rr = {'ids[]': rela_id, 'confirmStatus': 1}
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
    try:
        url = f'{host2}/hcTrade/suppurDistributionRelationBid/getDistributionRelationBidData.html?agreementId={agreement_id}'
        data = {'_search': False, 'nd': int(time.time() * 1000), 'rows': 10, 'page': 1, 'sidx': None, 'sord': 'asc',
                'hospitalName': hospital, 'goodsId': goods_id, 'goodsName': None, 'confirmStatus': None,
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
                    logger.error(f"配送关系查询结果为空或有多个，产品ID：{goods_id}，配送企业：{company}，响应值：{res_json['rows']}")
                    raise
        else:
            logger.error(f"配送关系查询失败，产品ID：{goods_id}，配送企业：{company}，状态码：{response.status_code}")
            raise
    except:
        raise


def calc_md5(data: str) -> str:
    hash_obj = hashlib.md5()
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()


def check_login():
    try:
        if os.path.exists(cookie_path):
            cookies_dict = json.load(open(cookie_path, 'r', encoding='utf-8'))
            coo = requests.cookies.RequestsCookieJar()
            for k, v in cookies_dict.items():
                coo.set(k, v)
            session.cookies.update(coo)
            headers.update({'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'})
            headers.update({'X-Requested-With': 'XMLHttpRequest'})
            headers.update({'Host': host2.split('/')[-1]})
            headers.update({'Referer': host2})
            url = f'{host2}/hcTrade/chatUser/getChatInitInfo.html'
            response = session.get(url, headers=headers)
            if response.status_code == 200:
                res_json = json.loads(response.text)
                if res_json['code'] == 0 and res_json['data']['mine']:
                    logger.info(f"免登陆成功，用户：{res_json['data']['mine']['username']}")
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
    except:
        logger.error(traceback.format_exc())
        return False


try:
    caCert = ''
    with open(os.path.join(current_path, 'config.txt'), 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for lin in lines:
            if 'caCert' in lin:
                caCert = lin.split('caCert')[-1].strip()[1:].strip()

    coo.set('headerShow', 'false')
    coo.set('SESSION_FLAG', '1')
    session.cookies.update(coo)
    if not check_login():
        access_token = None
        for _ in range(2):
            headers.update({"Host": host1.split('/')[-1], "Referer": host1})
            access_token = login(caCert)
            if access_token:
                break
            time.sleep(2)
        if not access_token:
            raise Exception("连续2次登陆失败，请重试")

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
            if '市平台产品ID' == table.cell_value(i, 7):
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
                    if is_jicai == '议价采购':
                        agreementType = '1'
                    elif is_jicai == '肝功生化类检测试剂':
                        agreementType = '27'
                    else:
                        raise Exception('协议类型不正确，仅支持 议价采购 和 肝功生化类检测试剂')
                    res = {}
                    company_md5 = calc_md5(company + agreementType)
                    if company_md5 in company_dict:
                        res.update({'agreementId': company_dict[company_md5]})
                    else:
                        res = query_company(company, agreementType, res)
                    res = query_hospital(hospital, res)
                    res = query_code(ms_code, agreementType, res)
                    auth_md5 = calc_md5(auth_file)
                    if auth_md5 in auth_file_url:
                        res.update({'authorUrl': auth_file_url[auth_md5]})
                    else:
                        res.update({'authorUrl': upload_file(auth_file)})
                    submit_c(res)
                    time.sleep(2)
                    relation_id = query_submit_list(ms_code, res['agreementId'], company, hospital)
                    if relation_id:
                        if relation_id in [1, 2, 3, 4]:
                            has_send += 1
                            if relation_id in [1, 2]:
                                logger.warning(f"已经配送过了，配送关系的状态为：{['', '已提交待配送方确认', '双方同意'][relation_id]}，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                            else:
                                logger.warning(f"配送关系的状态为：{['待提交', '已提交待配送方确认', '双方同意', '配送方拒绝', '已撤废'][relation_id]}，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                            continue
                        submit_finally(relation_id)
                        success += 1
                        logger.info(f"配送成功，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                    else:
                        logger.error(f"配送关系状态不正确，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
                except:
                    logger.error(traceback.format_exc())
                    logger.error(f"配送失败，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
            else:
                logger.error(f"Excel表格中的数据不全，产品ID：{ms_code}，配送企业：{company}，配送医院：{hospital}，协议类型：{is_jicai}，授权文件名：{auth_file}")
    logger.info(f"总数：{total_num}，配送成功：{success}，配送失败：{total_num - success - has_send}，已经配送：{has_send}")
except:
    logger.error("失败，请重试")
    logger.error(traceback.format_exc())

time.sleep(1)
g = input("按回车键继续...")
