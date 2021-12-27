import requests
import json
import time
# import perturbation as p
import lief
import random
import numpy as np
import statistics
import pandas as pd

from multiprocessing import Pool, Process
import subprocess as sp

from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.common.by import By


apikeylist = open("vt_api_key").read().split("\n")[:-1]
apilen = len(apikeylist)

skip_key_list = ['base_address', 'cid', 'entropy', 'markcount', 'region_size', 'return_value',
        'severity', 'size_of_data', 'tid', 'time', 'type', 'virtual_address', 'virtual_size',
        'address', 'allocation_type', 'eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi',
        'information_class', 'instruction', 'instruction_r', 'last_error', 'return_value',
        'nt_status', 'privilege_name', 'stacktrace', 'system_name', 'buffer', 'command_line',
        'creation_flags', 'current_directory', 'exception_code', 'filepath', 'filepath_r',
        'inherit_handles', 'raw', 'status', 'thread_handle', 'thread_identifier', 'hook_identifier',
        'length', 'last_error', 'module_address', 'reg_value', 'reg_key', 'flags', 'family',
        'win32_protect', 'view_size', 'section_offset', 'section_handle', 'process_handle',
        'families', 'computer_name', 'commit_size', 'trck', 'oldfilepath_r', 'oldfilepath',
        'newfilepath_r', 'new_filepath', 'symbol', 'pid', 'offset', 'module', 'snapshot_handle',
        'process_name', 'show_type', 'console_handle', 'callback_function', 'newfilepath', 'size',
        'language', 'filetype', 'stack_pivoted', 'stack_dep_bypass', 'protection', 'process_identifier',
        'heap_dep_bypass', 'parameter', 'function_address', 'parameters', 'martian_process',
        'value', 'key_handle', 'crypto_export_handle', 'blob_type', 'size', 'sublanguage',
        'status_info', 'share_access', 'file_attributes', 'desired_access', 'create_options',
        'create_disposition']

def send_to_sandbox(fname):
    sburl = "http://localhost:8090/tasks/create/file"
    data = {'timeout': '30'}
    with open(fname,'rb') as sample:
        files = {"file": (fname,sample)}
        header = {"Authorization": "Bearer cuckoo"}
        r = requests.post(sburl, data=data, files=files, headers=header)

    if r.status_code == 200:
        return r.json()

    return false

def send_to_sandbox5(fname,port):
    sburl = "http://localhost:"+port+"/tasks/create/file"
    data = {'timeout': '30'}
    with open(fname,'rb') as sample:
        files = {"file": (fname,sample)}
        header = {"Authorization": "Bearer cuckoo"}
        r = requests.post(sburl, data=data, files=files, headers=header)

    if r.status_code == 200:
        return r.json()

    return false

def status(taskid):
    spurl = "http://localhost:8090/tasks/view/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    r = requests.get(spurl+str(taskid), headers=header)
    return r.json()

def status5(taskid,port):
    spurl = "http://localhost:"+port+"/tasks/view/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    r = requests.get(spurl+str(taskid), headers=header)
    return r.json()

def get_cuckoo_report(fname):
    rpurl = "http://localhost:8090/tasks/report/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    taskid = send_to_sandbox(fname)["task_id"]

    while status(taskid)['task']['status'] != "reported":
        time.sleep(10)


    r = requests.get(rpurl+str(taskid), headers=header)
    return r.json()

def get_cuckoo_report5(fname_port):
    fname, port = tuple(fname_port.split("||"))
    rpurl = "http://localhost:"+port+"/tasks/report/"
    data = {'timeout': '30'}
    header = {"Authorization": "Bearer cuckoo"}

    taskid = send_to_sandbox5(fname,port)["task_id"]

    # print (fname, port, taskid)

    while True:
        try:
            st = status5(taskid,port)['task']['status'] 
            if st == "reported":
                break
        except:
            pass
        time.sleep(10)
    # time.sleep(3)

    r = requests.get(rpurl+str(taskid), headers=header)
    return r.json()

def send_vt_scan(fpath, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': ('myfile.exe', open(fpath, 'rb'))}
    response = requests.post(url, files=files, params=params)
    return response.json()["md5"]
    # pass


def get_vt_report(hashvalue,apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': hashvalue}
    response = requests.get(url, params=params)
    # status = response.json()["response_code"]
    
    return response.json()

def vt_analysis_prev(filehash):
    random.seed(None)
    i = random.randrange(0,apilen)
    # print (apikeylist[i])
    #scan = send_vt_scan(fpath,apikeylist[i])
    #filehash = scan["md5"]
    max_time = 70
    t = 0
    while True:
        i = (i+1)%apilen
        vt_report = get_vt_report(filehash, apikeylist[i])
        if vt_report["response_code"] == 1:
            vt_result = vt_report["positives"]/vt_report["total"]
            break
        time.sleep(25)
        t+=25
        if t > max_time:
            return 1.0, []

    detected = [data for data in vt_report["scans"].keys() if vt_report["scans"][data]["detected"]]

    return vt_result, detected # vt_report


def vt_analysis(filehash):
    hashvalue = filehash 
    url = "https://www.virustotal.com/gui/file/"+hashvalue+"/detection"

    disp = Display().start()

    driver = webdriver.Chrome(executable_path='./chromedriver')
    driver.get(url=url)
    driver.implicitly_wait(20)

    root = driver.find_element(By.CSS_SELECTOR,"file-view") # root element
    shadowdom1 = driver.execute_script("return arguments[0].shadowRoot",root)
    element1 = shadowdom1.find_element(By.TAG_NAME, "vt-ui-detections-list")
    shadowdom2 = driver.execute_script("return arguments[0].shadowRoot",element1)
    detections = shadowdom2.find_elements(By.CLASS_NAME, "detection")

    detected = []
    undetected = []
    for detection in detections:
        d = detection.text.split("\n")
        if len(d) == 1:
            continue
        elif d[1] == "Unable to process file type":
            continue

        if d[1] == "Undetected":
            undetected.append(d[0])
        else:
            detected.append(d[0])
    
    if (len(detected) + len(undetected) == 0) or len(detected) == 0 or len(detected) + len(undetected) < 60:
        driver.quit()
        disp.stop()        
        return vt_analysis_prev(filehash)


    vt_result = len(detected)/(len(detected)+len(undetected))
    
    driver.quit()
    disp.stop()

    return vt_result, detected


def parse_key(json_data, key_list):
    for key in json_data.keys():
        if isinstance(json_data[key], dict):
            key_list = parse_key(json_data[key], key_list)
        elif isinstance(json_data[key], list):
            for value in json_data[key]:
                if isinstance(value, dict):
                    key_list = parse_key(value, key_list)
                else:
                    if key + '-' + str(value) not in key_list:
                        key_list[key + '-' + str(value)] = 1
                    else:
                        key_list[key + '-' + str(value)] += 1
        else:
            if key + '-' + str(json_data[key]) not in key_list:
                key_list[key + '-' + str(json_data[key])] = 1
            else:
                key_list[key + '-' + str(json_data[key])] += 1
    return key_list

def parse_report(json_data):
    # with open(report_name) as json_file:
    #     json_data = json.load(json_file)
    key_list = []
    for lists in json_data['signatures']:
        key_list += list(parse_key(lists, {}).keys())

    # print (key_list)
    # print ("")

    return set(key_list)

def get_super_set(reports):
    super_set = set()
    
    for report in reports:
        super_set = super_set | parse_report(report)

    return list(super_set)

def search_file_name(s):
    for i in range(len(s)-1,-1,-1):
        if s[i] == "/":
            return s[i+1:]
    return s

def check_sig_set(signatures):
    sigs = []
    for sig in signatures:
        
        if sig["severity"] > 1:
            sigs.append(sig["description"])

    return set(sigs)


# origin = json report, target = filename
def func_check(origin_sig,target):
    target_sig = get_cuckoo_report(target)["signatures"]
    
    osig = check_sig_set(origin_sig)
    tsig = check_sig_set(target_sig)

    total = osig | tsig
    match = osig & tsig

    if len(match)/len(total) > 0.6:
        return True
    else:
        return False


def func_check_superset(origin_obj,target):
    # target_sig = get_cuckoo_report(target)["signatures"]
    # print (target)
    t_name = search_file_name(target)
    o_name = search_file_name(origin_obj.name)
    origin_super_set = origin_obj.superset
    args = [target+"||"+str(i) for i in range(8091,8096)]

    stime = time.time()

    with Pool(5) as p:
        reports = p.map(get_cuckoo_report5, args)
        target_set = get_super_set(reports)
    
    for i in range(len(origin_super_set)):
        if o_name in origin_super_set[i]:
            origin_super_set[i] = origin_super_set[i].replace(o_name,"")

    for i in range(len(target_set)):
        if t_name in target_set[i]:
            target_set[i] = target_set[i].replace(t_name,"")

    return set(target_set).issuperset(set(origin_super_set))

