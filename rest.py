#!/usr/bin/python
#coding=utf-8
import argparse
import requests,json
from requests.auth import HTTPBasicAuth
from subprocess import call
import time
import sys
import os

#控制器 = 192.168.1.5
#SFF    = 192.168.123.0
#SF     = 192.168.2.0

#os.system("docker run -itd --net=container:sf1 --privileged=true --name=firewall2 ubuntu14.04:firewall /bin/bash") 


controller='127.0.0.1'
DEFAULT_PORT='8080'

USERNAME='admin'
PASSWORD='admin'

#ip_dict={'ip_sf1':'192.168.1.30',
#         'ip_sf2':'192.168.1.40',
#         'ip_c1':'192.168.123.2',
#         'ip_c2':'192.168.123.3',
#         'ip_sff1':'192.168.123.4',
#         'ip_sff2':'192.168.123.5'}
ip_dict={'ip_sf1':'192.168.1.30',
         'ip_sf2':'192.168.1.40',
         'ip_c1':'127.0.0.1',
         'ip_c2':'127.0.0.1',
         'ip_sff1':'127.0.0.1',
         'ip_sff2':'127.0.0.1'}
         
def get(host, port, uri, debug=False):    #获取    #新增函数
    '''Perform a PUT rest operation, using the URL and data provided'''

    url='http://'+host+":"+port+uri

    headers = {'Content-type': 'application/yang.data+json',
               'Accept': 'application/yang.data+json'}
    if debug == True:
        print("GET %s" % url)
    r = requests.get(url, headers=headers, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    if debug == True:
        print r.text
    print "HTTP GET %s\nresult: %s" % (url, r.status_code)  #uri->url
    r.raise_for_status()
    time.sleep(5)
    
def put(host, port, uri, data, debug=False):  #修改
    '''Perform a PUT rest operation, using the URL and data provided'''

    url='http://'+host+":"+port+uri

    headers = {'Content-type': 'application/yang.data+json',
               'Accept': 'application/yang.data+json'}
    if debug == True:
        print("PUT %s" % url)
        print(json.dumps(data, indent=4, sort_keys=True))
    r = requests.put(url, data=json.dumps(data), headers=headers, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    if debug == True:
        print r.text
    print "HTTP PUT %s\nresult: %s" % (url, r.status_code)  #uri->url
    r.raise_for_status()
    time.sleep(5)

def post(host, port, uri, data, debug=False):   #增加
    '''Perform a POST rest operation, using the URL and data provided'''

    url='http://'+host+":"+port+uri
    headers = {'Content-type': 'application/yang.data+json',
               'Accept': 'application/yang.data+json'}
    if debug == True:
        print "POST %s" % url
        print json.dumps(data, indent=4, sort_keys=True)
    r = requests.post(url, data=json.dumps(data), headers=headers, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    if debug == True:
        print r.text
    print "HTTP POST %s\nresult: %s" % (url, r.status_code) #uri->url
    r.raise_for_status()
    time.sleep(5)
    
def get_uri():
#    return "/restconf/config/service-node:service-nodes"
#    return "/restconf/operational/opendaylight-inventory:nodes/node/openflow:1"
#    return "/stats/flow/1"
#    return "/stats/flowentry/modify" 
    return "/sfc_add_flow/10"

def get_data():
    return {
        "dpid": 1,
        "match":{
            "dl_dst": "00:00:00:00:00:02",
            "dl_src": "00:00:00:00:00:01",
            "in_port":1
        },
        "actions":[]
    }

if __name__ == "__main__":
    time_start = time.time()  #开始计时
    
    get(controller, DEFAULT_PORT, get_uri(), True)
    
    time_end = time.time()  #结束计时
    print "SFC Time Spent:%.4f" % (time_end-time_start), "s"
    
    
    
#    post(controller, DEFAULT_PORT, get_uri(), get_data(), True)
#    post(controller, DEFAULT_PORT, "/restconf/operations/service-function-forwarder-ovs:create-ovs-bridge", data, True)
    