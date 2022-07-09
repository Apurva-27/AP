#           Copyright (C) 2021 NEC CORPORATION
#
# ALL RIGHTS RESERVED BY NEC CORPORATION, THIS PROGRAM
# MUST BE USED SOLELY FOR THE PURPOSE FOR WHICH IT WAS
# FURNISHED BY NEC CORPORATION, NO PART OF THIS PROGRAM
# MAY BE REPRODUCED OR DISCLOSED TO OTHERS, IN ANY FORM
# WITHOUT THE PRIOR WRITTEN PERMISSION OF NEC CORPORATION.
# USE OF COPYRIGHT NOTICE DOES NOT EVIDENCE PUBLICATION
# OF THE PROGRAM
#
#            NEC CONFIDENTIAL AND PROPRIETARY
#


from datetime import datetime
from optparse import OptionParser
from winrm.exceptions import WinRMError, WinRMTransportError
from winrm.exceptions import WinRMOperationTimeoutError

import argparse
import sys
import winrm
import json
import commands
import glob
import logging
import os
import subprocess
import tempfile
import re
import time
import csv
import base64

logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s',
                    level=logging.INFO)
logging.info("-------------------------------------------------")
logging.info('Execution started of createHyperV.py')
logging.info("-------------------------------------------------")
# Static Parameters definition for file name
param_csv_file_name = 'param.csv'
parameter_csv_file_name = 'parameters.csv'
# Parameters definition for write parameters.csv
WRITE_CSV = '''$IMPORT_BLOCK = {
    $b64txt="%s"
    $byte = [System.Convert]::FromBase64String($b64txt)
    $txt = [System.Text.Encoding]::Default.GetString($byte)
    cd $env:temp
    Write-Output $txt | Add-Content parameters.csv
}
Invoke-Command -ScriptBlock $IMPORT_BLOCK | ConvertTo-Json
'''.strip()
# Define parameter to reboot the vm
START_REBOOT = '''
shutdown -r -f -t 1
'''.strip()
# Define parameter to create scripts for domain joning
ADD_COMPUTER = '''$ADD_COMPUTER_BLOCK = {
    $SECURE_STRING = ConvertTo-SecureString %s -AsPlainText -Force
    $CRED = New-Object System.Management.Automation.PsCredential("%s", $SECURE_STRING)
    if ( $? -ne $true ) {
        Write-Error "Failed to make credential."
        exit 1
    }
    Add-Computer -Domain %s -Credential $CRED
    if ( $? -ne $true ) {
        Write-Error "Failed to join domain."
        exit 1
    }
}
Invoke-Command -ScriptBlock $ADD_COMPUTER_BLOCK | ConvertTo-Json
'''.strip()
# Define function to sorts and converts list type parameters that are divided 
# into pieces into a list state that can be called by a key
def parse_list_parameters(parameters):
    '''
    Sorts and converts list type parameters that are divided 
    into pieces into a list state that can be called by a key. 
    It is assumed that the list type parameter is received in the following form. 

    "ListVal[0].StringVal":"Value"

    Parameters
    ----------
    elements : parameters
        construction parameters
    Returns
    -------
    constructed parameters that return list type parameters : list
    '''
    # Define variable to store the parameters
    elements = []
    for name in parameters.keys():
        if re.search(r'\[[0-9]+\]\.', name):
            logging.info("match")
            values = re.split('[\[\.]',name.replace(']', '').encode('utf-8'))
            element = {}
            element['number'] = values[1]
            value = parameters[name]
            if type(value) is not int and type(value) is not list:
                element['value'] = value.encode('utf-8')
            else:
                element['value'] = value
            element['child']  = values[2]
            element['parent']  = values[0]
            elements.append(element)
    parsed = parse_values(elements)
    aligned = align_list(parsed)
    for key in aligned.keys():
        parameters[key] = aligned[key]
    return parameters
# Define function to sort the inside of the list type parameter by ordinal number for each key
def align_list(parsed):
    '''
    Sort the inside of the list type parameter by ordinal number for each key. 
    Parameters
    ----------
    parsed : dict
        List type parameters divided by key  
    Returns
    -------
    the Listed parameters that have been sorted : dict
    '''
    aligned = {}
    for key in parsed.keys():
        params = parsed[key]
        items = []
        sorted_params = sorted(params.items())
        for number, params in sorted_params:
            items.append(params)
        aligned[key] = items
    return aligned
# Define function to sort list parameters by order with the original parameters
def parse_values(elements):
    '''
    Sort list parameters by order with the original parameters. 
    Assume a list type parameter converted into the following form. 
    {
        "parent":"ListVal",
        "number": "0",
        "child":"StringVal",
        "value":"Value"
    }
    Parameters
    ----------
    elements : dict
        Decomposition of list type parameters 
    Returns
    -------
    the dict object for each parameter identifier  : dict
    '''
    parsed = {}
    for element in elements:
        logging.info("element : %s" % element)
        parent = element['parent']
        if parent in parsed:
            values = parsed[parent]
        else:
            values = {}
        logging.info("values : %s" % values)
        number = element['number']
        if number in values:
            childs = values[number]
        else:
            childs = {}
        childs[element['child']] = element['value']
        values[number] = childs
        parsed[parent] = values
    return parsed
# Define function to get vm resource information
def get_resource_info(conn, parameters, services, nodes):
    '''
    Get a virtual machine to Hyper-V host server.
    Use the following Powershell Cmdlet to get the information. 
    Parameters
    ----------
    conn : dict
        a dict contains the connection information (host, port number, 
        user name, password, and authentication method)
    parameters : dict
        a construction parameter
    services : dict
        a service information defined in the service definition file  
    nodes : dict
        a resource definition information defined in the resource definition file 
    Returns
    -------
    the imported VM information : dict
    '''
    # Define resources variables that is used to store vm configuration paraemters
    resources = []
    virtual_machines = parameters["VirtualMachines"]
    for virtual_machine in virtual_machines:
        # Get parameters from orchestration-service.json
        # parameters releated to vm authentication configuration
        auth = {}
        auth["Type"] = "password"
        auth["User"] = services['Domain']['user'] + "@" + virtual_machine["domainname"]
        auth["Password"] = services['Domain']['password'] 
        auth["transport"] = "kerberos"
        auth["Transport"] = "kerberos"
        logging.info("-------------------------------------------------") 
        logging.info("Auth Type                   : %s", auth["Type"]) 
        logging.info("User                        : %s", auth["User"]) 
        logging.info("transport                   : %s", auth["transport"])
        logging.info("-------------------------------------------------")
        # parameters related to network configuration
        connection = {}
        connection["Ip"] = virtual_machine["vmhostname"]
        connection["Protocol"] = services['WindowsVM']['Connection']['Protocol']
        connection["Port"] =  str(services['WindowsVM']['Connection']['Port'])
        logging.info("-------------------------------------------------") 
        logging.info("IP Address                   : %s", connection["Ip"]) 
        logging.info("Connection Protocol          : %s", connection["Protocol"]) 
        logging.info("Port                         : %s", connection["Port"])
        logging.info("-------------------------------------------------")
        # Get parameters from orchestration-service.json
        # parameters releated to vm os configuration
        resource = {}
        resource["Name"] = virtual_machine["__ID"]
        resource["Architecture"] = services['WindowsVM']['Architecture']
        resource["Platform"] = services['WindowsVM']['Platform']
        logging.info("-------------------------------------------------") 
        logging.info("Name                   : %s", resource["Name"]) 
        logging.info("Archtecture            : %s", resource["Architecture"]) 
        logging.info("Plateform           : %s", resource["Platform"])
        logging.info("-------------------------------------------------")
        resource["Auth"] = auth
        resource["Connection"] = connection
        resources.append(resource)
    return resources
logging.info("-------------------------------------------------")
logging.info('Execution started of main method to create resource')
logging.info("-------------------------------------------------")
# Calling main method for resource creation
if __name__ == '__main__':
    args = sys.argv
    parser = argparse.ArgumentParser(usage='usage: %prog [OPTIONS] SIZE_PARAMETER PARAMETER RESOURCES')
    parser.add_argument("-d", '--working-dir',
                         help='Working directory for this script')
    parser.add_argument("-o", '--output-dir',
                         help='Output destination directory of result information file')
    parser.add_argument("-s", '--service-file',
                         help='Processing service definition file ')
    parser.add_argument("-n", '--node-file',
                         help='Processing node definition file ')
    parser.add_argument('size_file',
                         help='Size parameter file')
    parser.add_argument('parameter_file',
                         help='Construction parameter file')
    if len(args) == 12 :
        parser.add_argument('resouce_file', help='Resources file')
    args = parser.parse_args()
    work_dir = args.working_dir
    out_dir = args.output_dir
    service_file = args.service_file
    node_file = args.node_file
    size_file = args.size_file
    parameter_file = args.parameter_file
    logging.info("-------------------------------------------------") 
    logging.info("work_dir                   : %s", work_dir) 
    logging.info("out_dir                    : %s", out_dir) 
    logging.info("service_file               : %s", service_file) 
    logging.info("node_file                  : %s", node_file) 
    logging.info("size_file                  : %s", size_file) 
    logging.info("parameter_file             : %s", parameter_file) 
    logging.info("-------------------------------------------------") 
    logging.info("open service_file json : %s", service_file) 
    with open(service_file, 'r') as service_json:
        services = json.load(service_json)
    logging.info("open node_file json : %s", node_file) 
    with open(node_file, 'r') as node_json:
        nodes = json.load(node_json)
    logging.info("open node_file json : %s", size_file) 
    with open(size_file, 'r') as size_json:
        sizes = json.load(size_json)
    logging.info("open parameter_file json : %s", parameter_file) 
    with open(parameter_file, 'r') as parameter_json:
        parameters = json.load(parameter_json)
    parameters = parse_list_parameters(parameters)
    parameter_file_open = open(parameter_file, 'r')
    parameter_json = json.load(parameter_file_open)
    try:
        # time the start time of this script 
        start_time = datetime.now()
        # target hyper-v machine
        conn = {}
        conn['host'] = parameter_json["__HYPERV_SERVER_HOST"]
        conn['port']   = 5985
        conn['user']   = parameter_json["__HYPERV_USER_NAME"]
        conn['passwd'] = parameter_json["__HYPERV_USER_PASSWORD"]
        conn['method'] = "kerberos"
        domain_conn = services['Domain']
        host = conn['host']
        logging.info("-------------------------------------------------") 
        logging.info("Hyper-V Server Hostname : %s", conn['host']) 
        logging.info("Port                    : %s", conn['port']) 
        logging.info("User                    : %s", conn['user']) 
        logging.info("method                  : %s", conn['method'])
        logging.info("Domain                  : %s", domain_conn)
        logging.info("-------------------------------------------------") 
        # Domain controller information
        # Domain controller information
        # Generate KerberOS ticket for domain user.
        domain_user= conn['user'] + "@" + domain_conn['name']
        cmd = ['kinit', domain_user]
        passwd = conn['passwd']
        encoded_passwd = passwd.encode('utf-8', 'strict')
        logging.info('execute: %s' % ' '.join(cmd))
        proc = subprocess.Popen(['kinit', domain_user],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate(encoded_passwd + b'\n')
        logging.info('STDOUT: %s' % stdout)
        logging.warn('STDERR: %s' % stderr)
        # Create winrm connection with Hyper-V Server
        hyperv_host_s = winrm.Session(conn['host'], auth=(domain_user, conn['passwd']), transport="kerberos")
        # Remove parameters.csv file on Hyper-V Server if exists
        retval = hyperv_host_s.run_ps('cd $env:temp; Remove-Item parameters.csv')
        logging.info(retval)
        # Create parameters.csv file
        logging.info("write csv to work_dir")
        with open(work_dir + '/' + 'param.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerow(["vmname","memory","cpu","disksize","vswitchname","gateway","ipaddr","subnet","dns","templatepath","vhdsourcepath","vhddestinationpath","assetname","hddtype","vlan","gen","domainname","username","passwd"])
            virtual_machines = parameters["VirtualMachines"]
            # Get parameters from environment_parameter.json
            for vm in virtual_machines:
                vmname=str(vm["vmname"])
                vmhostname=str(vm["vmhostname"])
                memory=str(vm["memory"])
                cpu=str(vm["cpu"])
                disksize=str(vm["disksize"])
                vswitchname=str(vm["vswitchname"])
                gateway=str(vm["gateway"])
                ipaddr=str(vm["ipadd"])
                subnet=str(vm["subnet"])
                dns=str(vm["dns"])
                templatepath=str(vm["templatepath"])
                vhdsourcepath=str(vm["vhdsourcepath"])
                vhddestinationpath=str(vm["vhddestinationpath"])
                assetname=str(vm["assetname"])
                hddtype=str(vm["hddtype"])
                vlan=str(vm["vlan"])
                gen=str(vm["gen"])
                domainname=str(vm["domainname"])
                username=str(vm["username"])
                passwd=str(vm["passwd"])
                writer.writerow([vmname,memory,cpu,disksize,vswitchname,gateway,ipaddr,subnet,dns,templatepath,vhdsourcepath,vhddestinationpath,assetname,hddtype,vlan,gen,domainname,username,passwd])
        # write parameters.csv to Hyper-V Server
        logging.info("write csv to Hyper-V host")
        with open(work_dir + '/' + 'param.csv') as f:
            for line in f.readlines():
                line = line.rstrip()
                logging.info(line)
                write_csv_script = WRITE_CSV % ( base64.b64encode(line.encode()) )    
                logging.info(write_csv_script)
                retval = hyperv_host_s.run_ps(write_csv_script)
                logging.info(retval)
        # import Hyper-v machine
        logging.info("import_vm")
        retval = hyperv_host_s.run_ps('cd $env:temp;.\hyperv_script.ps1')
        # Please adjust your environment
        time.sleep(360)
        # Verify whether vm is accessible
        resouce_info = {}
        resouce_info["Resources"] = get_resource_info(conn, parameters, services, nodes)
        ip_address = resouce_info["Resources"][0]["Connection"]["Ip"]
        #response = 1
        #while response!=0:
        #    response=os.system("ping -c 1 " + ip_address)
        #logging.info("System Response : "+str(response))
        #######################################################
        # add a target machine to domain
        #######################################################
        # create PowerShell Script to join vm into the domain
        add_script = ADD_COMPUTER % (domain_conn['password'], domain_conn['user'] + '@' + domain_conn['name'], domain_conn['name'])
        logging.info("Join domain Script: %s" % add_script)
        # Join each vm into the domain
        for vm in virtual_machines:
            user = domain_conn['user'] + '@' + domain_conn['name']
            passwd = domain_conn['password']
            hyperv_guest_s = winrm.Session(vm["ipadd"], auth=(vm["username"], vm["passwd"]), transport="ntlm")
            logging.info("ipaddr : %s" % vm["ipadd"])
            logging.info("local user : %s" % vm["username"])
            logging.info("local passwd : %s" % vm["passwd"])
            r = hyperv_guest_s.run_ps('date')
            logging.info("Connection test Ret: %s" % r.status_code)
            r = hyperv_guest_s.run_ps(add_script)
            logging.info("Join domain Script Ret: %s" % r.status_code)
            r = hyperv_guest_s.run_ps("Enable-NetFirewallRule -Name WINRM-HTTP-In-TCP-NoScope")
            logging.info("Enable-NetFirewallRule Ret: %s" % r.status_code)
            r = hyperv_guest_s.run_cmd(START_REBOOT)
            time.sleep(300)
            logging.info("Reboot Ret: %s" % r.status_code)
        resouce_info = {}
        logging.info("get_resource_info")
        resouce_info["Resources"] = get_resource_info(conn, parameters, services, nodes)
        result_file = os.path.join(out_dir, 'result.json')
        logging.info("result_file : %s" % result_file)
        with open(result_file, 'w') as fp:
            json.dump(resouce_info, fp, indent=2)
    except (WinRMTransportError, WinRMOperationTimeoutError, WinRMError) :
        logging.fatal('Failed to describe VM', exc_info=True)
        exit(255)
    except RuntimeError:
        logging.fatal('Failed to describe VM', exc_info=True)
        exit(1)
    finally:
        elapsed_time = datetime.now() - start_time
        logging.info('Elapsed Time: %s' % str(elapsed_time))
    logging.info("-------------------------------------------------")
    logging.info('Execution ended of createHyperV.py')
    logging.info("-------------------------------------------------")