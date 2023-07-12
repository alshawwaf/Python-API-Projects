#!/usr/bin/env python3
"""
This script reads rules from a CSV file and creates an ansible playbook to add those rules.

Source,Destination,Protocol(s),Rule Documentation,Owner,Notes,Description
Src_objects, dedtination_object,	IP,	JIRA 1234,	Note,	Approved by James, First rule Test 
Any,	Local SA Subnet,	TCP-80,	JIRA 4321,	Note2,	Approved by Jeff,	Local SE Subnet.

python -m venv venv
python -m pip install cp-mgmt-api-sdk
"""

import argparse
import csv
import logging
import sys
import yaml

from cpapi import APIClient, APIClientArgs
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password", default="vpn123")
    parser.add_argument("-m", "--management", default="203.0.113.100")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("-l", "--package", default="SA-Rules")
    
    parser.add_argument("-i",
                        "--inputfile",
                        default="sa-rules.csv",
                        help="input file",
                        type=argparse.FileType("r"))
    parser.add_argument("-o",
                        "--outputfile",
                        default=sys.stdout,
                        help="Output file",
                        type=argparse.FileType("w"))
    parsed_args = parser.parse_args()

    client_args = APIClientArgs(server=parsed_args.management)
    
    with APIClient(client_args) as client:

        login = client.login(username=parsed_args.username,
                             password=parsed_args.password,
                             domain=parsed_args.domain)
        if login.success:
            log.info("login succeeded")
        else:
            log.error(login.error_message)
            sys.exit(1)

        rules = []
        csv_reader = csv.DictReader(parsed_args.inputfile)
        for row in csv_reader:
            if row['Source']:
                rules.append(row)
           
        src= set()
        dst= set()
        services= set()   
        tasks=[]

        for position,rule in enumerate(rules[::-1]):
            
            src_split=[k.strip() for k in rule['Source'].split(",")]
            if "any" in [k.lower() for k in src_split]:
                src_split = "Any"
            else:
                for item in src_split:
                    
                    src.add(item.upper())
                
            dst_split=[k.strip() for k in rule['Destination'].split(",")]
            if "any" in [k.lower() for k in dst_split]:
                dst_split = "Any"
            else:
                for item in dst_split:
                    dst.add(item.upper())
            services_split=[k.strip() for k in rule['Protocol(s)'].split(",")]
            if "any" in [k.lower() for k in services_split]:
                services_split = "Any"
            else:
                for item in services_split:
                    services.add(item.upper())
            
            
            
                                                
            comments = f" {rule['Rule Documentation']} {rule['Owner']} {rule['Notes']} {rule['Description']}"
            rules_template={"name": f"task for {rule['Rule Documentation']} ",
                            "check_point.mgmt.cp_mgmt_access_rule": {
                            "layer": f"{parsed_args.package} Network",
                            "name": rule['Rule Documentation'] + " - " +str(position),
                            "position": f"{position+1}",
                            "source": src_split,
                            "destination": dst_split,
                            "service": services_split,
                            "track": {"type":"Log"},
                            "action": "Accept",
                            "comments" : comments
                            },
            }
            tasks.append(rules_template)
            
        playbook = f"""
- name: playbook to create Check Point Rules using Ansible
  connection: httpapi
  hosts: {parsed_args.management}
  gather_facts: False
  tasks:
    - name: Include rules tasks created from the csv file
      import_tasks: {parsed_args.outputfile.name}
        """
        f = open("playbook.yml", "w")
        f.write(playbook)
        f.close()

        yaml.dump(tasks, parsed_args.outputfile, sort_keys=False, line_break=2)

        for service in services:
            if "tcp" in str(service).lower():     
                tcp_response = client.api_call("show-service-tcp",
                                payload={
                                    "name": service,
                                    })   
                if tcp_response.success:
                    log.debug(f"Service {service} already exists")
                elif tcp_response.data['code'] == "generic_err_object_not_found":    
                    comma_split = str(service).split(",")
                    for item in comma_split:
                        if  "-" in  str(item):
                            tcp_split = str(item).split("-", maxsplit=1)
                        
                            add_tcp_service = client.api_call("add-service-tcp",
                                        payload={
                                            "name": item,
                                            "port": tcp_split[1],
                                            "ignore-warnings":"true"
                                            }) 
                            if not add_tcp_service.success:
                                log.error(f"failed to add TCP service {item}:  {add_tcp_service}")
                        else:
                            log.error(f"{service} service does not have a port in the service name.")    
            elif "udp" in str(service).lower():     
                udp_response = client.api_call("show-service-udp",
                                payload={
                                    "name": service,
                                    })   
                if udp_response.success:
                    log.debug(f"Service {service} already exists")
                elif udp_response.data['code'] == "generic_err_object_not_found":    
                    comma_split = str(service).split(",")
                    for item in comma_split:
                        if  "-" in  str(item):
                            udp_split = str(item).split("-", maxsplit=1)
                        
                            add_udp_service = client.api_call("add-service-udp",
                                        payload={
                                            "name": item,
                                            "port": udp_split[1],
                                            "ignore-warnings":"true"
                                        })
                            if not add_udp_service.success:
                                log.error(f"failed to add UDP service {item}:  {add_udp_service}")
                        else:
                            log.error(f"{service} service does not have a port in the service name.")    
            else:
                log.warning(f"{service} is not a TCP or UDP service.")
                                    
        for item in src | dst:
            if item.upper() != "any":
                group_response = client.api_call("show-group",
                                payload={
                                    "name": item,
                                    })   
                if group_response.success:
                    log.debug(f"Object {item} already exists")
                elif group_response.data['code'] == "generic_err_object_not_found":    
                        
                    client.api_call("add-group",
                                payload={
                                    "name": item,
                                    }) 
                                    
        print("Publishing changes...")
        publish = client.api_call("publish")
        if not publish.success:
            print(publish.error_message)  
            
if __name__ == "__main__":
    main()
