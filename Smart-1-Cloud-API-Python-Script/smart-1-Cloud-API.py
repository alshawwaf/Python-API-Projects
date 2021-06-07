#!/usr/bin/env python3
"""
"""

import argparse
import requests
import json
import logging

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help=""" 
                        The commands are listed in the swagger
                        https://app.swaggerhub.com/apis-docs/Check-Point/smart-1_cloud_api/1.0.0#/Authentication/getAuthToken
                        """)
    parser.add_argument("-i", "--clientid", required=True)
    parser.add_argument("-n", "--name")
    parser.add_argument("-k", "--password", required=True)
    parsed_args = parser.parse_args()


    URL = "https://cloudinfra-gw.portal.checkpoint.com"
    auth = f"{URL}/auth/external"
    mgmt_service=f"{URL}/mgmt-service"
    gateways=f"{URL}/app/maas/api/v1/gateways"
    gateway=f"{URL}/app/maas/api/v1/gateways/{parsed_args.name}"

    payload = json.dumps({
    "clientId": parsed_args.clientid,
    "accessKey": parsed_args.password
    })
    headers = {
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", auth, headers=headers, data=payload)

    token = response.json()['data']['token']

    if parsed_args.command == 'show_all':
        payload={}
        headers = {
        'Content-Type': 'application/json',
        'Authorization': f"Bearer {token}" 
        }

        response = requests.request("GET", gateways, headers=headers, data=payload)

        for gateway in response.json()['data']['objects']:
            print (gateway['name'], gateway['statusDetails'])

    if parsed_args.command == 'register':
        if not parsed_args.name:
            print("The Gateway name is required, please specify the -n flag.")
        else:    
            payload=json.dumps({
                    "name":parsed_args.name,
                    "description":"Added using Python API script"})
            headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {token}" 
            }

            response = requests.request("POST", gateways, headers=headers, data=payload)

            print(response.json()['data']['token'],end="")

    if parsed_args.command == 'delete':
        if not parsed_args.name:
            print("The Gateway name is required, please specify the -n flag.")
        else:    
            headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {token}" 
            }

            response = requests.request("DELETE", gateway, headers=headers)

            print(response.text)

if __name__ == '__main__':
    main()