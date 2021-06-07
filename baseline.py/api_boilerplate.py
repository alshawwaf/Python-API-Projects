#!/usr/bin/env python3
"""
prints out quick overview of threat-protections
with their FINAL action and track setting per profile
"""
import argparse
import csv
import logging
import sys

from cpapi import APIClient, APIClientArgs

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password", default="vpn123")
    parser.add_argument("-m", "--management", default="192.168.44.231")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("-o",
                        "--outfile",
                        default=sys.stdout,
                        help="Output file",
                        nargs="?",
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


        hosts = client.api_query("show-simple-gateways").data
        [print(host["name"]) for host in hosts]
        set_session = client.api_call("set-session", payload={"description": "test session"})
        print(f"Changed description: {set_session.data['description']}" if set_session.success else set_session.error_message)

        publish = client.api_call("publish")
        if not publish.success:
            print(publish.error_message)


if __name__ == "__main__":
    main()
