#!/usr/bin/env python3

""" 
python -m pip install --upgrade pip
* create a virtual environment
python -m venv .venv 
* Install Requirements
python -m pip install colorama
* Install the Python SDK
python -m pip install cp-mgmt-api-sdk
"""
import argparse
import logging
import sys
from colorama import Fore, Back, Style
from time import sleep
from tqdm import tqdm
from cpapi import APIClient, APIClientArgs

# logging.basicConfig(
# filename="cp_se_lookup.log",
# filemode="a",
# format="%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s",
# datefmt="%Y-%m-%d %H:%M:%S",
# level=logging.DEBUG,
# )
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password", default="Cpwins!1")
    parser.add_argument("-m", "--management", default="10.1.1.100")
    parser.add_argument("-d", "--domain", default="")
    parser.add_argument("-c", "--cve", default="")
    parser.add_argument(
        "-o",
        "--outfile",
        default=sys.stdout,
        help="Output file",
        nargs="?",
        type=argparse.FileType("w"),
    )
    parsed_args = parser.parse_args()

    client_args = APIClientArgs(server=parsed_args.management)
    with APIClient(client_args) as client:

        login = client.login(
            username=parsed_args.username,
            password=parsed_args.password,
            domain=parsed_args.domain,
        )
        if login.success:
            log.info(" login succeeded")
        else:
            log.error(login.error_message)
            sys.exit(1)

        # Show IPS status
        ips_status = client.api_call("show-ips-status", payload={})
        if ips_status.success:
            log.info(
                Fore.LIGHTYELLOW_EX
                + f" Installed Version: {ips_status.data['installed-version']}"
                + Fore.RESET
            )
            log.info(
                Fore.LIGHTYELLOW_EX
                + f" Installed Version Creation Time: {ips_status.data['installed-version-creation-time']}"
                + Fore.RESET
            )
            log.info(
                Fore.LIGHTYELLOW_EX
                + f" Update Available: {ips_status.data['update-available']}"
                + Fore.RESET
            )
            if ips_status.data["update-available"] is True:
                log.warning(
                    Fore.RED
                    + " An update is available, consider updating your IPS database"
                    + Fore.RESET
                )
        else:
            log.error(ips_status.error_message)

        # Show IPS Protections, we have over 16K protections, we need to pull every 500 protections in each API call
        protections_list = []
        done = False
        offset = 0
        cve = parsed_args.cve

        # CVE is required. exit if not provided
        if not cve:
            log.error(Fore.RED + " Please Provide the CVE number")
            sys.exit(1)

        # Pull all Threat (IPS) protections and save them in a list
        while not done:

            # The maximum number of objects returned by the API is 500
            threat_protections = client.api_call(
                "show-threat-protections",
                payload={"limit": 500, "offset": offset, "details-level": "full"},
            ).data

            if threat_protections["total"] == 0:
                done = True
                log.info(f"No protections found")
                break

            if threat_protections["total"] > threat_protections["to"]:
                offset = int(threat_protections["to"])
                from_position = int(threat_protections["from"])
                total = threat_protections["total"]

                # Remove the blue color style

            else:
                done = True

            protections_list.append(threat_protections["protections"])

            log.info(
                Fore.CYAN
                + " Pulling Protections From the Management Database ..."
                + Fore.RESET
            )

        # sleep(random.uniform(0.01, 0.1))

        # Show Threat Profiles
        threat_profiles = client.api_call(
            "show-threat-profiles",
            payload={"limit": 100, "offset": 0, "details-level": "full"},
        )
        if not threat_profiles.success:
            log.error(Fore.RED + threat_profiles.error_message + Fore.RESET)

        profiles_with_ips = []
        for profile in threat_profiles.data["profiles"]:
            # Skip Profiles where IPS blade is unchecked.
            if profile["ips"] == False:
                log.warning(
                    Fore.LIGHTYELLOW_EX
                    + f"IPS blade is disabled. Profile: {profile['name']}"
                    + Fore.RESET
                )
                break
            profiles_with_ips.append(profile)

            # print_as_table( activation_settings_per_profile, title=f"{profile['name']} Profile Settings",)

        # use the function defined below lookup the CVE from the protection list
        protection = match_cve_to_protection(cve, protections_list)

        profiles = profiles_with_ips

        # See if the Protection is enabled in the existing profiles based on the policy of each profile
        policy_decision_per_profile = protection_activation_per_profile(
            protection, profiles
        )

        print_as_table(policy_decision_per_profile, title="Policy Per Profile")

        # Find out which gateway is assigned to which profile
        threat_rulebase = client.api_call(
            "show-threat-rulebase",
            payload={
                "name": "Standard Threat Prevention",
                "offset": 0,
                "limit": 20,
                "details-level": "standard",
                "use-object-dictionary": "false",
                # "filter": f"{profile['name']}",
            },
        )

        # Get the Policy Decision
        rulebase_decision = []
        for threat_rule in threat_rulebase.data["rulebase"]:
            rule_number = threat_rule["rule-number"]
            rule_action = threat_rule["action"]["name"]
            rule_targets = []
            for target in threat_rule["install-on"]:
                rule_targets.append(target["name"])
            rule = {
                "Rule Number": rule_number,
                "Profile": rule_action,
                "Targets": rule_targets,
                "Activation": policy_decision_per_profile[
                    threat_rule["action"]["name"]
                ],
            }
            rulebase_decision.append(rule)
        for rule in rulebase_decision:
            print_as_table(rule, title="Policy Decision")


def match_cve_to_protection(cve, protections_list):
    for protection_list in protections_list:
        for protection in protection_list:

            if protection.get("industry-reference") is None:
                log.debug(
                    Fore.LIGHTYELLOW_EX
                    + f" The protection {protection['name']} does not have CVE assigned, returning None"
                    + Fore.RESET
                )
                continue

            for item in protection["industry-reference"]:
                if item == cve:
                    log.info(
                        Fore.LIGHTYELLOW_EX
                        + " Protection Matched with CVE!"
                        + Fore.RESET
                    )
                    log.info(
                        Fore.CYAN
                        + f" Protection Name: {protection['name']}"
                        + Fore.RESET
                    )
                    # log.debug(protection)
                    # print_as_table(protection, title="Protection Details")
                    return protection


def print_as_table(data, title=None):
    """Prints a dictionary as a formatted table.

    Args:
        data (dict): The dictionary to print.
        title (str, optional): Title of the table. Defaults to None.
    """
    if not data:
        print("No data to print in the table.")
        return

    keys = list(data.keys())
    max_key_length = max(len(str(key)) for key in keys)
    max_value_length = max(len(str(value)) for value in data.values())

    # Print title
    if title:
        print("-" * (max_key_length + max_value_length + 5))
        print(f"| {title:^{max_key_length + max_value_length + 3}} |")
        print("-" * (max_key_length + max_value_length + 5))

    # Print header
    print(f"| {'Name':<{max_key_length}} | {'Value':<{max_value_length}} |")
    print("-" * (max_key_length + max_value_length + 5))

    # Print data
    for key, value in data.items():
        print(f"| {str(key):<{max_key_length}} | {str(value):<{max_value_length}} |")
        print("-" * (max_key_length + max_value_length + 5))


def protection_activation_per_profile(protection, profiles):
    #  the performance Impact and severity levels coming from the API are not the same as in SmartConsole
    profile_perfomance_impact_levels = [
        "very_low",
        "low",
        "medium",
        "high",
    ]
    protections_performance_impact_levels = [
        "Very low",
        "Low",
        "Medium",
        "High",
    ]

    profile_severity_levels = [
        "Low or above",
        "Medium or above",
        "High",
        "Critical",
    ]
    # NA as shown in SmartConsole are not handled here
    protections_severity_levels = [
        "Low",
        "Medium",
        "High",
        "Critical",
    ]

    # First we need to find the Activation Policy on the Protection by Default.
    protection_performance_impact = protection["performance-impact"]
    protection_severity = protection["severity"]

    # The "Performance Impact" and "severity" determine whether the protection is active or not
    policy_decision_per_profile = {}
    for profile in profiles:
        performance_impact_policy_from_profile = profile[
            "active-protections-performance-impact"
        ]
        severity_policy_from_profile = profile["active-protections-severity"]

        is_performance_active = protections_performance_impact_levels.index(
            protection_performance_impact
        ) <= profile_perfomance_impact_levels.index(
            performance_impact_policy_from_profile
        )
        log.debug(
            Fore.LIGHTCYAN_EX
            + f"Protection activation based on Performance Impact: {is_performance_active} Profile: {profile['name']} "
        )

        is_severity_active = protections_severity_levels.index(
            protection_severity
        ) >= profile_severity_levels.index(severity_policy_from_profile)

        log.debug(
            f"Protection activation based on Severity: {is_severity_active} Profile: {profile['name']} "
        )
        is_active_in_policy = (
            True
            if is_performance_active == True and is_severity_active == True
            else False
        )

        log.debug(
            Fore.CYAN
            + f" Activation in the profile {profile['name']} on Performance Impact and Severity of the Protection: "
            + Fore.RED
            + f"{is_active_in_policy}"
            + Fore.RESET
        )

        if not is_active_in_policy:
            log.info(
                Fore.RED
                + f" Protection is Disabled in the Profile: "
                + Fore.LIGHTWHITE_EX
                + f"{profile['name']}"
                + Fore.RESET
            )
            # continue

        # To Decide the activation method (Detect/Prevent/Inactive/Ask), we check the confidence level
        if protection["confidence-level"] == "Low":
            activation_mode = profile["confidence-level-low"]
            log.debug(
                Fore.GREEN
                + f" Activation Mode in the profile {profile['name']} for Low Confidence Protections: "
                + Fore.RED
                + f"{activation_mode}"
                + Fore.RESET
            )
            policy_decision_per_profile[profile["name"]] = activation_mode
        if protection["confidence-level"] == "Medium":
            activation_mode = profile["confidence-level-medium"]
            log.debug(
                Fore.CYAN
                + f" Activation Mode in the profile {profile['name']} for Medium Confidence Protections: "
                + Fore.RED
                + f"{activation_mode}"
                + Fore.RESET
            )
            policy_decision_per_profile[profile["name"]] = activation_mode
        if protection["confidence-level"] == "High":
            activation_mode = profile["confidence-level-high"]
            log.debug(
                Fore.GREEN
                + f" Activation Mode for High Confidence Protections: "
                + Fore.RED
                + f"{activation_mode}"
                + Fore.RESET
            )
            policy_decision_per_profile[profile["name"]] = activation_mode

    return policy_decision_per_profile


if __name__ == "__main__":
    main()
