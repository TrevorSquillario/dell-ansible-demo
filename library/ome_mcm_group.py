#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 2.1.4
# Copyright (C) 2020 Dell Inc. or its subsidiaries. All Rights Reserved.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#


from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''

'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

import json
import random
import time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError
from ssl import SSLError
import requests
import urllib3

class SessionManager:
    session = None
    base_url = ''

    def get_session(self):
        if not self.session:
            self.session = requests.Session()
            self.session.headers.update({'content-type': 'application/json'})
        return self.session

    def get_base_url(self):
        return self.base_url

    def set_base_url(self, url):
        self.base_url = url


def authenticate(session_manager, username, password):
    session_url = '{0}/SessionService/Sessions'.format(session_manager.get_base_url())
    session = session_manager.get_session()
    auth_success = False

    user_details = {
        'UserName': username,
        'Password': password,
        'SessionType': 'API'
    }
    session_info = session.post(session_url, verify=False, json=user_details)
    if session_info.status_code == 201:
        session.headers.update({
            'X-Auth-Token': session_info.headers['X-Auth-Token'],
            'content-type': 'application/json'
        })
        auth_success = True
    else:
        print('Failed to login. Check username and password')

    return auth_success

def get_mcm_group(session_manager):
    session = session_manager.get_session()
    url = '{0}/ManagementDomainService'.format(session_manager.get_base_url())
    response = session.get(url, verify=False)
    groupname = ""
    if response.status_code == 200:
        response = response.json()
        group = response.get('GroupConfiguration')
        if group:
            groupname = group.get('GroupName')
    else:
        print('Failed to get groups and status code returned is %s', response.status_code)
    return groupname

def create_mcm_group(session_manager, group_name, vip_ipv4_address, vip_subnet, vip_gateway):
    create_group_url = '{0}/ManagementDomainService'.format(session_manager.get_base_url())
    session = session_manager.get_session()
    create_group_payload = {
        "GroupName": group_name,
        "GroupDescription": "",
        "JoinApproval": "AUTOMATIC",
        "ConfigReplication": [{
            "ConfigType": "Power",
            "Enabled": True
        }, {
            "ConfigType": "UserAuthentication",
            "Enabled": True
        }, {
            "ConfigType": "AlertDestinations",
            "Enabled": True
        }, {
            "ConfigType": "TimeSettings",
            "Enabled": True
        }, {
            "ConfigType": "ProxySettings",
            "Enabled": True
        }, {
            "ConfigType": "SecuritySettings",
            "Enabled": True
        }, {
            "ConfigType": "NetworkServices",
            "Enabled": True
        }, {
            "ConfigType": "LocalAccessConfiguration",
            "Enabled": True
        }]
    }
    if vip_ipv4_address and vip_subnet and vip_gateway:
        create_group_payload["VirtualIPConfiguration"] = {
            "IPv4": {
                "StaticIPv4Address": vip_ipv4_address,
                "SubnetMask": vip_subnet,
                "Gateway": vip_gateway
            }
        }

    group_info = session.put(create_group_url, verify=False,
                             json=create_group_payload)
    job_id = None
    if group_info.status_code == 200:
        group_info = group_info.json()
        job_id = group_info.get('JobId')
        print('MCM group created : Job ID = {0}'.format(job_id))
    else:
        print('Failed to create MCM group with the below error')
    return job_id


def get_domains(session_manager):
    members = []
    session = session_manager.get_session()
    url = '{0}/ManagementDomainService/Domains'.format(session_manager.get_base_url())
    response = session.get(url, verify=False)
    if response.status_code == 200:
        response = response.json()
        member_devices = response.get('value')
        members = list(filter(lambda x: x.get(
            'DomainRoleTypeValue') == 'MEMBER', member_devices))
    else:
        print('Failed to get domains and status code returned is %s', response.status_code)
    return members


def get_discovered_domains(session_manager, role=None):
    discovered_domains = []
    session = session_manager.get_session()
    url = '{0}/ManagementDomainService/DiscoveredDomains'.format(session_manager.get_base_url())
    domains_info = session.get(url, verify=False)
    if domains_info.status_code == 200:
        domains = domains_info.json()
        if domains.get('@odata.count') > 0:
            discovered_domains = domains.get('value')
        else:
            print("No domains discovered ... Error")
    else:
        print('Failed to discover domains - Status Code %s')
    if role:
        discovered_domains = list(filter(lambda x: x.get(
            'DomainRoleTypeValue') == role, discovered_domains))
    return discovered_domains


def add_all_members_via_lead(session_manager):
    """ Add standalone domains to the group"""
    standalone_domains = get_discovered_domains(session_manager,
                                                role='STANDALONE')
    session = session_manager.get_session()
    job_id = None
    if standalone_domains:
        body = []
        for domain in standalone_domains:
            body.append({'GroupId': domain.get('GroupId')})

        url = '{0}/ManagementDomainService/Actions/ManagementDomainService.Domains'.format(
            session_manager.get_base_url())
        response = session.post(url, json=body, verify=False)
        if response.status_code == 200:
            response_data = response.json()
            job_id = response_data.get('JobId')
            print('Added members to the created group, Job ID = {0}'.format(job_id))
        else:
            print('Failed to add members to the group')
    else:
        print('No standalone chassis found to add as member to the created group')
    return job_id


def assign_backup_lead(session_manager, backup_chassis):
    url = '{0}/ManagementDomainService/Actions/ManagementDomainService.AssignBackupLead'.format(
        session_manager.get_base_url())
    session = session_manager.get_session()
    members = get_domains(session_manager)
    job_id = None
    if members:
        if backup_chassis:
            for member in members:
                if member.get('Identifier') == backup_chassis:
                    member_id = member.get('Id')
        else:
            member_id = members[0].get('Id')

        body = [{
            'Id': member_id
        }]
        response = session.post(url, verify=False, json=body)
        if response.status_code == 200:
            response = response.json()
            job_id = response.get('JobId')
        else:
            print('Failed to assign backup lead')
    else:
        print('Created group has no members. Failed to assign a backup lead')
    return job_id


def get_job_status(session_manager, job_id):
    """ Tracks the update job to completion / error """
    session = session_manager.get_session()
    job_status_map = {
        "2020": "Scheduled",
        "2030": "Queued",
        "2040": "Starting",
        "2050": "Running",
        "2060": "Completed",
        "2070": "Failed",
        "2090": "Warning",
        "2080": "New",
        "2100": "Aborted",
        "2101": "Paused",
        "2102": "Stopped",
        "2103": "Canceled"
    }
    max_retries = 20
    sleep_interval = 60
    failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
    job_url = '{0}/JobService/Jobs({1})'.format(session_manager.get_base_url(), job_id)
    loop_ctr = 0
    job_incomplete = True
    print("Polling %s to completion ..." % job_id)
    while loop_ctr < max_retries:
        loop_ctr += 1
        time.sleep(sleep_interval)
        job_resp = session.get(job_url, verify=False)
        if job_resp.status_code == 200:
            job_status = str((job_resp.json())['LastRunStatus']['Id'])
            print("Iteration %s: Status of %s is %s" % (loop_ctr, job_id, job_status_map[job_status]))
            if int(job_status) == 2060:
                job_incomplete = False
                print("Completed job successfully ... Exiting")
                break
            elif int(job_status) in failed_job_status:
                job_incomplete = False
                print("Job failed ... ")
                job_hist_url = str(job_url) + "/ExecutionHistories"
                job_hist_resp = session.get(job_hist_url, verify=False)
                if job_hist_resp.status_code == 200:
                    job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
                    job_hist_det_url = str(job_hist_url) + "(" + job_history_id + ")/ExecutionHistoryDetails"
                    job_hist_det_resp = session.get(job_hist_det_url, verify=False)
                    if job_hist_det_resp.status_code == 200:
                        print(job_hist_det_resp.text)
                    else:
                        print("Unable to parse job execution history .. Exiting")
                break
        else:
            print("Unable to poll status of %s - Iteration %s " % (job_id, loop_ctr))
    if job_incomplete:
        print("Job %s incomplete after polling %s times...Check status" % (job_id, max_retries))


def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": "str"},
            "username": {"required": True, "type": "str"},
            "password": {"required": True, "type": "str", "no_log": True},
            "name": {"required": True, "type": "str"},
            "backup_chassis": {"required": False, "type": "str"},
            "vip_ipv4_address": {"required": False, "type": "str"},
            "vip_subnet": {"required": False, "type": "str"},
            "vip_gateway": {"required": False, "type": "str"}
        },
        supports_check_mode=True
    )
    try:
        base_url = 'https://{0}/api'.format(module.params["hostname"])

        session_manager = SessionManager()
        session_manager.set_base_url(base_url)
        if authenticate(session_manager, module.params["username"], module.params["password"]):
            group_check = get_mcm_group(session_manager)
            if group_check == module.params["name"]:
                module.exit_json(msg="MCM group exists", changed=False)
            else:
                if module.check_mode:
                    module.exit_json(changed=True)
                else:
                    job_id = create_mcm_group(session_manager, module.params["name"], module.params["vip_ipv4_address"], module.params["vip_subnet"], module.params["vip_gateway"])
                    if job_id:
                        print('Polling group creation ...')
                        get_job_status(session_manager, job_id)
                        standalone_domains = get_discovered_domains(session_manager,
                                                        role='STANDALONE')
                        if standalone_domains:
                            job_id = add_all_members_via_lead(session_manager)
                            if job_id:
                                print('Polling addition of members to group ...')
                                get_job_status(session_manager, job_id)
                                job_id = assign_backup_lead(session_manager, module.params["backup_chassis"])
                                if job_id:
                                    print('Polling backup lead assignment ...')
                                    get_job_status(session_manager, job_id)
                                    module.exit_json(msg="MCM group created successfully", changed=True)
                                else:
                                    module.fail_json(msg="Unable to track backup lead assignment ...")
                            else:
                                module.fail_json(msg="Unable to track addition of members to group ...")
                        else:
                            module.exit_json(msg="MCM group created successfully. No standalone chassis found.", changed=True)
                    else:
                        module.fail_json(msg="Unable to track group creation .. Exiting")
        else:
            module.fail_json(msg="Unable to authenticate. Check IP/username/password")

    except HTTPError as err:
        if err.code == 501:
            module.fail_json(msg=SYSTEM_NOT_SUPPORTED_ERROR_MSG, error_info=json.load(err))
        module.fail_json(msg=str(err), error_info=json.load(err))
    except URLError as err:
        module.exit_json(msg=str(err), unreachable=True)
    except (IOError, ValueError, TypeError, SSLError, ConnectionError, SSLValidationError) as err:
        module.fail_json(msg=str(err))


if __name__ == "__main__":
    main()
