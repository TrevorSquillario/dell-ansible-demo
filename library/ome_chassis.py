#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Dell EMC OpenManage Ansible Modules
# Version 2.2
# Copyright (C) 2020 Dell Inc.

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# All rights reserved. Dell, EMC, and other trademarks are trademarks of Dell Inc. or its subsidiaries.
# Other trademarks may be trademarks of their respective owners.
#


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ome_chassis
short_description: Change chassis and slot names
version_added: "2.9"
description: This module will change a chassis name or a chassis slot name.
options:
  hostname:
    description: Target IP Address or hostname.
    type: str
    required: true
  username:
    description: Target username.
    type: str
    required: true
  password:
    description: Target user password.
    type: str
    required: true
  port:
    description: Target HTTPS port.
    type: int
    default: 443
  name:
    description: Value used to change the name of the chassis
    type: str
    required: true
  chassis_name:
    description: Name of chassis to modify
    type: str
    required: false
  chassis_id:
    description: Id of chassis to modify
    type: int
    required: false
  chassis_service_tag: 
    description: Service tag of chassis to modify
    type: str
    required: false
  slot_names: 
    description: List of slots with name associated. Use slots 1-8. See example
    type: list
    required: false
requirements:
    - "python >= 2.7.5"
author: "Trevor Squillario <Trevor.Squillario@Dell.com>"
'''

EXAMPLES = r'''
---
- name: Change chassis name and slot names
  ome_chassis:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "MX7000-MKZ1234"
    chassis_service_tag: "MKZ1234"
    slot_names:
        - slot: 1
          name: Slot-1
        - slot: 2
          name: Slot-2
        - slot: 3
          name: Slot-3

- name: Change chassis name based on inventory
  ome_chassis:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ inventory_hostname | upper }}"
    chassis_service_tag: "{{ service_tag }}"
'''

RETURN = r'''
---
msg:
  description: Overall status of the operation.
  returned: always
  type: str
  sample: "Successfully created..."
status:
  description: Returns response of api request
  returned: On success
  type: int
  sample: {
            "chassis_name_status": {
                "Builtin": false, 
                "CreatedBy": "root", 
                "Editable": true, 
                "EndTime": null, 
                "Id": 71541, 
                "JobDescription": "Job submitted via Ansible", 
                "JobName": "Update Chassis Name", 
                "JobStatus": {
                    "Id": 2080, 
                    "Name": "New"
                }, 
                "JobType": {
                    "Id": 3, 
                    "Internal": false, 
                    "Name": "DeviceAction_Task"
                }, 
                "LastRun": null, 
                "LastRunStatus": {
                    "Id": 2200, 
                    "Name": "NotRun"
                }, 
                "NextRun": null, 
                "Params": [
                    {
                        "JobId": 71541, 
                        "Key": "name", 
                        "Value": "MX7000-C38V9T2"
                    }, 
                    {
                        "JobId": 71541, 
                        "Key": "operationName", 
                        "Value": "SET_NAME"
                    }
                ], 
                "Schedule": "startnow", 
                "StartTime": null, 
                "State": "Enabled", 
                "Targets": [
                    {
                        "Data": "", 
                        "Id": 25015, 
                        "JobId": 71541, 
                        "TargetType": {
                            "Id": 1000, 
                            "Name": "DEVICE"
                        }
                    }
                ], 
                "UpdatedBy": null, 
                "UserGenerated": true, 
                "Visible": true
        }, 
        "chassis_slot_name_status": [ {
                "Builtin": false, 
                "CreatedBy": "root", 
                "Editable": true, 
                "EndTime": null, 
                "Id": 71571, 
                "JobDescription": "Job submitted via Ansible", 
                "JobName": "Update slot 1 name", 
                "JobStatus": {
                    "Id": 2080, 
                    "Name": "New"
                }, 
                "JobType": {
                    "Id": 3, 
                    "Internal": false, 
                    "Name": "DeviceAction_Task"
                }, 
                "LastRun": null, 
                "LastRunStatus": {
                    "Id": 2200, 
                    "Name": "NotRun"
                }, 
                "NextRun": null, 
                "Params": [
                    {
                        "JobId": 71571, 
                        "Key": "operationName", 
                        "Value": "UPDATE_SLOT_DATA"
                    }, 
                    {
                        "JobId": 71571, 
                        "Key": "slotConfig", 
                        "Value": "1|1000|Slot-1"
                    }
                ], 
                "Schedule": "startnow", 
                "StartTime": null, 
                "State": "Enabled", 
                "Targets": [
                    {
                        "Data": "", 
                        "Id": 25015, 
                        "JobId": 71571, 
                        "TargetType": {
                            "Id": 1000, 
                            "Name": "DEVICE"
                        }
                    }
                ], 
                "UpdatedBy": null, 
                "UserGenerated": true, 
                "Visible": true
            }, 
            {
                "Builtin": false, 
                "CreatedBy": "root", 
                "Editable": true, 
                "EndTime": null, 
                "Id": 71572, 
                "JobDescription": "Job submitted via Ansible", 
                "JobName": "Update slot 2 name", 
                "JobStatus": {
                    "Id": 2080, 
                    "Name": "New"
                }, 
                "JobType": {
                    "Id": 3, 
                    "Internal": false, 
                    "Name": "DeviceAction_Task"
                }, 
                "LastRun": null, 
                "LastRunStatus": {
                    "Id": 2200, 
                    "Name": "NotRun"
                }, 
                "NextRun": null, 
                "Params": [
                    {
                        "JobId": 71572, 
                        "Key": "operationName", 
                        "Value": "UPDATE_SLOT_DATA"
                    }, 
                    {
                        "JobId": 71572, 
                        "Key": "slotConfig", 
                        "Value": "2|1000|Slot-2"
                    }
                ], 
                "Schedule": "startnow", 
                "StartTime": null, 
                "State": "Enabled", 
                "Targets": [
                    {
                        "Data": "", 
                        "Id": 25015, 
                        "JobId": 71572, 
                        "TargetType": {
                            "Id": 1000, 
                            "Name": "DEVICE"
                        }
                    }
                ], 
                "UpdatedBy": null, 
                "UserGenerated": true, 
                "Visible": true
            }, 
            {
                "Builtin": false, 
                "CreatedBy": "root", 
                "Editable": true, 
                "EndTime": null, 
                "Id": 71573, 
                "JobDescription": "Job submitted via Ansible", 
                "JobName": "Update slot 3 name", 
                "JobStatus": {
                    "Id": 2080, 
                    "Name": "New"
                }, 
                "JobType": {
                    "Id": 3, 
                    "Internal": false, 
                    "Name": "DeviceAction_Task"
                }, 
                "LastRun": null, 
                "LastRunStatus": {
                    "Id": 2200, 
                    "Name": "NotRun"
                }, 
                "NextRun": null, 
                "Params": [
                    {
                        "JobId": 71573, 
                        "Key": "operationName", 
                        "Value": "UPDATE_SLOT_DATA"
                    }, 
                    {
                        "JobId": 71573, 
                        "Key": "slotConfig", 
                        "Value": "3|1000|Slot-3"
                    }
                ], 
                "Schedule": "startnow", 
                "StartTime": null, 
                "State": "Enabled", 
                "Targets": [
                    {
                        "Data": "", 
                        "Id": 25015, 
                        "JobId": 71573, 
                        "TargetType": {
                            "Id": 1000, 
                            "Name": "DEVICE"
                        }
                    }
                ], 
                "UpdatedBy": null, 
                "UserGenerated": true, 
                "Visible": true
            }
        ]
    }
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError

def get_job_payload():
    payload = {
        "JobName": "Update Chassis Name",
        "JobDescription": "Job submitted via Ansible",
        "Schedule": "startnow",
        "State": "Enabled",
        "Targets": [
            {
            "Id": 10000,
            "Data": "",
            "TargetType": {
                "Id": 1000,
                "Name": "DEVICE"
                }
            }
        ],
        "Params": [],
        "JobType":
            {
            "Id": 3,
            "Name": "DeviceAction_Task"
            }
    }
    return payload

def get_device(device_id, name, service_tag, rest_obj):
    if device_id:
        path = "DeviceService/Devices?$filter=Id eq %s" % (id)
    elif name:
        path = "DeviceService/Devices?$filter=DeviceName eq '%s'" % (name)
    elif service_tag:
        path = "DeviceService/Devices?$filter=DeviceServiceTag eq '%s'" % (service_tag)
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path.replace(" ", "%20"))
    device = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            device = resp_json['value'][0]
    return device

def set_chassis_name(module_params, rest_obj):
    http_method = 'POST'
    path = 'JobService/Jobs'
    payload = get_job_payload()
    job_payload = [
        {
        "Key": "operationName",
        "Value": "SET_NAME"
        },
        {
        "Key": "name",
        "Value": module_params["name"]
        }
    ]
    payload["JobName"] = "Update Chassis Name"
    payload["Targets"][0]["Id"] = module_params["chassis_id"]
    payload["Params"] = job_payload
    resp = rest_obj.invoke_request(http_method, path, data=payload)
    return resp

def get_chassis_slot_names(chassis_id, rest_obj):
    path = 'DeviceService/Devices(%s)/DeviceBladeSlots' % chassis_id
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path)
    slots = []
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            for slot in resp_json['value']:
                slots.append({
                    "slot": int(slot["SlotNumber"]),
                    "name": slot["SlotName"]
                    })    
    return slots

def set_chassis_slot_name(chassis_id, slot_names, rest_obj):
    http_method = 'POST'
    path = 'JobService/Jobs'
    payload = get_job_payload()
    job_payload = [
        {
        "Key": "slotConfig",
        "Value": "1|1000|Device0001"
        },
        {
        "Key": "operationName",
        "Value": "UPDATE_SLOT_DATA"
        }
    ]
    payload["Targets"][0]["Id"] = chassis_id
    resp_arr = []
    for slot in slot_names:
        slot_num = slot["slot"]
        slot_name = slot["name"]
        job_payload[0]["Value"] = "%s|1000|%s" % (slot_num, slot_name)
        payload["JobName"] = "Modify Chassis Slot %s Name" % slot_num
        payload["Params"] = job_payload   
        resp = rest_obj.invoke_request(http_method, path, data=payload)
        resp_arr.append(resp)
    return resp_arr

def fail_module(module, **failmsg):
    module.fail_json(**failmsg)

def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": 'str'},
            "username": {"required": True, "type": 'str'},
            "password": {"required": True, "type": 'str', "no_log": True},
            "port": {"required": False, "default": 443, "type": 'int'},
            "name": {"required": False, "type": "str"},
            "chassis_name": {"required": False, "type": "str"},
            "chassis_id": {"required": False, "type": "int"},
            "chassis_service_tag": {"required": False, "type": "str"},
            "slot_names": {"required": False, "default": [], "type": "list"}
        },
        supports_check_mode=False)

    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            chassis = get_device(module.params["chassis_id"], module.params["chassis_name"], module.params["chassis_service_tag"], rest_obj)
            if chassis:
                chassis_id = chassis['Id']
                module.params["chassis_id"] = chassis_id
                status = {}
                changed = False
                if chassis["DeviceName"] != module.params["name"]: # Set chassis name if different
                    chassis_name_resp = set_chassis_name(module.params, rest_obj)
                    if chassis_name_resp.success:
                        status["chassis_name_status"] = chassis_name_resp.json_data
                        changed = True
                if len(module.params["slot_names"]) > 0: # Set chassis slot names
                    slot_names = module.params["slot_names"] # Names provided by user/module
                    slot_names_valid = True
                    slot_name_choices = [1,2,3,4,5,6,7,8]
                    for slot in slot_names:
                        if not isinstance(slot["slot"], int) and slot["slot"] not in slot_name_choices: # Validate slot names
                            slot_names_valid = False
                    if slot_names_valid:
                        chassis_slot_names = get_chassis_slot_names(chassis_id, rest_obj) # Get get current slot names from chassis
                        slot_names_to_update = [] # Variable to hold slot names to be updated
                        for slot in slot_names: 
                            for chassis_slot in chassis_slot_names:
                                if slot["slot"] == chassis_slot["slot"]:
                                    if slot["name"] != chassis_slot["name"]: # If slot name is different add it to the list to be updated
                                        slot_names_to_update.append(slot)

                        status["chassis_slot_name_status"] = []
                        if len(slot_names_to_update) > 0:
                            chassis_slot_name_resps = set_chassis_slot_name(module.params["chassis_id"], slot_names_to_update, rest_obj)
                            for resp in chassis_slot_name_resps:
                                if resp.success:
                                    status["chassis_slot_name_status"].append(resp.json_data)
                                    changed = True
                        else:
                            status["chassis_slot_name_status"] = "No changes required"
                    else:
                        fail_module(module, msg="Slot must be an integer 1-8 %s" % (module.params['slot_names']))                    
                
                if changed:
                    module.exit_json(msg="Successfully submitted chassis update job", changed=True, status=status)
                else:
                    module.exit_json(msg="No changes required", changed=False, status=status)

            else:
                fail_module(module, msg="Unable to find chassis %s" % (module.params['chassis_name']))

    except HTTPError as err:
        fail_module(module, msg=str(err), status=json.load(err))
    except (URLError, SSLValidationError, ConnectionError, TypeError, ValueError) as err:
        fail_module(module, msg=str(err))

if __name__ == '__main__':
    main()