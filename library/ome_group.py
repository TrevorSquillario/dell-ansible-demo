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
module: ome_group
short_description: Create, modify or delete a group
version_added: "2.9"
description: This module creates, modifies or deletes a group. Only static groups supported at this time. 
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
    description: Name of the group.
    type: str
    required: true
  description:
    description: Description of the group.
    type: str
    required: false
  parent_name:
    description: Name of the parent to create group under. Only Static Groups supported at this time.
    type: str
    default: Static Groups
    required: true
  state:
    description:
      - C(present) creates group
      - C(absent) deletes group
    choices: [present, absent]
    default: present
requirements:
    - "python >= 2.7.5"
author: "Trevor Squillario <Trevor.Squillario@Dell.com>"
'''

EXAMPLES = r'''
---
- name: Create static group
  ome_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "Group0001"

- name: Delete static group
  ome_group:
    hostname: "{{ hostname }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "Group0001"
    state: absent
'''

RETURN = r'''
---
msg:
  description: Overall status of the operation.
  returned: always
  type: str
  sample: "Successfully created group"
status:
  description: Returns Id of group, when I(state) is C(present).
  returned: When I(state) is C(present).
  type: int
  sample: 23877
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError

def get_group(name, rest_obj):
    path = "GroupService/Groups?$filter=Name eq '%s'" % (name)
    http_method = 'GET'
    resp = rest_obj.invoke_request(http_method, path.replace(" ", "%20"))
    group = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            group = resp_json['value'][0]
    return group

def create_group(name, description, parent_group_id, rest_obj):
    group_payload = {"GroupModel": {
        "Name": name,
        "Description": description,
        "MembershipTypeId": 12,
        "ParentId": int(parent_group_id)}
    }
    http_method = 'POST'
    path = 'GroupService/Actions/GroupService.CreateGroup'
    resp = rest_obj.invoke_request(http_method, path, data=group_payload)
    return resp

def delete_group(group_id, rest_obj):
    http_method = 'DELETE'
    path = 'GroupService/Groups(%s)' % group_id
    resp = rest_obj.invoke_request(http_method, path)
    return resp

def fail_module(module, **failmsg):
    module.fail_json(**failmsg)

def main():
    module = AnsibleModule(
        argument_spec={
            "hostname": {"required": True, "type": 'str'},
            "username": {"required": True, "type": 'str'},
            "password": {"required": True, "type": 'str', "no_log": True},
            "port": {"required": False, "default": 443, "type": 'int'},
            "name": {"required": True, "type": 'str'},
            "description": {"required": False, "type": 'str'},
            "parent_name": {"required": False, "default": "Static Groups", "type": 'str'},
            "state": {"required": False, "default": "present",
                    "choices": ['present', 'absent']}
        },
        supports_check_mode=False)

    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            parent_group = get_group(module.params['parent_name'], rest_obj)
            if parent_group:
                parent_group_id = parent_group['Id']
                group = get_group(module.params['name'], rest_obj)
                if group == None:
                    if module.params['state'] == "present":
                        group_resp = create_group(module.params['name'], module.params['description'], parent_group_id, rest_obj)
                        if group_resp.success:
                            module.exit_json(msg="Successfully created group", changed=True, status=group_resp.json_data)
                else:
                    group_id = group['Id']
                    if module.params['state'] == "present":
                        module.exit_json(msg="Group already exists", changed=False)
                    elif module.params['state'] == "absent":
                        delete_resp = delete_group(group_id, rest_obj)
                        if delete_resp.success:
                            module.exit_json(msg="Successfully deleted group", changed=True)
            else:
                fail_module(module, msg="Unable to find group %s" % (module.params['parent_name']))

    except HTTPError as err:
        fail_module(module, msg=str(err), status=json.load(err))
    except (URLError, SSLValidationError, ConnectionError, TypeError, ValueError) as err:
        fail_module(module, msg=str(err))

if __name__ == '__main__':
    main()