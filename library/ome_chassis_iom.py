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
module: ome_chassis_iom
short_description: Change chassis iom name and network settings
version_added: "2.9"
description: This module will change chassis iom name and network settings
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

requirements:
    - "python >= 2.7.5"
author: "Trevor Squillario <Trevor.Squillario@Dell.com>"
'''

EXAMPLES = r'''
---
- name: Change chassis name and slot names
  ome_chassis_iom:
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
  ome_chassis_iom:
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
  sample: 
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.remote_management.dellemc.ome import RestOME
from ansible.module_utils.six.moves.urllib.error import URLError, HTTPError
from ansible.module_utils.urls import ConnectionError, SSLValidationError
try:
    from urllib import quote  # Python 2.X
except ImportError:
    from urllib.parse import quote  # Python 3+

def get_management_payload():
    payload = {
        "SettingType": "Management"
    }
    return payload

def get_monitoring_payload():
    payload = {
        "SettingType": "Monitoring",
        "EnableSNMP": True,
        "EnableSNMPV1": False,
        "EnableSNMPV2": True,
        "ReadCommunityString": "public"
    }
    return payload

def get_network_payload():
    payload = {
    "SettingType": "Network",
    "MgmtVLANId": "0",
    "EnableMgmtVLANId": False,
    "IomIPv4Settings":
        {
            "EnableIPv4": True,
            "EnableDHCP": True,
            "StaticIPAddress": "",
            "StaticSubnetMask": "",
            "StaticGateway": ""
        },
        "IomIPv6Settings":
        {
            "EnableIPv6": False,
            "StaticIPv6Address": "",
            "StaticPrefixLength": "",
            "StaticGateway": "",
            "UseDHCPv6": False
        },
        "IomDNSSettings":
        {
            "PrimaryDNS": "",
            "SecondaryDNS": "",
            "TertiaryDNS": ""
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
    http_method = "GET"
    resp = rest_obj.invoke_request(http_method, path.replace(" ", "%20"))
    device = None
    if resp.success:
        resp_json = resp.json_data
        if resp_json['@odata.count'] > 0:
            device = resp_json['value'][0]
    return device

def get_device_settings(device_id, setting_type, rest_obj):
    path = "DeviceService/Devices(%s)/Settings('%s')" % (device_id, setting_type)
    http_method = "GET"
    resp = rest_obj.invoke_request(http_method, quote(path))
    settings = None
    if resp.success:
        resp_json = resp.json_data
        settings = resp_json
    return settings

def set_device_name(module_params, rest_obj):
    http_method = "PUT"
    path = "DeviceService/Devices(%s)/Settings('Management')" % (module_params["device_id"])
    payload = get_management_payload()
    payload["Hostname"] = module_params["name"]
    resp = rest_obj.invoke_request(http_method, quote(path), data=payload)
    return resp

def set_device_password(module_params, rest_obj):
    http_method = "PUT"
    path = "DeviceService/Devices(%s)/Settings('Management')" % (module_params["device_id"])
    payload = get_management_payload()
    payload["RootPassword"] = module_params["root_password"]
    resp = rest_obj.invoke_request(http_method, quote(path), data=payload)
    return resp

def set_device_network(payload, module_params, rest_obj):
    http_method = "PUT"
    path = "DeviceService/Devices(%s)/Settings('Network')" % (module_params["device_id"])
    resp = rest_obj.invoke_request(http_method, quote(path), data=payload)
    return resp

def set_device_monitoring(payload, module_params, rest_obj):
    http_method = "PUT"
    path = "DeviceService/Devices(%s)/Settings('Monitoring')" % (module_params["device_id"])
    resp = rest_obj.invoke_request(http_method, quote(path), data=payload)
    return resp

def update_device_network_payload(network_settings, module_params):
    payload = get_network_payload()
    changed = False
    # Update payload from current settings
    payload["IomIPv4Settings"]["EnableIPv4"] = network_settings["IomIPv4Settings"]["EnableIPv4"]
    payload["IomIPv4Settings"]["EnableDHCP"] = network_settings["IomIPv4Settings"]["EnableDHCP"]
    payload["IomIPv4Settings"]["StaticIPAddress"] = network_settings["IomIPv4Settings"]["StaticIPAddress"]
    payload["IomIPv4Settings"]["StaticSubnetMask"] = network_settings["IomIPv4Settings"]["StaticSubnetMask"]
    payload["IomIPv4Settings"]["StaticGateway"] = network_settings["IomIPv4Settings"]["StaticGateway"]
    payload["IomIPv6Settings"]["EnableIPv6"] = network_settings["IomIPv6Settings"]["EnableIPv6"]
    payload["IomIPv6Settings"]["UseDHCPv6"] = network_settings["IomIPv6Settings"]["UseDHCPv6"]
    payload["IomIPv6Settings"]["StaticIPv6Address"] = network_settings["IomIPv6Settings"]["StaticIPv6Address"]
    payload["IomIPv6Settings"]["StaticPrefixLength"] = network_settings["IomIPv6Settings"]["StaticPrefixLength"]
    payload["IomIPv6Settings"]["StaticGateway"] = network_settings["IomIPv6Settings"]["StaticGateway"]
    payload["IomDNSSettings"]["PrimaryDNS"] = network_settings["IomDNSSettings"]["PrimaryDNS"]
    payload["IomDNSSettings"]["SecondaryDNS"] = network_settings["IomDNSSettings"]["SecondaryDNS"]
    payload["IomDNSSettings"]["TertiaryDNS"] = network_settings["IomDNSSettings"]["TertiaryDNS"]
    payload["EnableMgmtVLANId"] = network_settings["EnableMgmtVLANId"]
    payload["MgmtVLANId"] = network_settings["MgmtVLANId"]

    # Update payload from module params
    if payload["IomIPv4Settings"]["EnableIPv4"] != module_params["ipv4_enable"]:
        payload["IomIPv4Settings"]["EnableIPv4"] = module_params["ipv4_enable"]
        changed = True
    if payload["IomIPv4Settings"]["EnableDHCP"] != module_params["ipv4_dhcp_enable"]:
        payload["IomIPv4Settings"]["EnableDHCP"] = module_params["ipv4_dhcp_enable"]
        changed = True
    if module_params["ipv4_address"] and payload["IomIPv4Settings"]["StaticIPAddress"] != module_params["ipv4_address"]:
        payload["IomIPv4Settings"]["StaticIPAddress"] = module_params["ipv4_address"]
        changed = True
    if module_params["ipv4_netmask"] and payload["IomIPv4Settings"]["StaticSubnetMask"] != module_params["ipv4_netmask"]:
        payload["IomIPv4Settings"]["StaticSubnetMask"] = module_params["ipv4_netmask"]
        changed = True
    if module_params["ipv4_gateway"] and payload["IomIPv4Settings"]["StaticGateway"] != module_params["ipv4_gateway"]:
        payload["IomIPv4Settings"]["StaticGateway"] = module_params["ipv4_gateway"]
        changed = True
    if payload["IomIPv6Settings"]["EnableIPv6"] != module_params["ipv6_enable"]:
        payload["IomIPv6Settings"]["EnableIPv6"] = module_params["ipv6_enable"]
        changed = True
    if payload["IomIPv6Settings"]["UseDHCPv6"] != module_params["ipv6_dhcp_enable"]:
        payload["IomIPv6Settings"]["UseDHCPv6"] = module_params["ipv6_dhcp_enable"]
        changed = True
    if module_params["ipv6_address"] and payload["IomIPv6Settings"]["StaticIPv6Address"] != module_params["ipv6_address"]:
        payload["IomIPv6Settings"]["StaticIPv6Address"] = module_params["ipv6_address"]
        changed = True
    if module_params["ipv6_prefix"] and payload["IomIPv6Settings"]["StaticPrefixLength"] != module_params["ipv6_prefix"]:
        payload["IomIPv6Settings"]["StaticPrefixLength"] = module_params["ipv6_prefix"]
        changed = True
    if module_params["ipv6_gateway"] and payload["IomIPv6Settings"]["StaticGateway"] != module_params["ipv6_gateway"]:
        payload["IomIPv6Settings"]["StaticGateway"] = module_params["ipv6_gateway"]
        changed = True
    if module_params["dns1"] and payload["IomDNSSettings"]["PrimaryDNS"] != module_params["dns1"]:
        payload["IomDNSSettings"]["PrimaryDNS"] = module_params["dns1"]
        changed = True
    if module_params["dns2"] and payload["IomDNSSettings"]["SecondaryDNS"] != module_params["dns2"]:
        payload["IomDNSSettings"]["SecondaryDNS"] = module_params["dns2"]
        changed = True
    if module_params["dns3"] and payload["IomDNSSettings"]["TertiaryDNS"] != module_params["dns3"]:
        payload["IomDNSSettings"]["TertiaryDNS"] = module_params["dns3"]
        changed = True
    if payload["EnableMgmtVLANId"] != module_params["management_vlan_enable"]:
        payload["EnableMgmtVLANId"] = module_params["management_vlan_enable"]
        changed = True
    if module_params["management_vlan_id"] and payload["MgmtVLANId"] != module_params["management_vlan_id"]:
        payload["MgmtVLANId"] = module_params["management_vlan_id"]
        changed = True
    return payload, changed

def update_device_monitoring_payload(monitoring_settings, module_params):
    payload = get_monitoring_payload()
    changed = False
    # Update payload from current settings
    payload["EnableSNMP"] = monitoring_settings["EnableSNMP"]
    payload["EnableSNMPV1"] = monitoring_settings["EnableSNMPV1"]
    payload["EnableSNMPV2"] = monitoring_settings["EnableSNMPV2"]
    payload["ReadCommunityString"] = monitoring_settings["ReadCommunityString"]

    # Update payload from module params
    if payload["EnableSNMP"] != module_params["snmp_enable"]:
        payload["EnableSNMP"] = module_params["snmp_enable"]
        changed = True
    if payload["EnableSNMPV1"] != module_params["snmpv1_enable"]:
        payload["EnableSNMPV1"] = module_params["snmpv1_enable"]
        changed = True
    if payload["EnableSNMPV2"] != module_params["snmpv2_enable"]:
        payload["EnableSNMPV2"] = module_params["snmpv2_enable"]
        changed = True
    if payload["ReadCommunityString"] != module_params["snmp_community_string"]:
        payload["ReadCommunityString"] = module_params["snmp_community_string"]
        changed = True

    return payload, changed

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
            "device_name": {"required": False, "type": "str"},
            "device_id": {"required": False, "type": "int"},
            "device_service_tag": {"required": False, "type": "str"},
            "root_password": {"required": False, "type": "str", "no_log": True},
            "ipv4_enable": {"required": False, "default": True, "type": "bool"},
            "ipv4_address": {"required": False, "type": "str"},
            "ipv4_netmask": {"required": False, "type": "str"},
            "ipv4_gateway": {"required": False, "type": "str"},
            "ipv4_dhcp_enable": {"required": False, "default": True, "type": "bool"},
            "ipv6_enable": {"required": False, "default": False, "type": "bool"},
            "ipv6_address": {"required": False, "type": "str"},
            "ipv6_prefix": {"required": False, "type": "str"},
            "ipv6_gateway": {"required": False, "type": "str"},
            "ipv6_dhcp_enable": {"required": False, "default": False, "type": "bool"},
            "dns1": {"required": False, "type": "str"},
            "dns2": {"required": False, "type": "str"},
            "dns3": {"required": False, "type": "str"},
            "management_vlan_enable": {"required": False, "default": False, "type": "bool"},
            "management_vlan_id": {"required": False, "type": "int"},
            "snmp_enable": {"required": False, "default": True, "type": "bool"},
            "snmpv1_enable": {"required": False, "default": False, "type": "bool"},
            "snmpv2_enable": {"required": False, "default": True, "type": "bool"},
            "snmp_community_string": {"required": False, "default": "public", "type": "str"}
        },
        supports_check_mode=True)

    try:
        with RestOME(module.params, req_session=True) as rest_obj:
            iom = get_device(module.params["device_id"], module.params["device_name"], module.params["device_service_tag"], rest_obj)
            if iom:
                device_id = iom['Id']
                module.params["device_id"] = device_id
                status = {
                    "device_name_status": {"changed": False},
                    "device_password_status": {"changed": False},
                    "device_network_status": {"changed": False},
                    "device_monitoring_status": {"changed": False}
                }
                changed = False
                mgmt_settings = get_device_settings(device_id, "Management", rest_obj)
                if mgmt_settings: # Set management 
                    if module.params["name"] and mgmt_settings["Hostname"] != module.params["name"]: # Set iom name
                        changed = True
                        status["device_name_status"]["changed"] = changed
                        if not module.check_mode:
                            device_name_resp = set_device_name(module.params, rest_obj)
                            if device_name_resp.success:
                                status["device_name_status"]["response"] = device_name_resp.json_data
                
                if module.params["root_password"]: # Set root password
                    changed = True
                    status["device_password_status"]["changed"] = changed
                    if not module.check_mode:
                        device_password_resp = set_device_password(module.params, rest_obj)
                        if device_password_resp.success:
                            status["device_password_status"]["response"] = device_password_resp.json_data

                network_settings = get_device_settings(device_id, "Network", rest_obj)
                if network_settings: # Set network 
                    network_payload, network_changed = update_device_network_payload(network_settings, module.params)
                    if network_changed:
                        changed = True
                        status["device_network_status"]["changed"] = changed
                        if not module.check_mode:
                            device_network_resp = set_device_network(network_payload, module.params, rest_obj)
                            if device_network_resp.success:
                                status["device_network_status"]["response"] = device_network_resp.json_data
                
                monitoring_settings = get_device_settings(device_id, "Monitoring", rest_obj)
                if monitoring_settings: # Set monitoring
                    monitoring_payload, monitoring_changed = update_device_monitoring_payload(monitoring_settings, module.params)
                    if monitoring_changed:
                        changed = True
                        status["device_monitoring_status"]["changed"] = changed
                        if not module.check_mode:
                            device_monitoring_resp = set_device_monitoring(monitoring_payload, module.params, rest_obj)
                            if device_monitoring_resp.success:
                                status["device_monitoring_status"]["response"] = device_monitoring_resp.json_data

                if changed:
                    module.exit_json(msg="Successfully submitted iom update job", changed=True, status=status)
                else:
                    module.exit_json(msg="No changes made", changed=False, status=status)

            else:
                fail_module(module, msg="Unable to find iom %s" % (module.params['device_name']))

    except HTTPError as err:
        fail_module(module, msg=str(err), status=json.load(err))
    except (URLError, SSLValidationError, ConnectionError, TypeError, ValueError) as err:
        fail_module(module, msg=str(err))

if __name__ == '__main__':
    main()