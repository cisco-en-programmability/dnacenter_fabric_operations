#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2021 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2021 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import os
import time
import requests
import urllib3
import json
import sys
import logging
import datetime
import yaml

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from dotenv import load_dotenv
from dnacentersdk import DNACenterAPI
from datetime import datetime
from pprint import pprint
from requests.auth import HTTPBasicAuth  # for Basic Auth

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

load_dotenv('environment.env')

DNAC_URL = os.getenv('DNAC_URL')
DNAC_USER = os.getenv('DNAC_USER')
DNAC_PASS = os.getenv('DNAC_PASS')

os.environ['TZ'] = 'America/Los_Angeles'  # define the timezone for PST
time.tzset()  # adjust the timezone, more info https://help.pythonanywhere.com/pages/SettingTheTimezone/

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)


def time_sleep(time_sec):
    """
    This function will wait for the specified time_sec, while printing a progress bar, one '!' / second
    Sample Output :
    Wait for 10 seconds
    !!!!!!!!!!
    :param time_sec: time, in seconds
    :return: none
    """
    print('\nWait for ' + str(time_sec) + ' seconds')
    for i in range(time_sec):
        print('!', end='')
        time.sleep(1)
    return


def get_dnac_token(dnac_auth):
    """
    Create the authorization token required to access Cisco DNA Center
    Call to Cisco DNA Center - /api/system/v1/auth/login
    :param dnac_auth - Cisco DNA Center Basic Auth string
    :return Cisco DNA Center Token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    response_json = response.json()
    dnac_jwt_token = response_json['Token']
    return dnac_jwt_token


def provision_device(device_ip, site_hierarchy, dnac_token):
    """
    This function will provision a network device to a site
    :param device_ip: device management IP address
    :param site_hierarchy: site hierarchy, for example {Global/OR/PDX-1/Floor-2}
    :param dnac_token: Cisco DNA Center auth token
    :return: response, in JSON
    """
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/provision-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_fabric_site(site_hierarchy, dnac_token):
    """
    This function will create a new fabric at the site with the hierarchy {site_hierarchy}
    :param site_hierarchy: site hierarchy, for example {Global/OR/PDX-1/Floor-2}
    :param dnac_token: Cisco DNA Center auth token
    :return: response in JSON
    """
    payload = {
        "siteNameHierarchy": site_hierarchy
    }
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/fabric-site'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_edge_device(device_ip, site_hierarchy, dnac_token):
    """
    This function will add the device with the management IP address {device_ip}, as an edge device, to the fabric at
    the site with the hierarchy {site_hierarchy}
    :param device_ip: device management IP address
    :param site_hierarchy: fabric site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/edge-device'
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_control_plane_node(device_ip, site_hierarchy, dnac_token):
    """
    This function will add the device with the management IP address {device_ip}, as a control-plane node to the fabric
    at the site with the hierarchy {site_hierarchy}
    :param device_ip: device management IP address
    :param site_hierarchy: fabric site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/control-plane-device'
    payload = {
        'deviceManagementIpAddress': device_ip,
        'siteNameHierarchy': site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def add_border_device(payload, dnac_token):
    """
    This function will add a new border mode device to fabric
    :param payload: the required payload per the API docs
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/border-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_l3_vn(l3_vn_name, site_hierarchy, dnac_token):
    """
    This function will create a new L3 virtual network with the name {l3_vn_name} at the site
    with the hierarchy {site_hierarchy}
    :param l3_vn_name: L3 VN name
    :param site_hierarchy: site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/virtual-network'
    payload = {
        'virtualNetworkName': l3_vn_name,
        "siteNameHierarchy": site_hierarchy
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def create_auth_profile(auth_profile, site_hierarchy, dnac_token):
    """
    This function will create a new default auth profile for the fabric at the {site_hierarchy}
    :param auth_profile: auth profile, enum { No Authentication , Open Authentication, Closed Authentication, Low Impact}
    :param site_hierarchy: site hierarchy
    :param dnac_token: Cisco DNA Center auth token
    :return: API response
    """
    url = DNAC_URL + '/dna/intent/api/v1/business/sda/authentication-profile'
    payload = {
        'siteNameHierarchy': site_hierarchy,
        "authenticateTemplateName": auth_profile
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    return response_json


def main():
    """
    This script will create a new fabric at the site specified in the param provided.
    """

    # logging, debug level, to file {application_run.log}
    logging.basicConfig(
        filename='application_run.log',
        level=logging.DEBUG,
        format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')

    current_time = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print('\nCreate Fabric App Start, ', current_time)

    with open('fabric_operations.yml', 'r') as file:
        project_data = yaml.safe_load(file)

    print('\n\nProject Details:\n')
    pprint(project_data)

    # parse the input data
    area_name = project_data['area_info']['name']
    area_hierarchy = project_data['area_info']['hierarchy']

    building_name = project_data['building_info']['name']
    building_address = project_data['building_info']['address']
    building_lat = project_data['building_info']['lat']
    building_long = project_data['building_info']['long']

    floor_name = project_data['floor_info']['name']
    floor_number = project_data['floor_info']['number']
    floor_rf_model = project_data['floor_info']['rf_model']
    floor_width = project_data['floor_info']['width']
    floor_length = project_data['floor_info']['length']
    floor_height = project_data['floor_info']['height']

    site_hierarchy = 'Global/' + area_name + '/' + building_name + '/' + floor_name

    dhcp_server = project_data['network_settings']['dhcp_server']
    dns_server = project_data['network_settings']['dns_server']
    syslog_server = project_data['network_settings']['syslog_server']
    ntp_server = project_data['network_settings']['ntp_server']

    device_ips = project_data['devices_info']['device_ips']

    ip_pool_name = project_data['ip_pool']['name']
    ip_pool_type = project_data['ip_pool']['type']
    ip_pool_cidr = project_data['ip_pool']['subnet']
    ip_pool_gateway = project_data['ip_pool']['gateway']
    ip_pool_dhcp_server = project_data['ip_pool']['dhcp_server']
    ip_pool_dns_server = project_data['ip_pool']['dns_server']
    ip_pool_address_space = project_data['ip_pool']['address_family']

    ip_sub_pool_name = project_data['ip_sub_pool']['name']
    ip_sub_pool_type = project_data['ip_sub_pool']['type']
    ip_sub_pool_cidr = project_data['ip_sub_pool']['subnet']
    ip_sub_pool_gateway = project_data['ip_sub_pool']['gateway']
    ip_sub_pool_dhcp_server = project_data['ip_sub_pool']['dhcp_server']
    ip_sub_pool_dns_server = project_data['ip_sub_pool']['dns_server']
    ip_sub_pool_address_space = project_data['ip_sub_pool']['address_family']

    ip_transit_pool_name = project_data['ip_transit_pool']['name']
    ip_transit_pool_type = project_data['ip_transit_pool']['type']
    ip_transit_pool_cidr = project_data['ip_transit_pool']['subnet']
    ip_transit_pool_gateway = project_data['ip_transit_pool']['gateway']
    ip_transit_pool_dhcp_server = project_data['ip_transit_pool']['dhcp_server']
    ip_transit_pool_address_space = project_data['ip_transit_pool']['address_family']

    l3_vn_name = project_data['l3_vn']['name']

    border_device_ip = project_data['border_devices']['ip'][0]
    routing_protocol = project_data['border_devices']['routing_protocol']
    internal_bpg_as = str(project_data['border_devices']['internal_bgp_as'])
    external_bpg_as = str(project_data['border_devices']['external_bgp_as'])
    external_interface_name = project_data['border_devices']['external_interface']
    transit_network = project_data['border_devices']['transit_network']
    transit_vlan = str(project_data['border_devices']['transit_vlan'])

    control_plane_device_ips = project_data['control_plane_devices']['ip']
    edge_device_ips = project_data['edge_devices']['ip']

    default_auth_profile = project_data['auth_profile']['name']

    # Create a DNACenterAPI "Connection Object"
    dnac_api = DNACenterAPI(username=DNAC_USER, password=DNAC_PASS, base_url=DNAC_URL, version='2.2.2.3', verify=False)

    # get Cisco DNA Center Auth token
    dnac_auth = get_dnac_token(DNAC_AUTH)
    
    # create a new area
    print('\nCreating a new area:', area_name)
    area_payload = {
        "type": "area",
        "site": {
            "area": {
                "name": area_name,
                "parentName": area_hierarchy
            }
        }
    }
    response = dnac_api.sites.create_site(payload=area_payload)
    time_sleep(10)

    # create a new building
    print('\n\nCreating a new building:', building_name)
    building_payload = {
        'type': 'building',
        'site': {
            'building': {
                'name': building_name,
                'parentName': 'Global/' + area_name,
                'address': building_address,
                'latitude': building_lat,
                'longitude': building_long
            }
        }
    }
    response = dnac_api.sites.create_site(payload=building_payload)
    print(response.text)
    time_sleep(10)

    # create a new floor
    print('\n\nCreating a new floor:', floor_name)
    floor_payload = {
        'type': 'floor',
        'site': {
            'floor': {
                'name': floor_name,
                'parentName': 'Global/' + area_name + '/' + building_name,
                'height': floor_height,
                'length': floor_length,
                'width': floor_width,
                'rfModel': floor_rf_model
            }
        }
    }
    response = dnac_api.sites.create_site(payload=floor_payload)
    time_sleep(10)

    # create site network settings
    network_settings_payload = {
        'settings': {
            'dhcpServer': [
                dhcp_server
            ],
            'dnsServer': {
                'domainName': '',
                'primaryIpAddress': dns_server,
            },
            'syslogServer': {
                'ipAddresses': [
                    syslog_server
                ],
                'configureDnacIP': True
            },
            'ntpServer': [
                ntp_server
            ]
        }
    }

    # get the site_id
    print('\n\nConfiguring Network Settings:')
    pprint(project_data['network_settings'])
    response = dnac_api.sites.get_site(name=site_hierarchy)
    site_id = response['response'][0]['id']
    response = dnac_api.network_settings.create_network(site_id=site_id, payload=network_settings_payload)
    time_sleep(10)

    # add devices to inventory
    print('\n\nAdding devices to inventory: ')
    for ip_address in device_ips:
        add_device_payload = {
            "cliTransport": "ssh",
            "enablePassword": "apiuser123!",
            "ipAddress": [
                ip_address
            ],
            "password": "apiuser123!",
            "snmpRWCommunity": "wr!t3",
            "snmpVersion": "v2",
            "userName": "dnacenter"
        }
        response = dnac_api.devices.add_device(payload=add_device_payload)
        time.sleep(5)
    time_sleep(120)

    # add devices to site
    print('\n\nAssigning devices to site:', site_hierarchy)
    for ip_address in device_ips:
        assign_device_payload = {
            'device': [
                {
                    'ip': ip_address
                }
            ]
        }
        response = dnac_api.sites.assign_device_to_site(site_id=site_id, payload=assign_device_payload)
    time_sleep(60)
    
    # create a new Global Pool
    print('\n\nCreating the Global Pool: ', ip_pool_name)
    global_pool_payload = {
        'settings': {
            'ippool': [
                {
                    'ipPoolName': ip_pool_name,
                    'type': ip_pool_type,
                    'ipPoolCidr': ip_pool_cidr,
                    'gateway': ip_pool_gateway,
                    'dhcpServerIps': [
                        ip_pool_dhcp_server
                        ],
                    'dnsServerIps': [
                        ip_pool_dns_server
                        ],
                    'IpAddressSpace': ip_pool_address_space
                }
            ]
        }
    }
    response = dnac_api.network_settings.create_global_pool(payload=global_pool_payload)
    time_sleep(10)

    # create an IP sub_pool for site_hierarchy
    ip_sub_pool_subnet = ip_sub_pool_cidr.split('/')[0]
    ip_sub_pool_mask = int(ip_sub_pool_cidr.split('/')[1])
    print('\n\nCreating the IP subpool: ', ip_pool_cidr)
    sub_pool_payload = {
        'name': ip_sub_pool_name,
        'type': ip_sub_pool_type,
        'ipv4GlobalPool': ip_pool_cidr,
        'ipv4Prefix': True,
        'ipv6AddressSpace': False,
        'ipv4PrefixLength': ip_sub_pool_mask,
        'ipv4Subnet': ip_sub_pool_subnet,
        'ipv4GateWay': ip_sub_pool_gateway,
        'ipv4DhcpServers': [
            ip_sub_pool_dhcp_server
            ],
        'ipv4DnsServers': [
            ip_sub_pool_dns_server
            ],
        'ipv6Prefix': True,
        'ipv6GlobalPool': '2001:2021::1000/64',
        'ipv6PrefixLength': 96,
        'ipv6Subnet': '2001:2021::1000'
        }
    response = dnac_api.network_settings.reserve_ip_subpool(site_id=site_id, payload=sub_pool_payload)
    time_sleep(10)

    # create an IP transit pool for site_hierarchy
    print('\n\nCreating the IP transit pool: ', ip_transit_pool_cidr)
    ip_transit_pool_subnet = ip_transit_pool_cidr.split('/')[0]
    ip_transit_pool_mask = int(ip_transit_pool_cidr.split('/')[1])
    transit_pool_payload = {
        'name': ip_transit_pool_name,
        'type': ip_transit_pool_type,
        'ipv4GlobalPool': ip_pool_cidr,
        'ipv4Prefix': True,
        'ipv6AddressSpace': False,
        'ipv4PrefixLength': ip_transit_pool_mask,
        'ipv4Subnet': ip_transit_pool_subnet,
        'ipv4GateWay': ip_transit_pool_gateway,
        'ipv4DhcpServers': [
            ip_transit_pool_dhcp_server
            ],
        'ipv6Prefix': True,
        'ipv6GlobalPool': '2001:2021::1000/64',
        'ipv6PrefixLength': 96,
        'ipv6Subnet': '2001:2021::1000'
        }
    response = dnac_api.network_settings.reserve_ip_subpool(site_id=site_id, payload=transit_pool_payload)
    time_sleep(10)

    # create a new fabric at site
    print('\n\nCreating new fabric at site:', site_hierarchy)
    response = create_fabric_site(site_hierarchy, dnac_auth)
    time_sleep(15)

    # provision devices
    print('\n\nProvisioning devices to site:', site_hierarchy)
    for ip_address in device_ips:
        response = provision_device(ip_address, site_hierarchy, dnac_auth)
    time_sleep(120)

    # create L3 VN at global level
    print('\n\nCreating new L3 Virtual Network: ', l3_vn_name)
    l3_vn_payload = {
        'virtualNetworkName': l3_vn_name,
        "isGuestVirtualNetwork": False,
    }
    response = dnac_api.sda.add_virtual_network_with_scalable_groups(payload=l3_vn_payload)
    time_sleep(5)

    # assign Layer 3 VN to fabric
    print('\n\nAssign L3 Virtual Network: ', l3_vn_name)
    response = create_l3_vn(l3_vn_name, site_hierarchy, dnac_auth)
    time_sleep(5)

    # add auth profile to fabric
    print('\n\nAdding default auth profile to fabric: ', default_auth_profile)
    response = create_auth_profile(default_auth_profile, site_hierarchy, dnac_auth)
    time_sleep(5)

    # add control-plane node to fabric
    print('\n\nAdding control-plane devices to fabric: ', control_plane_device_ips)
    for device_ip in control_plane_device_ips:
        response = add_control_plane_node(device_ip, site_hierarchy, dnac_auth)
        time.sleep(2)
    time_sleep(5)

    # add border node to fabric
    print('\n\nAdding a border node device: ', border_device_ip)
    border_payload = {
        'deviceManagementIpAddress': border_device_ip,
        'siteNameHierarchy': site_hierarchy,
        'externalDomainRoutingProtocolName': routing_protocol,
        'externalConnectivityIpPoolName': ip_transit_pool_name,
        'internalAutonomouSystemNumber': internal_bpg_as,
        'borderSessionType': 'External',
        'connectedToInternet': True,
        'externalConnectivitySettings': [
            {
                'interfaceName': external_interface_name,
                'externalAutonomouSystemNumber': external_bpg_as,
                'l3Handoff': [
                    {
                        'virtualNetwork': {
                            'virtualNetworkName': l3_vn_name,
                            'vlanId': transit_vlan
                        }
                    }
                ]
            }
        ]
    }
    response = add_border_device(border_payload, dnac_auth)
    time_sleep(5)

    # add edge devices to fabric
    print('\n\nAdding edge devices to fabric: ', edge_device_ips)
    for device_ip in edge_device_ips:
        response = add_edge_device(device_ip, site_hierarchy, dnac_auth)
        time.sleep(2)
    time_sleep(5)

    current_time = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print('\n\nCreate Fabric App Run End, ', current_time)


if __name__ == '__main__':
    sys.exit(main())

