
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_f5_dns_record
short_description: Manage DNS records on BIG-IP ZoneRunner
description:
  - Manage DNS record on BIG-IP. The records managed here are primarily used
    for configuring DNS records on a BIG-IP ZoneRunner.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  zone_name:
    description:
      - Specifies the name of the DNS zone.
      - The name must begin with a letter and contain only letters, numbers,
        and the underscore character.
    type: str
    required: True
  view_name:
    description:
      - Specifies the name of the View.
    type: str
    default: external
  domain_name:
    description:
      - Specifies the domain name of the record.
    type: str
    required: True
  state:
    description:
      - Specifies the desired state of the DNS record.
      - When l(state=present) the module will attempt to create the specified
        DNS record if it does not already exist.
      - When l(state=absent), the module will remove the specified DNS
        record.
    type: str
    choices:
     - present
     - absent
    default: present
  type:
    description:
      - Specifies the type of DNS zone
    type: str
    choices:
      - A
      - AAAA
      - CNAME
      - DNAME
      - DS
      - HINFO
      - MX
      - NAPTR
      - NS
      - PTR
      - SRV
      - TXT
    required: True, if 'state' is 'present'
  ttl:
    description:
      - Specifies the TTL for this record.
    type: int
    required: True
  ip_address:
    description:
      - Specifies The ip address of the record.
      - Required when (type=A, AAA, PTR).
      - Supported only for (type=A, AAA, PTR).
    type: str
  reverse:
    description:
      - Indicating whether PTR records should automatically be generated.
      - When (reverse=0) the module will not to generate PTR
      - When (reverse=1) the module will attempt to generate the specified PTR
      - Supported only for (type=A, AAA).
    type: int
    choices:
      - 0
      - 1
    default: 0
  cname:
    description:
      - Specifies The cname of the record.
      - Required when (type=CNAME).
      - Supported only for (type=CNAME).
    type: str
  label:
    description:
      - Specifies The label of the record.
      - Required when (type=DNAME).
      - Supported only for (type=DNAME).
    type: str
  key_tag:
    description:
      - Specifies The keytag of the KEY record.
      - Required when (type=DS).
      - Supported only for (type=DS).
    type: str
  algorithm:
    description:
      - Specifies The algorithm used to calculate the key.
      - Required when (type=DS).
      - Supported only for (type=DS).
    type: str
  digest_type:
    description:
      - Specifies The digest type identifies the digest algorithm used.
      - Required when (type=DS).
      - Supported only for (type=DS).
    type: str
  digest:
    description:
      - Specifies The digest type identifies the digest algorithm used.
      - Required when (type=DS).
      - Supported only for (type=DS).
    type: str
  hardware:
    description:
      - Specifies The hardware info for this record.
      - Required when (type=HINFO).
      - Supported only for (type=HINFO).
    type: str
  os:
    description:
      - Specifies The OS info for the record.
      - Required when (type=HINFO).
      - Supported only for (type=HINFO).
    type: str
  preference:
    description:
      - Specifies The preference to use for this record.
      - Required when (type=MX, NAPTR).
      - Supported only for (type=MX, NAPTR).
    type: str
  mail:
    description:
      - Specifies The mail-exchanger for this record.
      - Required when (type=MX).
      - Supported only for (type=MX).
    type: str
  order:
    description:
      - Specifies The order in which the records MUST be processed.
      - Required when (type=NAPTR).
      - Supported only for (type=NAPTR).
    type: str
  flags:
    description:
      - Specifies A character string containing flags to control interpretation of the remaining fields in the record.
      - Required when (type=NAPTR).
      - Supported only for (type=NAPTR).
    type: str
  service:
    description:
      - Specifies The service(s) available down this rewrite path.
      - Required when (type=NAPTR).
      - Supported only for (type=NAPTR).
    type: str
  regexp:
    description:
      - Specifies A string containing a substituion expression.
      - Required when (type=NAPTR).
      - Supported only for (type=NAPTR).
    type: str
  replacement:
    description:
      - Specifies The next NAME to query for NAPTR, SRV or address records.
      - Required when (type=NAPTR).
      - Supported only for (type=NAPTR).
    type: str
  host_name:
    description:
      - Specifies The hostname of the Name Server.
      - Required when (type=NS).
      - Supported only for (type=NS).
    type: str
  priority:
    description:
      - Specifies The priority to use for this record.
      - Required when (type=SRV).
      - Supported only for (type=SRV).
    type: int
  weight:
    description:
      - Specifies The weight to use for this record.
      - Required when (type=SRV).
      - Supported only for (type=SRV).
    type: int
  port:
    description:
      - Specifies The port for this service.
      - Required when (type=SRV).
      - Supported only for (type=SRV).
    type: int
  target:
    description:
      - Specifies The target to use for this record.
      - Required when (type=SRV).
      - Supported only for (type=SRV).
    type: str
  text:
    description:
      - Specifies The text entry for the record.
      - Required when (type=TXT).
      - Supported only for (type=TXT).
    type: str
  provider:
    type: dict
    suboptions:
      user:
        description:
          - The username to connect to the BIG-IP with. This user must have administrative privileges on the device.
          - You may omit this option by setting the environment variable F5_USER or ANSIBLE_NET_USERNAME
        type: str
        required: True
      password:
        description:
          - The password for the user account used to connect to the BIG-IP.
          - You may omit this option by setting the environment variable F5_PASSWORD or ANSIBLE_NET_PASSWORD
        type: str
        required: True
      host:
        description:
          - The BIG-IP host.
          - You may omit this option by setting the environment variable F5_HOST
        type: str
        required: True
      host_port:
        description:
          - The BIG-IP server port.
          - You may omit this option by setting the environment variable F5_HOST_PORT
        type: int
        default: 443
        required: False
"""

EXAMPLES = """
tasks:
  - name: Create an A record
    o4n_f5_dns_zone:
      name:
      type: A
      state: present
      ttl:
      ip_address:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an AAAA record
    o4n_f5_dns_zone:
      name:
      type: AAAA
      state: present
      ttl:
      ip_address:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an CNAME record
    o4n_f5_dns_zone:
      name:
      type: CNAME
      state: present
      ttl:
      cname:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an DNAME record
    o4n_f5_dns_zone:
      name:
      type: DNAME
      state: present
      ttl:
      label:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an DS record
    o4n_f5_dns_zone:
      name:
      type: DS
      state: present
      ttl:
      key_tag:
      algorithm:
      digest_type:
      digest:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an HINFO record
    o4n_f5_dns_zone:
      name:
      type: HINFO
      state: present
      ttl:
      hardware:
      os:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an MX record
    o4n_f5_dns_zone:
      name:
      type: MX
      state: present
      ttl:
      preference:
      mail:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an NAPTR record
    o4n_f5_dns_zone:
      name:
      type: NAPTR
      state: present
      ttl:
      order:
      preference:
      flags:
      service:
      regexp:
      replacement:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an NS record
    o4n_f5_dns_zone:
      name:
      type: NS
      state: present
      ttl:
      host_name:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an PTR record
    o4n_f5_dns_zone:
      name:
      type: PTR
      state: present
      ttl:
      ip_address:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an SRV record
    o4n_f5_dns_zone:
      name:
      type: SRV
      state: present
      ttl:
      priority:
      weight:
      port:
      target:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Create an TXT record
    o4n_f5_dns_zone:
      name:
      type: TXT
      state: present
      ttl:
      text:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost


  - name: Delete an A record
    o4n_f5_dns_zone:
      name:
      type: A
      state: absent
      ttl:
      ip_address:
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost
"""
RETURN = """
output:
  description: List of Zones created
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": false,
        "msg": [
            "Record 'record.com.' added to Zone 'zone.com.'. Value:",
            {
                "domain_name": "record.com.",
                "ip_address": "192.168.0.10",
                "ttl": 3600
            }
        ],
        "failed": false,
      }
"""

import bigsuds
from ansible.module_utils.basic import AnsibleModule, env_fallback


# Decorator Functions
def create_record_decorator(function):
    def decorator_function(_provider, _zone_name, _view_zone, _name, *args, **kwargs):
        try:
            b = bigsuds.BIGIP(hostname=_provider['host'], port=_provider['host_port'], username=_provider['user'], password=_provider['password'])
            zone_view = {
                'view_name': _view_zone,
                'zone_name': _zone_name
            }

            rr_values = function(b, zone_view, _provider, _zone_name, _view_zone, _name, *args, **kwargs)

            values_list = []
            for values in rr_values.values():
                values_list.append(str(values))

            rrs = b.Management.ResourceRecord.get_rrs([zone_view])
            exist = [0]
            for rr in rrs[0]:
                if all(item in rr for item in values_list):
                    exist = [1]

            if 1 in exist:
                status = True
                msg_ret = f"Record '{_name}' added to Zone '{_zone_name}'. Value:", rr_values
                return status, msg_ret, []
            elif 0 in exist:
                status = False
                msg_ret = f"Record '{_name}' was not added to Zone '{_zone_name}'. Value:", rr_values
                return status, msg_ret, []

        except Exception as error:
            print(error)
            status = False
            msg_ret = f"error: <{error}>"
            return status, msg_ret, []

    return decorator_function


def delete_record_decorator(function):
    def decorator_function(_provider, _zone_name, _view_zone, _name, *args, **kwargs):
        try:
            b = bigsuds.BIGIP(hostname=_provider['host'], port=_provider['host_port'], username=_provider['user'], password=_provider['password'])
            zone_view = {
                'view_name': _view_zone,
                'zone_name': _zone_name
            }

            rr_values = function(b, zone_view, _provider, _zone_name, _view_zone, _name, *args, **kwargs)

            values_list = []
            for valus in rr_values.values():
                values_list.append(str(valus))

            rrs = b.Management.ResourceRecord.get_rrs([zone_view])
            exist = [0]
            for rr in rrs[0]:
                if all(item in rr for item in values_list):
                    exist = [1]

            if 0 in exist:
                status = True
                msg_ret = f"Record '{_name}' deleted on Zone '{_zone_name}'. Value:", rr_values
                return status, msg_ret, []
            elif 1 in exist:
                status = False
                msg_ret = f"Record '{_name}' was not deleted to Zone '{_zone_name}'. Value:", rr_values
                return status, msg_ret, []

        except Exception as error:
            print(error)
            status = False
            msg_ret = f"error: <{error}>"
            return status, msg_ret, []

    return decorator_function


# Creation Functions
@create_record_decorator
def create_record_a(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _ip_address, _reverse):
    rr_values = {
        'domain_name': _name,
        'ip_address': _ip_address,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_a(view_zones=[zone_view],
                                      a_records=[[rr_values]],
                                      sync_ptrs=[_reverse])
    return rr_values


@create_record_decorator
def create_record_aaaa(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _ip_address, _reverse):
    rr_values = {
        'domain_name': _name,
        'ip_address': _ip_address,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_aaaa(view_zones=[zone_view],
                                         aaaa_records=[[rr_values]],
                                         sync_ptrs=[_reverse])
    return rr_values


@create_record_decorator
def create_record_cname(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _cname):
    rr_values = {
        'domain_name': _name,
        'cname': _cname,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_cname(view_zones=[zone_view],
                                          cname_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_dname(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _label):
    rr_values = {
        'domain_name': _name,
        'label': _label,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_dname(view_zones=[zone_view],
                                              dname_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_ds(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _key_tag, _algorithm, _digest_type, _digest):
    rr_values = {
        'domain_name': _name,
        'key_tag': _key_tag,
        'algorithm': _algorithm,
        'digest_type': _digest_type,
        'digest': _digest,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_ds(view_zones=[zone_view],
                                       ds_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_hinfo(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _hardware, _os):
    rr_values = {
        'domain_name': _name,
        'hardware': _hardware,
        'os': _os,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_hinfo(view_zones=[zone_view],
                                          hinfo_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_mx(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _preference, _mail):
    rr_values = {
        'domain_name': _name,
        'preference': _preference,
        'mail': _mail,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_mx(view_zones=[zone_view],
                                       mx_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_naptr(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _order, _preference, _flags, _service, _regexp, _replacement):
    rr_values = {
        'domain_name': _name,
        'order': _order,
        'preference': _preference,
        'flags': _flags,
        'service': _service,
        'regexp': _regexp,
        'replacement': _replacement,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_naptr(view_zones=[zone_view],
                                          naptr_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_ns(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _host_name):
    rr_values = {
        'domain_name': _name,
        'host_name': _host_name,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_ns(view_zones=[zone_view],
                                       ns_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_ptr(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _dname):
    rr_values = {
        'ip_address': _name,
        'dname': _dname,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_ptr(view_zones=[zone_view],
                                        ptr_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_srv(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _priority, _weight, _port, _target):
    rr_values = {
        'domain_name': _name,
        'priority': _priority,
        'weight': _weight,
        'port': _port,
        'target': _target,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_srv(view_zones=[zone_view],
                                        srv_records=[[rr_values]])
    return rr_values


@create_record_decorator
def create_record_txt(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _text):
    rr_values = {
        'domain_name': _name,
        'text': _text,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.add_txt(view_zones=[zone_view],
                                        txt_records=[[rr_values]])
    return rr_values


# Delete Functions
@delete_record_decorator
def delete_record_a(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _ip_address, _reverse):
    rr_values = {
        'domain_name': _name,
        'ip_address': _ip_address,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_a(view_zones=[zone_view],
                                         a_records=[[rr_values]],
                                         sync_ptrs=[_reverse])
    return rr_values


@delete_record_decorator
def delete_record_aaaa(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _ip_address, _reverse):
    rr_values = {
        'domain_name': _name,
        'ip_address': _ip_address,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_aaaa(view_zones=[zone_view],
                                            aaaa_records=[[rr_values]],
                                            sync_ptrs=[_reverse])
    return rr_values


@delete_record_decorator
def delete_record_cname(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _cname):
    rr_values = {
        'domain_name': _name,
        'cname': _cname,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_cname(view_zones=[zone_view],
                                             cname_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_dname(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _label):
    rr_values = {
        'domain_name': _name,
        'label': _label,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_dname(view_zones=[zone_view],
                                             dname_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_ds(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _key_tag, _algorithm, _digest_type, _digest):
    rr_values = {
        'domain_name': _name,
        'key_tag': _key_tag,
        'algorithm': _algorithm,
        'digest_type': _digest_type,
        'digest': _digest,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_ds(view_zones=[zone_view],
                                          ds_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_hinfo(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _hardware, _os):
    rr_values = {
        'domain_name': _name,
        'hardware': _hardware,
        'os': _os,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_hinfo(view_zones=[zone_view],
                                             hinfo_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_mx(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _preference, _mail):
    rr_values = {
        'domain_name': _name,
        'preference': _preference,
        'mail': _mail,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_mx(view_zones=[zone_view],
                                          mx_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_naptr(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _order, _preference, _flags, _service, _regexp, _replacement):
    rr_values = {
        'domain_name': _name,
        'order': _order,
        'preference': _preference,
        'flags': _flags,
        'service': _service,
        'regexp': _regexp,
        'replacement': _replacement,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_naptr(view_zones=[zone_view],
                                             naptr_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_ns(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _host_name):
    rr_values = {
        'domain_name': _name,
        'host_name': _host_name,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_ns(view_zones=[zone_view],
                                          ns_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_ptr(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _dname):
    rr_values = {
        'dname': _dname,
        'ip_address': _name,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_ptr(view_zones=[zone_view],
                                           ptr_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_srv(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _priority, _weight, _port, _target):
    rr_values = {
        'domain_name': _name,
        'priority': _priority,
        'weight': _weight,
        'port': _port,
        'target': _target,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_srv(view_zones=[zone_view],
                                           srv_records=[[rr_values]])
    return rr_values


@delete_record_decorator
def delete_record_txt(b, zone_view, _provider, _zone_name, _view_zone, _name, _ttl, _text):
    rr_values = {
        'domain_name': _name,
        'text': _text,
        'ttl': _ttl
      }
    b.Management.ResourceRecord.delete_txt(view_zones=[zone_view],
                                           txt_records=[[rr_values]])
    return rr_values


def argument_spec():
    argument_spec = dict(
        zone_name=dict(required=True, type='str'),
        view_zone=dict(required=False, type='str', default = "external"),
        name=dict(required=True, type='str'),
        state=dict(required=False, type='str', choices=['present', 'absent'], default = "present"),
        type=dict(required=True, type='str', choice=['A', 'AAAA', 'CNAME', 'DNAME', 'DS', 'HINFO', 'MX', 'NAPTR', 'NS', 'PTR', 'SRV', 'TXT']),
        ttl=dict(required=False, type='int', default= 0),
        ip_address=dict(required=False, type='str'),
        reverse=dict(required=False, type='int', choice=[0, 1], default= 0),
        cname=dict(required=False, type='str'),
        label=dict(required=False, type='str'),
        key_tag=dict(required=False, type='int'),
        algorithm=dict(required=False, type='int'),
        digest_type=dict(required=False, type='int'),
        digest=dict(required=False, type='str'),
        hardware=dict(required=False, type='str'),
        os=dict(required=False, type='str'),
        preference=dict(required=False, type='int'),
        mail=dict(required=False, type='str'),
        order=dict(required=False, type='int'),
        flags=dict(required=False, type='str'),
        service=dict(required=False, type='str'),
        regexp=dict(required=False, type='str'),
        replacement=dict(required=False, type='str'),
        host_name=dict(required=False, type='str'),
        dname=dict(required=False, type='str'),
        priority=dict(required=False, type='int'),
        weight=dict(required=False, type='int'),
        port=dict(required=False, type='int'),
        target=dict(required=False, type='str'),
        text=dict(required=False, type='str'),
        provider=dict(
            type='dict',
            default={},
            options=dict(
                user=dict(
                    required=True,
                    fallback=(env_fallback, ['F5_USER', 'ANSIBLE_NET_USERNAME'])
                ),
                password=dict(
                    required=True,
                    no_log=True,
                    fallback=(env_fallback, ['F5_PASSWORD', 'ANSIBLE_NET_PASSWORD'])
                ),
                host=dict(
                    required=True,
                    fallback=(env_fallback, ['F5_HOST'])
                ),
                host_port=dict(
                    type='int',
                    default=443,
                    fallback=(env_fallback, ['F5_HOST_PORT'])
                )
            )
        )
    )

    return argument_spec


def main():
    spec = argument_spec()
    module = AnsibleModule(
        argument_spec=spec,
        required_if=[
            ('type', 'A', ['ip_address']),
            ('type', 'AAAA', ['ip_address']),
            ('type', 'CNAME', ['cname']),
            ('type', 'DNAME', ['label']),
            ('type', 'DS', ['key_tag', 'algorithm', 'digest_type', 'digest']),
            ('type', 'HINFO', ['hardware', 'os']),
            ('type', 'MX', ['preference', 'mail']),
            ('type', 'NAPTR', ['order', 'preference', 'flags', 'service', 'regexp', 'replacement']),
            ('type', 'NS', ['host_name']),
            ('type', 'PTR', ['dname']),
            ('type', 'SRV', ['priority', 'weight', 'port', 'target']),
            ('type', 'TXT', ['text']),
            ('state', 'present', ['ttl']),
        ]
    )

    zone_name = module.params.get("zone_name")
    view_zone = module.params.get("view_zone")
    name = module.params.get("name")
    state = module.params.get("state")
    rr_type = module.params.get("type")
    ttl = module.params.get("ttl")
    ip_address = module.params.get("ip_address")
    reverse = module.params.get("reverse")
    cname = module.params.get("cname")
    label = module.params.get('label')
    key_tag = module.params.get('key_tag')
    algorithm = module.params.get('algorithm')
    digest_type = module.params.get('digest_type')
    digest = module.params.get('digest')
    hardware = module.params.get('hardware')
    os = module.params.get('os')
    preference = module.params.get('preference')
    mail = module.params.get('mail')
    order = module.params.get('order')
    flags = module.params.get('flags')
    service = module.params.get('service')
    regexp = module.params.get('regexp')
    replacement = module.params.get('replacement')
    host_name = module.params.get('host_name')
    dname = module.params.get('dname')
    priority = module.params.get('priority')
    weight = module.params.get('weight')
    port = module.params.get('port')
    target = module.params.get('target')
    text = module.params.get('text')
    provider = module.params.get('provider')

    if state == "present":
        if rr_type == 'A':
            success, msg_ret, output = create_record_a(provider, zone_name, view_zone, name, ttl, ip_address, reverse)
        elif rr_type == 'AAAA':
            success, msg_ret, output = create_record_aaaa(provider, zone_name, view_zone, name, ttl, ip_address, reverse)
        elif rr_type == 'CNAME':
            success, msg_ret, output = create_record_cname(provider, zone_name, view_zone, name, ttl, cname)
        elif rr_type == 'DNAME':
            success, msg_ret, output = create_record_dname(provider, zone_name, view_zone, name, ttl, label)
        elif rr_type == 'DS':
            success, msg_ret, output = create_record_ds(provider, zone_name, view_zone, name, ttl, key_tag, algorithm, digest_type, digest)
        elif rr_type == 'HINFO':
            success, msg_ret, output = create_record_hinfo(provider, zone_name, view_zone, name, ttl, hardware, os)
        elif rr_type == 'MX':
            success, msg_ret, output = create_record_mx(provider, zone_name, view_zone, name, ttl, preference, mail)
        elif rr_type == 'NAPTR':
            success, msg_ret, output = create_record_naptr(provider, zone_name, view_zone, name, ttl, order, preference, flags, service, regexp, replacement)
        elif rr_type == 'NS':
            success, msg_ret, output = create_record_ns(provider, zone_name, view_zone, name, ttl, host_name)
        elif rr_type == 'PTR':
            success, msg_ret, output = create_record_ptr(provider, zone_name, view_zone, name, ttl, dname)
        elif rr_type == 'SRV':
            success, msg_ret, output = create_record_srv(provider, zone_name, view_zone, name, ttl, priority, weight, port, target)
        elif rr_type == 'TXT':
            success, msg_ret, output = create_record_txt(provider, zone_name, view_zone, name, ttl, text)

        if success:
            module.exit_json(failed=False, msg=msg_ret, content=output)
        else:
            module.fail_json(failed=True, msg=msg_ret, content=output)

    elif state == "absent":
        if rr_type == 'A':
            success, msg_ret, output = delete_record_a(provider, zone_name, view_zone, name, ttl, ip_address, reverse)
        elif rr_type == 'AAAA':
            success, msg_ret, output = delete_record_aaaa(provider, zone_name, view_zone, name, ttl, ip_address, reverse)
        elif rr_type == 'CNAME':
            success, msg_ret, output = delete_record_cname(provider, zone_name, view_zone, name, ttl, cname)
        elif rr_type == 'DNAME':
            success, msg_ret, output = delete_record_dname(provider, zone_name, view_zone, name, ttl, label)
        elif rr_type == 'DS':
            success, msg_ret, output = delete_record_ds(provider, zone_name, view_zone, name, ttl, key_tag, algorithm, digest_type, digest)
        elif rr_type == 'HINFO':
            success, msg_ret, output = delete_record_hinfo(provider, zone_name, view_zone, name, ttl, hardware, os)
        elif rr_type == 'MX':
            success, msg_ret, output = delete_record_mx(provider, zone_name, view_zone, name, ttl, preference, mail)
        elif rr_type == 'NAPTR':
            success, msg_ret, output = delete_record_naptr(provider, zone_name, view_zone, name, ttl, order, preference, flags, service, regexp, replacement)
        elif rr_type == 'NS':
            success, msg_ret, output = delete_record_ns(provider, zone_name, view_zone, name, ttl, host_name)
        elif rr_type == 'PTR':
            success, msg_ret, output = delete_record_ptr(provider, zone_name, view_zone, name, ttl, dname)
        elif rr_type == 'SRV':
            success, msg_ret, output = delete_record_srv(provider, zone_name, view_zone, name, ttl, priority, weight, port, target)
        elif rr_type == 'TXT':
            success, msg_ret, output = delete_record_txt(provider, zone_name, view_zone, name, ttl, text)

        if success:
            module.exit_json(failed=False, msg=msg_ret, content=output)
        else:
            module.fail_json(failed=True, msg=msg_ret, content=output)


if __name__ == "__main__":
    main()
