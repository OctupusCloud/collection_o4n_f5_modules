
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_f5_dns_zone
short_description: Manage DNS zones on BIG-IP ZoneRunner
description:
  - Manage DNS zones on BIG-IP. The zones managed here are primarily used
    for configuring DNS on a BIG-IP ZoneRunner.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  name:
    description:
      - Specifies the name of the DNS zone.
      - The name must begin with a letter and contain only letters, numbers,
        and the underscore character.
    type: str
    required: True
  view:
    description:
      - Specifies the name of the View.
    type: str
    default: external
  state:
    description:
      - Specifies the desired state of the DNS zone.
      - When l(state=present) the module will attempt to create the specified
        DNS zone if it does not already exist.
      - When l(state=absent), the module will remove the specified DNS
        zone and all subsequent DNS records.
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
      - MASTER
      - SLAVE
      - STUB
      - FORWARD
      - HINT
    required: True, if 'state' is 'present'
  file:
    description:
      - Specifies the File of the Zone.
    type: str
    required: True, if 'state' is 'present'
  option_seq:
    description:
      - Specifies the Options of the Zone.
    type: list
    elements: str
    required: True, if 'state' is 'present'
  records:
    type: dict
    suboptions:
      soa:
        type: dict
        suboptions:
          ttl:
            description:
              - The "time to live" of the record.
            type: int
            required: True, if 'state' is 'present'
          master_server:
            description:
              - Specifies the Master Server of the record.
            type: str
            required: True, if 'state' is 'present'
          email_contact:
            description:
              - Specifies the Email Contact of the person responsible for the zone.
            type: str
            required: True, if 'state' is 'present'
          serial_number:
            description:
              - Specifies the serial number to start with for this zone
            type: int
            required: True, if 'state' is 'present'
          refresh_interval:
            description:
              - The refresh interval(secs) for the zone
            type: int
            required: True, if 'state' is 'present'
          retry_interval:
            description:
              - The interval(secs) between retries for the zone
            type: int
            required: True, if 'state' is 'present'
          expire:
            description:
              - The upper limit(secs) before a zone expires
            type: int
            required: True, if 'state' is 'present'
          negative_ttl:
            description:
              - The Negative TTL for any RR from this zone
            type: int
            required: True, if 'state' is 'present'
      ns:
        type: dict
        suboptions:
          ttl:
            description:
              - The "time to live" of the record.
            type: int
            required: True, if 'state' is 'present'
          name_server:
            description:
              - The Nameserver of the record
            type: str
            required: True, if 'state' is 'present'
      a:
        type: dict
        suboptions:
          ip_address:
            description:
              - Specifies an list of IP addresses of the Record
            type: str
            required: True, if 'state' is 'present'
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
  - name: Create a DNS zone for DNS Zonnerunner
    o4n_f5_dns_zone:
      name: zone.foo.com.
      view: external
      state: present
      type: MASTER
      file: db.external.zone.foo.com
      option_seq:
        - 'allow-update {
              localhost;
          };
          '
      records:
        soa:
          ttl: 86400
          master_server: foo1.zone.foo.com.
          email_contact: hostmaster.zone.foo.com.
          serial_number: 2023030201
          refresh_interval: 10800
          retry_interval: 3600
          expire: 604800
          negative_ttl: 86400
        ns:
          ttl: 30
          name_server: foo1.zone.foo.com.
        a:
          ip_address: 192.168.0.10
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Delete a DNS zone for DNS Zonnerunner
    o4n_f5_dns_zone:
      name: zone.foo.com.
      view: external
      state: absent
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    register: output
    delegate_to: localhost

  - name: Delete multiple DNS zone for DNS Zonnerunner
    o4n_f5_dns_zone:
      name: "{{ item }}"
      view: external
      state: absent
      provider:
        user: admin
        password: secrt
        host: 192.168.0.2
        host_port: 443
    loop:
      - zone1.foo.com.
      - zone2.foo.com.
      - zone3.foo.com.
    register: output
    delegate_to: localhost

  - name: Update a DNS zone for DNS Zonnerunner
    o4n_f5_dns_zone:
      name: zone.foo.com.
      view: external
      state: present
      type: MASTER
      file: db.external.zone.foo.com
      option_seq:
        - 'allow-update {
              localhost;
          };
          '
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
            "Zone zone.com. created: ",
            [
                "view_name: external",
                "zone_name: zone.com.",
                "zone_type: MASTER",
                "zone_file: db.external.zone.com.",
                "option_seq: ['allow-update {    localhost;};']"
            ]
        ],
        "failed": false,
      }

output:
  description: List of Zones deleted
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": false,
        "msg": "Zone zone.com. deleted: ",
        "failed": false,
      }
"""

from datetime import datetime
import bigsuds
from ansible.module_utils.basic import AnsibleModule, env_fallback


def create_zone(_zone_name, _view_zone, _zone_type, _zone_file, option_seq, _records, _provider):
    try:
        b = bigsuds.BIGIP(hostname=_provider['host'], port=_provider['host_port'], username=_provider['user'], password=_provider['password'])
        zone_view = {
            'view_name': _view_zone,
            'zone_name': _zone_name
        }
        zone_add_info = {
                    'view_name': _view_zone,
                    'zone_name': _zone_name,
                    'zone_type': _zone_type,
                    'zone_file': _zone_file,
                    'option_seq': option_seq
                }
        zone_add_records = ""
        zone_exist = b.Management.Zone.zone_exist([zone_view])
        if 0 in zone_exist:
            if _zone_type == "MASTER" and _records is not None:
                date = datetime.now().strftime("%Y%m%d")
                soa_ttl = _records['soa']['ttl']
                soa_master_server = _records['soa']['master_server']
                soa_email_contact = _records['soa']['email_contact']
                soa_serial_number = date + "99"
                soa_refresh_interval = _records['soa']['refresh_interval']
                soa_retry_interval = _records['soa']['retry_interval']
                soa_expire = _records['soa']['expire']
                soa_negative_ttl = _records['soa']['negative_ttl']
                ns_ttl = _records['ns']['ttl']
                ns_name_server = _records['ns']['ttl']
                a_ip_address = _records['a']['ip_address']
                zone_add_records = f'{_zone_name} {soa_ttl} IN SOA {soa_master_server} {soa_email_contact} {soa_serial_number} {soa_refresh_interval} {soa_retry_interval} {soa_expire} {soa_negative_ttl};\n' \
                                  f'{_zone_name} {ns_ttl} IN NS {ns_name_server};\n' \
                                  f'{ns_name_server} {ns_ttl} IN A {a_ip_address};'

            b.Management.Zone.add_zone_text([zone_add_info], [[zone_add_records]], [0])
            zone_exist = b.Management.Zone.zone_exist([zone_view])
            if 0 in zone_exist:
                status = False
                msg_ret = f"Zone {_zone_name} was not created"
                return status, msg_ret, []
            elif 1 in zone_exist:
                zone = b.Management.Zone.get_zone_v2([zone_view])
                status = True
                msg_ret = f"Zone {_zone_name} was created: ", [f'{k}: {v}' for k, v in zone[0].items()]
                return status, msg_ret, []
        elif 1 in zone_exist:
            zone_old = b.Management.Zone.get_zone_v2([zone_view])
            for options in zone_old:
                option_seq_old = options["option_seq"]
                if (option_seq is not []) and (option_seq != option_seq_old):
                    zone_info = {
                        'view_name': _view_zone,
                        'zone_name': _zone_name,
                        'option_seq': option_seq
                    }
                    b.Management.Zone.set_zone_option([zone_info])
                    zone = b.Management.Zone.get_zone_v2([zone_view])
                    status = True
                    msg_ret = f"Zone {_zone_name} was updated in View '{_view_zone}'", [f'{k}: {v}' for k, v in zone[0].items()]
                    return status, msg_ret, []
            status = True
            msg_ret = f"Zone {_zone_name} already exists in View '{_view_zone}'.."
            return status, msg_ret, []

    except Exception as error:
        status = False
        msg_ret = f"error: <{error}>"
        return status, msg_ret, []


def delete_zone(_zone_name, _view_zone, _provider):
    try:
        b = bigsuds.BIGIP(hostname=_provider['host'], port=_provider['host_port'], username=_provider['user'], password=_provider['password'])
        zone_view = {
                'view_name': _view_zone,
                'zone_name': _zone_name
            }
        zone_exist = b.Management.Zone.zone_exist([zone_view])
        if 1 in zone_exist:
            b.Management.Zone.delete_zone([zone_view])
            zone_exist = b.Management.Zone.zone_exist([zone_view])
            if 1 in zone_exist:
                status = False
                msg_ret = f"Zone {_zone_name} was not deleted"
                return status, msg_ret, []
            elif 0 in zone_exist:
                status = True
                msg_ret = f"Zone {_zone_name} was deleted"
                return status, msg_ret, []
        elif 0 in zone_exist:
            status = True
            msg_ret = f"Zone '{_zone_name}', no exists in View '{_view_zone}'.."
            return status, msg_ret, []
    except Exception as error:
        status = False
        msg_ret = f"error: <{error}>"
        return status, msg_ret, []


def argument_spec():
    argument_spec = dict(
        name=dict(required=True, type='str'),
        view=dict(required=False, type='str', default = "external"),
        state=dict(required=False, type='str', choices=['present', 'absent'], default = "present"),
        type=dict(required=False, type='str', choice=['MASTER', 'SLAVE', 'STUB', 'FORWARD', 'HINT']),
        file=dict(required=False, type='str', default=" "),
        option_seq=dict(required=False, type='list', elements='str', default=[]),
        records=dict(
            required=False,
            type='dict',
            options=dict(
                soa=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        ttl=dict(required=False, type='int'),
                        master_server=dict(required=False, type='str'),
                        email_contact=dict(required=False, type='str'),
                        serial_number=dict(required=False, type='int'),
                        refresh_interval=dict(required=False, type='int', default= 10800),
                        retry_interval=dict(required=False, type='int', default= 3600),
                        expire=dict(required=False, type='int', default= 604800),
                        negative_ttl=dict(required = False, type = 'int', default = 86400)
                    )
                ),
                ns=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        ttl=dict(required=False, type='int'),
                        name_server=dict(required=False, type='str')
                    )
                ),
                a=dict(
                    required=False,
                    type='dict',
                    options=dict(
                        ip_address=dict(required=False, type='str')
                    )
                )
            )
        ),
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
                ('type', 'MASTER', ['file', 'option_seq']),
                ('type', 'SLAVE', ['file', 'option_seq']),
                ('type', 'STUB', ['file', 'option_seq']),
                ('type', 'FORWARD', ['option_seq']),
                ('type', 'HINT', ['file'])
            ]
    )
    zone_name = module.params.get("name")
    view_zone = module.params.get("view")
    state = module.params.get("state")
    zone_type = module.params.get("type")
    zone_file = module.params.get("file")
    option_seq = module.params.get("option_seq")
    records = module.params.get("records")
    provider = module.params.get('provider')

    if state == "present":
        success, msg_ret, output = create_zone(zone_name, view_zone, zone_type, zone_file, option_seq, records, provider)
        if success:
            module.exit_json(failed=False, msg=msg_ret, content=output)
        else:
            module.fail_json(failed=True, msg=msg_ret, content=output)
    elif state == "absent":
        success, msg_ret, output = delete_zone(zone_name, view_zone, provider)
        if success:
            module.exit_json(failed=False, msg=msg_ret, content=output)
        else:
            module.fail_json(failed=True, msg=msg_ret, content=output)


if __name__ == "__main__":
    main()
