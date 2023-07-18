#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Contributors to the Octupus project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'octupus',
                    'metadata_version': '1.1'}

DOCUMENTATION = """
---
module: o4n_prune_disabled_node_from_date
short_description: Its main function is the ability to remove (or "prune") nodes that have been disabled since a specific date on BIG-IP.
description:
  - Its main function is the ability to remove (or "prune") nodes that have been disabled since a specific date on BIG-IP.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
options:
  before_date:
    description:
      - This is a specific date provided as an input to the module. 
      - The main function of the module will use this date as a reference point to remove all nodes that have been disabled before this date.
      - The date should be provided in the YYYY/MM/DD format.
    type: str
    required: True
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
          - You may omit this option by setting the environment variable F5_SERVER
        type: str
        required: True
      port:
        description:
          - The BIG-IP server port.
          - You may omit this option by setting the environment variable F5_SERVER_PORT
        type: int
        default: 443
        required: False
      validate_certs:
        description:
          - If no, SSL certificates are not validated. Use this only on personally controlled sites using self-signed certificates.
          - You may omit this option by setting the environment variable F5_VALIDATE_CERTS.
          - Choices: false ← (default), true
        type: bool
        default: False
        required: False
"""

EXAMPLES = """
tasks:
  - name: Remove Disabled Nodes
    o4n_prune_disabled_node_from_date:
      before_date: "2023/07/17"
    register: output
"""
RETURN = """
output:
  description: The Remove Disabled Nodes output
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": false,
        "content": [
            {
                "addr": "192.168.0.1",
                "availability_state": "offline",
                "enabled_state": "disabled",
                "node": "/Common/remove_server",
                "status_reason": "/Common/icmp: No successful responses received before deadline. @2023/07/17 19:52:21. "
            }
        ],
        "failed": false,
        "msg": "Se han eliminado un total de 107  Nodos que se encontraban en estado 'Disabled' con fecha inferior a 2023/07/17."
      }
"""

import re
import json
import requests
import traceback
from datetime import datetime
from requests.auth import HTTPBasicAuth
from ansible.module_utils.basic import AnsibleModule, env_fallback

# Deshabilitar los warnings de SSL
requests.packages.urllib3.disable_warnings()

BASE_HEADERS = {'Content-Type': 'application/json'}


def prune_disabled_nodes_from_date(provider, before_date_str, module):
    try:
        host = provider["host"]
        port = provider["port"]
        auth = HTTPBasicAuth(provider["user"], provider["password"])
        url = f"https://{host}:{port}/mgmt/tm/ltm/node/stats"
        response = requests.get(url, auth=auth, headers=BASE_HEADERS, verify=provider["validate_certs"])
        node_delete_lst = []

        if response.ok:
            response = json.loads(response.text)
            for node in response['entries']:
                enabled_state = response['entries'][node]['nestedStats']['entries']['status.enabledState']['description']
                availability_state = response['entries'][node]['nestedStats']['entries']['status.availabilityState']['description']
                status_reason = response['entries'][node]['nestedStats']['entries']['status.statusReason']['description']
                tm_name = response['entries'][node]['nestedStats']['entries']['tmName']['description']
                addr = response['entries'][node]['nestedStats']['entries']['addr']['description']
                patron = r"@(\d{4}/\d{2}/\d{2})"
                coincidence = re.findall(patron, status_reason)
                if (enabled_state == "disabled") and (availability_state == "offline") and coincidence:
                    deadline_str = coincidence[0]
                    before_date = datetime.strptime(before_date_str, '%Y/%m/%d')
                    deadline = datetime.strptime(deadline_str, '%Y/%m/%d')
                    if deadline < before_date:
                        url_delete_node = f"https://{host}:{port}/mgmt/tm/ltm/node/{tm_name.replace('/', '~')}"
                        response_delete = requests.delete(url_delete_node, auth=auth, headers=BASE_HEADERS, verify=provider["validate_certs"])
                        if response_delete.ok:
                            node_delete = {
                                "node": tm_name,
                                "addr": addr,
                                "enabled_state": enabled_state,
                                "availability_state": availability_state,
                                "status_reason": status_reason
                            }
                            node_delete_lst.append(node_delete)
                        else:
                            response_delete = json.loads(response_delete.text)
        else:
            response = json.loads(response.text)
            module.fail_json(msg=response, content=[])

        if len(node_delete_lst) > 0:
            msg_ret = f"A total of {len(node_delete_lst)} Nodes that were in 'Disabled' state with a date earlier than '{before_date_str}' have been removed."
        else:
            msg_ret = f"No Nodes in 'Disabled' state with a date earlier than '{before_date_str}' were found."

        status = True
        return status, msg_ret, node_delete_lst

    except Exception as error:
        status = False
        tb = traceback.format_exc()
        msg_ret = f"Error: <{str(error)}>\n{tb}"
        return status, msg_ret, []


def main():
    module = AnsibleModule(
        argument_spec=dict(
            before_date=dict(required=True, type='str'),
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
                        fallback=(env_fallback, ['F5_SERVER'])
                    ),
                    port=dict(
                        type='int',
                        default=443,
                        fallback=(env_fallback, ['F5_SERVER_PORT']),
                    ),
                    validate_certs=dict(
                        type='bool',
                        default=False,
                        fallback=(env_fallback, ['F5_VALIDATE_CERTS'])
                    )
                )
            )
        )
    )

    before_date = module.params['before_date']
    provider = module.params['provider']

    success,msg_ret,output = prune_disabled_nodes_from_date(provider, before_date, module)
    if success:
            module.exit_json(failed=False, msg=msg_ret, content=output)
    else:
        module.fail_json(failed=True, msg=msg_ret, content=output)


if __name__ == "__main__":
    main()
