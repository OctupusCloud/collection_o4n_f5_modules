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
module: o4n_bigip_sys_failover
short_description: Its main function is the ability to set failover status on BIG-IP.
description:
  - Its main function is the ability to set failover status on BIG-IP.
  - All operations are performed over Web Services API.
version_added: "1.0"
author: "Randy Rozo"
notes:
  - Testeado en linux
requirements:
  - ansible >= 2.10
  - Establecer `ansible_python_interpreter` a Python 3 si es necesario.
options:
  device:
    description:
      - Specifies the name of the device that should become the active device for the traffic group or for all traffic groups.
    type: str
    required: False
  no_persist:
    description:
      - Does not persist the change in status of a unit or cluster. Valid only with offline status.
    type: bool
    required: False
  offline:
    description:
      - Changes the status of a unit or cluster to Forced Offline. If persist or no-persist are not specified, the change in status will be persisted in-between system restarts.
    type: bool
    required: False
  online:
    description:
      - Changes the status of a unit or cluster from Forced Offline to either Active or Standby, depending upon the status of the other unit or cluster in a redundant pair.
    type: bool
    required: False
  persist:
    description:
      - Persists the change in status of a unit or cluster. Valid only with offline status.
    type: bool
    required: False
  standby:
    description:
      - Specifies that the active unit or cluster fails over to a Standby state, causing the standby unit or cluster to become Active.
    type: bool
    required: False
  traffic_group:
    description:
      - Specifies the name of the traffic-group that the standby command refers to.
    type: str
    required: False
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
  - name: Set Failover
    o4n_bigip_sys_failover:
      standby: true
      traffic_group: traffic-group-1
    register: output
"""
RETURN = """
output:
  description: The Set Failover output
  type: dict
  returned: allways
  sample:
    "output": {
        "changed": true,
        "content": [
            {
                "command": "run",
                "kind": "tm:sys:failover:runstate",
                "standby": true,
                "trafficGroup": "traffic-group-1"
            }
        ],
        "failed": false,
        "msg": "Success set failover state"
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


def set_sys_failover(provider, params):
    try:
        payload = {
            "command": "run"
        }
        keys = ['device', 'no_persist', 'offline', 'online', 'persist', 'standby', 'traffic_group']

        for key in keys:
            if params[key] is not None:
                if key == "no_persist":
                    payload["noPersist"] = params[key]
                if key == "traffic_group":
                    payload["trafficGroup"] = params[key]
                else:
                    payload[key] = params[key]

        host = provider["host"]
        port = provider["port"]
        auth = HTTPBasicAuth(provider["user"], provider["password"])
        url = f"https://{host}:{port}/mgmt/tm/sys/failover"
        response = requests.post(url, auth=auth, headers=BASE_HEADERS, data=json.dumps(payload), verify=provider["validate_certs"])

        if response.ok:
            response = json.loads(response.text)
            msg_ret = "Success set failover state"
            return True, msg_ret, response

        else:
            response = json.loads(response.text)
            msg_ret = "Failed to set failover state"
            return False, msg_ret, response

    except Exception as error:
        status = False
        tb = traceback.format_exc()
        msg_ret = f"Error: <{str(error)}>\n{tb}"
        return status, msg_ret, []


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device=dict(required=False, type='str'),
            no_persist=dict(required=False, type='bool'),
            offline=dict(required=False, type='bool'),
            online=dict(required=False, type='bool'),
            persist=dict(required=False, type='bool'),
            standby=dict(required=False, type='bool'),
            traffic_group=dict(required=False, type='str'),
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

    provider = module.params['provider']

    success, msg_ret, output = set_sys_failover(provider, module.params)
    if success:
        module.exit_json(changed=True, failed=False, msg=msg_ret, content=output)
    else:
        module.fail_json(failed=True, msg=msg_ret, content=output)


if __name__ == "__main__":
    main()
