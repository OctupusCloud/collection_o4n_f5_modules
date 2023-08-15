#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: (c) 2019, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
"""

EXAMPLES = r"""
- name: Create an smtp profile
  o4n_bigip_profile_smtp:
    name: foo
    parent: /Common/barfoo
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Modify an smtp profile
  o4n_bigip_profile_smtp:
    name: foo
    security: yes
    description: my description
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost

- name: Remove an smtp profile
  o4n_bigip_profile_smtp:
    name: foo
    state: absent
    provider:
      password: secret
      server: lb.mydomain.com
      user: admin
  delegate_to: localhost
"""

RETURN = r"""
description:
  description: Description of the profile.
  returned: changed
  type: str
  sample: Foo is bar
parent:
  description: Specifies the profile from which this profile inherits settings.
  returned: changed
  type: str
  sample: /Common/smtp
security:
  description: Enables secure smtp traffic for the BIG-IP Application Security Manager.
  returned: changed
  type: bool
  sample: false
"""
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule, env_fallback

from ansible_collections.f5networks.f5_modules.plugins.module_utils.bigip import (
    F5RestClient,
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import (
    F5ModuleError,
    AnsibleF5Parameters,
    transform_name,
    f5_argument_spec,
    flatten_boolean,
    fq_name,
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.icontrol import (
    tmos_version,
)
from ansible_collections.f5networks.f5_modules.plugins.module_utils.teem import (
    send_teem,
)


class Parameters(AnsibleF5Parameters):
    api_map = {
        "defaultsFrom": "parent",
    }

    api_attributes = [
        "description",
        "security",
    ]

    returnables = [
        "description",
        "parent",
        "security",
    ]

    updatables = [
        "description",
        "parent",
        "security",
    ]


class ApiParameters(Parameters):
    pass


class ModuleParameters(Parameters):
    @property
    def parent(self):
        if self._values["parent"] is None:
            return None
        result = fq_name(self.partition, self._values["parent"])
        return result

    @property
    def security(self):
        result = flatten_boolean(self._values["security"])
        if result is None:
            return None
        if result == "yes":
            return "enabled"
        return "disabled"


class Changes(Parameters):
    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            pass
        return result


class UsableChanges(Changes):
    pass


class ReportableChanges(Changes):
    @property
    def security(self):
        result = flatten_boolean(self._values["security"])
        return result


class Difference(object):
    def __init__(self, want, have=None):
        self.want = want
        self.have = have

    def compare(self, param):
        try:
            result = getattr(self, param)
            return result
        except AttributeError:
            return self.__default(param)

    def __default(self, param):
        attr1 = getattr(self.want, param)
        try:
            attr2 = getattr(self.have, param)
            if attr1 != attr2:
                return attr1
        except AttributeError:
            return attr1

    @property
    def description(self):
        if self.want.description is None:
            return None
        if self.have.description in [None, "none"] and self.want.description == "":
            return None
        if self.want.description != self.have.description:
            return self.want.description


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get("module", None)
        self.client = F5RestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = UsableChanges()

    def _set_changed_options(self):
        changed = {}
        for key in Parameters.returnables:
            if getattr(self.want, key) is not None:
                changed[key] = getattr(self.want, key)
        if changed:
            self.changes = UsableChanges(params=changed)

    def _update_changed_options(self):
        diff = Difference(self.want, self.have)
        updatables = Parameters.updatables
        changed = dict()
        for k in updatables:
            change = diff.compare(k)
            if change is None:
                continue
            else:
                if isinstance(change, dict):
                    changed.update(change)
                else:
                    changed[k] = change
        if changed:
            self.changes = UsableChanges(params=changed)
            return True
        return False

    def _announce_deprecations(self, result):
        warnings = result.pop("__warnings", [])
        for warning in warnings:
            self.client.module.deprecate(msg=warning["msg"], version=warning["version"])

    def exec_module(self):
        start = datetime.now().isoformat()
        version = tmos_version(self.client)
        changed = False
        result = dict()
        state = self.want.state

        if state == "present":
            changed = self.present()
        elif state == "absent":
            changed = self.absent()

        reportable = ReportableChanges(params=self.changes.to_return())
        changes = reportable.to_return()
        result.update(**changes)
        result.update(dict(changed=changed))
        self._announce_deprecations(result)
        send_teem(start, self.client, self.module, version)
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        result = self._update_changed_options()
        if result:
            return True
        return False

    def update(self):
        self.have = self.read_current_from_device()
        if not self.should_update():
            return False
        if self.module.check_mode:
            return True
        self.update_on_device()
        return True

    def remove(self):
        if self.module.check_mode:
            return True
        self.remove_from_device()
        if self.exists():
            raise F5ModuleError("Failed to delete the resource.")
        return True

    def create(self):
        self._set_changed_options()
        if self.module.check_mode:
            return True
        self.create_on_device()
        return True

    def exists(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/smtp/{2}".format(
            self.client.provider["server"],
            self.client.provider["server_port"],
            transform_name(self.want.partition, self.want.name),
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if resp.status == 404 or "code" in response and response["code"] == 404:
            return False
        if (
            resp.status in [200, 201]
            or "code" in response
            and response["code"] in [200, 201]
        ):
            return True

        errors = [401, 403, 409, 500, 501, 502, 503, 504]

        if resp.status in errors or "code" in response and response["code"] in errors:
            if "message" in response:
                raise F5ModuleError(response["message"])
            else:
                raise F5ModuleError(resp.content)

    def create_on_device(self):
        params = self.changes.api_params()
        params["name"] = self.want.name
        params["partition"] = self.want.partition
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/smtp/".format(
            self.client.provider["server"],
            self.client.provider["server_port"],
        )
        resp = self.client.api.post(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if "code" in response and response["code"] in [400, 409]:
            if "message" in response:
                raise F5ModuleError(response["message"])
            else:
                raise F5ModuleError(resp.content)
        return True

    def update_on_device(self):
        params = self.changes.api_params()
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/smtp/{2}".format(
            self.client.provider["server"],
            self.client.provider["server_port"],
            transform_name(self.want.partition, self.want.name),
        )
        resp = self.client.api.patch(uri, json=params)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if "code" in response and response["code"] == 400:
            if "message" in response:
                raise F5ModuleError(response["message"])
            else:
                raise F5ModuleError(resp.content)

    def remove_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/smtp/{2}".format(
            self.client.provider["server"],
            self.client.provider["server_port"],
            transform_name(self.want.partition, self.want.name),
        )
        response = self.client.api.delete(uri)
        if response.status == 200:
            return True
        raise F5ModuleError(response.content)

    def read_current_from_device(self):
        uri = "https://{0}:{1}/mgmt/tm/ltm/profile/smtp/{2}".format(
            self.client.provider["server"],
            self.client.provider["server_port"],
            transform_name(self.want.partition, self.want.name),
        )
        resp = self.client.api.get(uri)
        try:
            response = resp.json()
        except ValueError as ex:
            raise F5ModuleError(str(ex))

        if "code" in response and response["code"] == 400:
            if "message" in response:
                raise F5ModuleError(response["message"])
            else:
                raise F5ModuleError(resp.content)
        return ApiParameters(params=response)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        argument_spec = dict(
            name=dict(required=True),
            description=dict(),
            parent=dict(),
            security=dict(type="bool"),
            state=dict(default="present", choices=["present", "absent"]),
            partition=dict(default="Common", fallback=(env_fallback, ["F5_PARTITION"])),
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
    )

    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == "__main__":
    main()
