#!/usr/bin/python

import yaml
import json
import requests

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: roas_sync.py
short_description: Synchronize ROAs with KRILL
options:
  url:
    required: true
    description:
      - URL to connect to KRILL API
  ca:
    required: true
    description:
      - KRILL CA
  token:
    required: true
    description:
      - Token for KRILL API
  source:
    required: true
    description:
      - CMDB source ROAs
"""

def main() :
    module_args = dict(
        url=dict(type='str', required=True),
        ca=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        source=dict(type='path', required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    url = module.params["url"]
    ca = module.params["ca"]
    token = module.params["token"]
    headers = {"Authorization": f"Bearer {token}"}
    source = module.params["source"]

    wanted = yaml.safe_load(open(source))
    wanted = wanted["roas"]

    got = {}
    resp = requests.get(f"{url}/cas/{ca}/routes", headers=headers)
    if resp.status_code >= 400:
        raise AnsibleError(
            "cannot fetch roas from api: "
            f"{resp.text}")
    roas = resp.json()
    for roa in roas :
        got.update(
            {
                roa["prefix"]: {
                    "asn": roa["asn"],
                    "max": roa["max_length"]
                }
            }
        )

    add = []
    remove = []

    for prefix, details in wanted.items():
        if prefix not in got or details != got[prefix]:
            add.append(
                {
                    "asn": details["asn"],
                    "prefix": prefix,
                    "max_length": details["max"]
                }
            )
            result["changed"] = True

    for prefix, details in got.items():
        if prefix not in wanted or details != wanted[prefix]:
            remove.append(
                {
                    "asn": details["asn"],
                    "prefix": prefix,
                    "max_length": details["max"]
                }
            )
            result["changed"] = True

    if result["changed"]:
        result['diff'] = dict(
            before=yaml.safe_dump(got),
            after=yaml.safe_dump(wanted)
        )
        result["add"] = add
        result["remove"] = remove

    if module.check_mode or not result['changed'] :
        module.exit_json(**result)

    if remove:
        data = {
            "added": [],
            "removed": remove
        }
        resp = requests.post(f"{url}/cas/{ca}/routes", headers=headers, json=data)
        if resp.status_code >= 400:
            raise AnsibleError(
                "cannot remove roas: "
                f"{resp.text}")
    if add:
        data = {
            "added": add,
            "removed": []
        }
        resp = requests.post(f"{url}/cas/{ca}/routes", headers=headers, json=data)
        if resp.status_code >= 400:
            raise AnsibleError(
                "cannot add roas: "
                f"{resp.text}")

    module.exit_json(**result)

if __name__ == "__main__" :
    main()
