#!/usr/bin/python

DOCUMENTATION = """
---
module: ssh_user_alias.py
short_description: Create alias for users in SSH authorized_keys
options:
  user:
    description:
      - base user to make alias for
  groups:
    description:
      - list of groups we want our aliases to be in
"""

import os
import re
from ansible.module_utils.basic import AnsibleModule


def main():
    module_args = dict(
        user=dict(type='str', required=True),
        groups=dict(type='list', elements='str', default=[])
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    got = {}
    wanted = {}

    for source in ["/etc/passwd",
                   "/etc/shadow",
                   "/etc/group"]:
        with open(source) as f:
            got[source] = f.read()
            wanted[source] = got[source]

    base_uid = None
    to_remove = []

    # Handle /etc/passwd
    to_keep = []
    for line in wanted["/etc/passwd"].split("\n"):
        if not line:
            continue
        user, _, uid, gid, gecos, home, shell = line.split(":")
        if user == module.params["user"]:
            base_uid, base_gid, base_home, base_shell = uid, gid, home, shell
        elif gecos == "cmdb,,,":
            to_remove.append(user)
            continue
        to_keep.append(line)
    if base_uid is None:
        result["msg"] = "user {} not found in /etc/passwd".format(
            module.params["user"])
        module.fail_json(**result)

    # Get HOME/.ssh/authorized_keys
    to_add = []
    with open(os.path.join(base_home, ".ssh", "authorized_keys")) as f:
        for line in f:
            if not line:
                continue
            line = line.strip()
            user = line.split(" ", 2)[-1]
            if re.match(r"[a-z]+", user):
                to_add.append(user)

    # Add users
    for user in to_add:
        to_keep.append(":".join([user, "x", base_uid, base_gid,
                                 "cmdb,,,", base_home, base_shell]))
    wanted["/etc/passwd"] = "\n".join(to_keep) + "\n"

    # Handle /etc/shadow
    to_keep = []
    for line in wanted["/etc/shadow"].split("\n"):
        if not line:
            continue
        user, passwd, _, _, _, _, _, _, _ = line.split(":")
        if passwd != "cmdb":
            to_keep.append(line)
    for user in to_add:
        to_keep.append(":".join([user, "cmdb", "18312", "0",
                                 "999999", "7", "", "", ""]))
    wanted["/etc/shadow"] = "\n".join(to_keep) + "\n"

    # Handle /etc/group
    to_keep = []
    for line in wanted["/etc/group"].split("\n"):
        if not line:
            continue
        group, password, gid, users = line.split(":")
        users = [u for u in users.split(",")
                 if u and u not in to_remove]
        if group in module.params["groups"]:
            users.extend(to_add)
        users = ",".join(users)
        to_keep.append(":".join([group, password, gid, users]))
    wanted["/etc/group"] = "\n".join(to_keep) + "\n"

    if got != wanted:
        result['changed'] = True
        result['diff'] = [
            dict(
                before_header=f,
                after_header=f,
                before=got[f],
                after=wanted[f])
            for f in got
        ]

    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    # Apply changes.
    for dest in wanted:
        with open(dest, "w") as f:
            f.write(wanted[dest])

    module.exit_json(**result)


if __name__ == '__main__':
    main()
