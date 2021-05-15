#!/usr/bin/env python3

import subprocess
import re
import functools
import crypt

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: irr_sync.py
short_description: Filter records to be sent to IRR
options:
  irr:
    required: true
    description:
      - IRR to target
  mntner:
    required: true
    description:
      - object to use as a maintainer
  source:
    required: true
    description:
      - records to be sent
  password:
    required: false
    description:
      - password for clear-text authentication
"""

RETURN = """
records:
  description: record to be sent for sync
  type: str
  returned: changed
"""


@functools.total_ordering
class Record(object):
    """IRR object with comparison special-ability."""

    def __init__(self, raw, excluded_fields):
        normalized = []
        for line in raw.split("\n"):
            mo = re.match(r"(\S+:)\s*(.*)", line)
            name, value = mo.groups()
            normalized.append(f"{name:16}{value}")
        self.raw = "\n".join(normalized)
        self.excluded_fields = tuple((f"{f}:" for f in excluded_fields))

    def __repr__(self):
        key = self.raw.split('\n')[0].replace(" ", "")
        return f"<Record:{key}>"

    def __str__(self):
        return "\n".join((s.replace(" # Filtered", "")
                          for s in self.raw.split("\n")
                          if not s.startswith(self.excluded_fields)))

    def __eq__(self, other):
        if not isinstance(other, Record):
            raise NotImplementedError(
                "cannot compare Record wih something else")
        return str(self) == str(other)

    def __lt__(self, other):
        if not isinstance(other, Record):
            raise NotImplementedError(
                "cannot compare Record wih something else")
        return str(self) < str(other)


def extract(raw, excluded_objects, excluded_fields):
    """Extract objects into records."""
    # First step, remove comments and unwanted lines
    records = "\n".join([record
                         for record in raw.split("\n")
                         if not record.startswith((
                                 "#",
                                 "%",
                         ))])
    # Second step, split records into invidual records
    records = [Record(record.strip(), excluded_fields)
               for record in re.split(r"\n\n+", records)
               if record.strip()
               and not record.startswith(
                   tuple(f"{o}:" for o in excluded_objects))]
    # Last step, put records in a dict
    records = {repr(record): record
               for record in records}
    return records


def insert_password(records, password):
    """Insert authentication password in records."""
    if password is None:
        return records
    # Split (again) the records
    records = (r.strip()
               for r in re.split(r"\n\n+", records)
               if r.strip())
    # Add password to each of them
    records = (f"{r}\npassword:       {password}"
               for r in records)
    # Replace @MD5PASSWORD@ marker
    records = (f"{r}".replace("@MD5PASSWORD@",
                              crypt.crypt(password, "$1$987tudsg"))
               for r in records)
    return "\n\n".join(records)


def run_module():
    module_args = dict(
        irr=dict(type='str', required=True),
        mntner=dict(type='str', required=True),
        source=dict(type='path', required=True),
        password=dict(type='str', required=False, default=None),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    irr = module.params['irr']

    # Grab existing records
    args = ["whois",
            "-h",
            "rr.arin.net" if irr == "ARIN" else f"whois.{irr.lower()}.net",
            "-s", irr,
            "-r" if irr == "ARIN" else "-BrG",
            "-i", "mnt-by",
            module.params['mntner']]
    proc = subprocess.run(args, capture_output=True)
    if proc.returncode != 0:
        raise AnsibleError(
            f"unable to query whois: {args}")

    with open(module.params['source']) as f:
        original = f.read()
    excluded_objects = ["domain"]
    excluded_fields = [
        "created",
        "last-modified",
        "auth",
        "changed",
        "method",
        "owner",
        "fingerpr"
    ]
    if irr == "ARIN":
        excluded_objects.extend([
            "mntner",
        ])
        excluded_fields.extend([
            "admin-c",
            "tech-c",
        ])
    got = extract(proc.stdout.decode('ascii'),
                  excluded_objects, excluded_fields)
    wanted = extract(original,
                     excluded_objects, excluded_fields)

    if got != wanted:
        result['changed'] = True
        if module._diff:
            result['diff'] = [
                dict(before_header=k,
                     after_header=k,
                     before=str(got.get(k, "")),
                     after=str(wanted.get(k, "")))
                for k in set((*wanted.keys(), *got.keys()))
                if k not in wanted or k not in got or wanted[k] != got[k]]
        deleted = "\n\n".join([got[k].raw + "\ndelete:         deleted by CMDB"
                               for k in got
                               if k not in wanted])
        result['records'] = insert_password(f"{original}\n\n{deleted}",
                                            module.params['password'])

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
