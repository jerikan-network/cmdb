#!/usr/bin/env python3

import yaml
import jinja2
import ipwhois
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: dns_sync_arin.py
short_description: Synchronize reverse zones with ARIN
options:
  irr:
    required: true
    description:
      - IRR to target
  contact:
    required: true
    description:
      - Object to use as a contact
  mntner:
    required: true
    description:
      - Object to use as a maintainer
  reverses:
    required: true
    description:
      - reverse zones as provided by dns_sync
"""

RETURN = """
reverses:
  description: a list of remaining reverse zones (not ones processed here)
  type: dict
  returned: always
records:
  description: record to be sent for sync through GPG-email
  type: str
  returned: changed
"""


def run_module():
    module_args = dict(
        irr=dict(type='str', required=True),
        contact=dict(type='str', required=True),
        mntner=dict(type='str', required=True),
        reverses=dict(type='dict', required=True),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    wanted = {}
    got = {}
    data = module.params['reverses']
    irr = module.params['irr']

    for zone, details in data.items():
        try:
            whois = ipwhois.IPWhois(
                address=details['net'].split("/")[0]).lookup_rdap(
                    asn_methods=['whois', 'http'])
        except ipwhois.exceptions.IPDefinedError:
            continue
        if not whois['asn_registry'].upper().startswith(irr):
            continue

        # Then, update
        template = jinja2.Template("""
domain:         {{ zone }}
descr:          Reverse zone for {{ net }}
{%- for ns in nss %}
nserver:        {{ ns }}
{%- endfor %}
admin-c:        {{ contact }}
tech-c:         {{ contact }}
zone-c:         {{ contact }}
mnt-by:         {{ mntner }}
source:         {{ irr }}
""".strip())
        wanted[zone] = template.render(zone=zone,
                                       irr=irr,
                                       contact=module.params['contact'],
                                       mntner=module.params['mntner'],
                                       net=details["net"],
                                       nss=details["ns"])

        # Grab existing records
        args = ["whois",
                "-h", f"whois.{irr.lower()}.net",
                "-s", irr,
                "-BrG",
                "-T", "domain",
                zone]
        proc = subprocess.run(args, capture_output=True)
        if proc.returncode != 0:
            raise AnsibleError(
                f"unable to query whois: {args}")
        out = [line.strip()
               for line in proc.stdout.decode('ascii').split("\n")
               if line.strip() and not line.startswith(("%",
                                                        "last-modified:",
                                                        "created:"))]
        if out:
            got[zone] = "\n".join(out)

    if got != wanted:
        result['changed'] = True
        if module._diff:
            result['diff'] = [
                dict(before_header=k,
                     after_header=k,
                     before=got.get(k, ""),
                     after=wanted.get(k, ""))
                for k in set((*wanted.keys(), *got.keys()))
                if k not in wanted or k not in got or wanted[k] != got[k]]
        result['records'] = "\n\n".join([wanted[zone]
                                         for zone in wanted
                                         if zone not in got
                                         or got[zone] != wanted[zone]])

    result['reverses'] = {k: v
                          for k, v in data.items()
                          if k not in wanted}

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
