#!/usr/bin/env python3

import yaml
import requests
import ipaddress
from xml.etree import ElementTree as ET

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: dns_sync_arin.py
short_description: Synchronize reverse zones with ARIN
options:
  key:
    required: true
    description:
      - key to connect to ARIN API
  org:
    required: true
    description:
      - ARIN organization
  reverses:
    required: true
    description:
      - reverse zones as provided by dns_sync
"""

RETURN = """
reverses:
  description: a list of remaining reverse zones (not ARIN ones)
  type: dict
  returned: always
"""

def run_module():
    module_args = dict(
        key=dict(type='str', required=True, no_log=True),
        org=dict(type='str', required=True),
        reverses=dict(type='dict', required=True),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    apikey = module.params['key']
    org = module.params['org']
    data = module.params['reverses']
    whois_ns = "http://www.arin.net/whoisrws/core/v1"
    rdns_ns = "http://www.arin.net/whoisrws/rdns/v1"
    reg_ns = "http://www.arin.net/regrws/core/v1"
    whois_url = "http://whois.arin.net/rest"
    reg_url = "https://reg.arin.net/rest"

    wanted = {}
    got = {}

    # Get networks
    resp = requests.get(f"{whois_url}/org/{org}/nets")
    if resp.status_code >= 400:
        raise AnsibleError(
            f"cannot get networks for {org}: "
            f"{resp.text}")
    tree = ET.fromstring(resp.content)
    handles = [netref.get("handle")
               for netref in tree.findall(f"{{{whois_ns}}}netRef")]

    # Get subnets
    for handle in handles:
        resp = requests.get(f"{whois_url}/net/{handle}")
        if resp.status_code >= 400:
            raise AnsibleError(
                f"cannot get network {handle}: "
                f"{resp.text}")
        tree = ET.fromstring(resp.content)
        netblocks = tree.find(f"{{{whois_ns}}}netBlocks")
        for netblock in netblocks:
            subnet = ipaddress.ip_network("{}/{}".format(
                netblock.find(f"{{{whois_ns}}}startAddress").text,
                netblock.find(f"{{{whois_ns}}}cidrLength").text))
            for zone, details in data.items():
                net = ipaddress.ip_network(details["net"])
                if net[0] in subnet and net[-1] in subnet:
                    got[zone] = []
                    wanted[zone] = sorted(data[zone]['ns'])

    # Get nameservers
    for zone in got:
        resp = requests.get(f"{whois_url}/rdns/{zone}")
        if resp.status_code == 404:
            continue
        if resp.status_code >= 400:
            raise AnsibleError(
                f"cannot DNS delegation for {zone}: "
                f"{resp.text}")
        tree = ET.fromstring(resp.content)
        nameservers = tree.find(f"{{{rdns_ns}}}nameservers")
        got[zone] = sorted([nameserver.text.lower()
                            for nameserver in nameservers])

    if got != wanted:
        result['changed'] = True
        if module._diff:
            result['diff'] = [
                dict(before_header=k,
                     after_header=k,
                     before=yaml.dump(got[k]) if k in got else "",
                     after=yaml.dump(wanted[k]) if k in wanted else "")
                for k in set((*wanted.keys(), *got.keys()))
                if k not in wanted or k not in got or wanted[k] != got[k]]

    result['reverses'] = {k: v
                          for k, v in data.items()
                          if k not in wanted}

    # Stop here if not change or if check mode
    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    # Update or create
    for zone in wanted:
        if zone in got and got[zone] == wanted[zone]:
            continue
        resp = requests.put(f"{reg_url}/delegation/{zone}",
                            params={"apikey": apikey})
        root = ET.Element(f"{{{reg_ns}}}delegation")
        ET.SubElement(root, f"{{{reg_ns}}}name").text = f"{zone}."
        nameservers = ET.SubElement(root, f"{{{reg_ns}}}nameservers")
        for nameserver in wanted[zone]:
            ET.SubElement(nameservers,
                          f"{{{reg_ns}}}nameserver").text = nameserver
        xml = ET.tostring(root, default_namespace=reg_ns)
        resp = requests.put(f"{reg_url}/delegation/{zone}",
                            params={"apikey": apikey},
                            data=xml)
        if resp.status_code >= 400:
            raise AnsibleError(
                f"cannot update DNS delegation for {zone}: "
                f"{resp.text}")

    # No deletion (it shouldn't happen)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
