#!/usr/bin/env python3

import yaml
import ipaddress
import math
import boto3
import requests
import collections
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: dns_sync.py
short_description: Synchronize DNS with Amazon/PowerDNS
options:
  aws_key:
    required: true
    description:
      - key to connect to AWS Route53 API
  aws_secret:
    required: true
    description:
      - secret to connect to AWS Route53 API
  powerdns_apikey:
    required: true
    description:
      - API key to connect to PowerDNS API
  powerdns_server:
    required: true
    description:
      - PowerDNS server
  source:
    required: true
    description:
      - Data to sync with DNS servers
  batch_size:
    required: false
    description:
      - Size of batches for creating records.

"""

RETURN = """
reverses:
  description: a list of all public reverse zones associated with subnet and associated nameservers
  type: dict
  returned: always
"""


class DNSClient(object):
    """Abstract class for a DNS client."""

    def create_zone(self, name):
        """Create a zone."""
        raise NotImplementedError(
            f"{self.__class__.__name__}: "
            f"creation of zone {name} not implemented")

    # No zone deletion

    def create_rrset(self, zone, name, type, values, ttl):
        """Create a record."""
        raise NotImplementedError(
            f"{self.__class__.__name__}: "
            f"creation of RRSet {name}.{zone} IN {type} "
            f"{','.join(values)} not implemented")

    def delete_rrset(self, zone, name, type, values, ttl):
        """Delete a record."""
        raise NotImplementedError(
            f"{self.__class__.__name__}: "
            f"creation of RRSet {name}.{zone} IN {type} "
            "not implemented")

    def get_zones(self):
        """Return the list of zones handled by this provider."""
        raise NotImplementedError(
            f"{self.__class__.__name__}: "
            f"zone retrieval not implemented")

    def get_records(self, zone, ttl):
        """Return list of records for a zone with a given TTL."""
        raise NotImplementedError(
            f"{self.__class__.__name__}: "
            f"records retrieval for {zone} not implemented")

    def get_ns(self, zone):
        """Return list of nameservers."""
        return []

    def commit(self):
        """Commit pending changes."""


class Route53(DNSClient):
    """DNS client for Route53."""

    def __init__(self, module):
        self.client = boto3.client(
            "route53",
            aws_access_key_id=module.params['aws_key'],
            aws_secret_access_key=module.params['aws_secret'])
        self.batch_size = module.params['batch_size']
        self.zones = {}
        self.batch = collections.defaultdict(list)

    def create_zone(self, name):
        zone = self.client.create_hosted_zone(
            Name=name,
            CallerReference=str(hash(name)),
            HostedZoneConfig={
                "Comment": "managed by CMDB",
                "PrivateZone": False})
        id = zone["HostedZone"]["Id"]
        self.zones[name] = id

    def create_rrset(self, zone, name, type, values, ttl):
        self.batch[zone].append(dict(
            Action="UPSERT",
            ResourceRecordSet=dict(
                Name=name,
                Type=type,
                TTL=ttl,
                ResourceRecords=[dict(Value=value)
                                 for value in values])))

    def delete_rrset(self, zone, name, type, values, ttl):
        self.batch[zone].append(dict(
            Action="DELETE",
            ResourceRecordSet=dict(
                Name=name,
                Type=type,
                TTL=ttl,
                ResourceRecords=[dict(Value=value)
                                 for value in values])))

    def get_zones(self):
        paginator = self.client.get_paginator('list_hosted_zones')
        for zone_page in paginator.paginate():
            for zone in zone_page["HostedZones"]:
                name = zone["Name"]
                id = zone["Id"]
                self.zones[name] = id
        return list(self.zones.keys())

    def get_records(self, zone, ttl):
        if zone not in self.zones:
            return []
        records = []
        paginator = self.client.get_paginator('list_resource_record_sets')
        for rrset_page in paginator.paginate(HostedZoneId=self.zones[zone]):
            for rrset in rrset_page['ResourceRecordSets']:
                if rrset['TTL'] != ttl:
                    continue
                record = dict(name=rrset['Name'],
                              type=rrset['Type'],
                              values=sorted(
                                  [v["Value"]
                                   for v in rrset['ResourceRecords']]))
                records.append(record)
        return records

    def get_ns(self, zone):
        if zone not in self.zones:
            return []
        rrsets = self.client.list_resource_record_sets(
            HostedZoneId=self.zones[zone],
            StartRecordType='NS',
            StartRecordName='.',
            MaxItems='20')
        return [
            ns["Value"]
            for rrset in rrsets["ResourceRecordSets"]
            for ns in rrset["ResourceRecords"]
            if rrset['Name'] == zone
            and rrset['Type'] == 'NS'
        ]

    def commit(self):
        for zone in self.batch:
            for start in range(0, len(self.batch[zone]), self.batch_size):
                slice = self.batch[zone][start:start+self.batch_size]
                self.client.change_resource_record_sets(
                    HostedZoneId=self.zones[zone],
                    ChangeBatch=dict(
                        Comment="CMDB update",
                        Changes=slice))
        self.batch.clear()


class PowerDNS(DNSClient):
    """DNS client for internal PowerDNS."""

    def __init__(self, module):
        self.server = module.params['powerdns_server']
        self.apikey = module.params['powerdns_apikey']
        self.batch_size = module.params['batch_size']
        self.zones = {}
        self.batch = collections.defaultdict(list)

    def create_zone(self, name):
        """Create a zone."""
        raise AnsibleError(
            f"dunno how to create zone {name} for PowerDNS")

    def create_rrset(self, zone, name, type, values, ttl):
        self.batch[zone].append(dict(
            changetype="replace",
            name=name,
            type=type,
            ttl=ttl,
            records=[{"content": value,
                      "disabled": False,
                      "set-ptr": False}
                     for value in values]))

    def delete_rrset(self, zone, name, type, values, ttl):
        self.batch[zone].append(dict(
            changetype="delete",
            name=name,
            type=type,
            records=[]))

    def get_zones(self):
        resp = requests.get(f"{self.server}/zones",
                            headers={"X-API-Key": self.apikey})
        if resp.status_code >= 400:
            raise AnsibleError(f"cannot get zones from {self.server}: "
                               f"{resp.text}")
        for zone in resp.json():
            name = zone['name']
            id = zone['id']
            self.zones[name] = id
        return list(self.zones.keys())

    def get_records(self, zone, ttl):
        if zone not in self.zones:
            return []
        records = []
        resp = requests.get(f"{self.server}/zones/{self.zones[zone]}",
                            headers={"X-API-Key": self.apikey})
        if resp.status_code >= 400:
            raise AnsibleError(f"cannot get records for zone {zone} "
                               f"from {self.server}: "
                               f"{resp.text}")
        for rrset in resp.json()['rrsets']:
            if rrset['ttl'] != ttl:
                continue
            record = dict(name=rrset['name'],
                          type=rrset['type'],
                          values=sorted(
                              [v['content']
                               for v in rrset['records']]))
            records.append(record)
        return records

    def commit(self):
        for zone in self.batch:
            for start in range(0, len(self.batch[zone]), self.batch_size):
                slice = self.batch[zone][start:start+self.batch_size]
                resp = requests.patch(f"{self.server}/zones/{zone}",
                                      data=json.dumps(dict(rrsets=slice)),
                                      headers={"X-API-Key": self.apikey})
                if resp.status_code >= 400:
                    raise AnsibleError(
                        f"cannot create batched records for {zone}: "
                        f"{resp.text}")
        self.batch.clear()


def run_module():
    module_args = dict(
        aws_key=dict(type='str', required=True),
        aws_secret=dict(type='str', required=True, no_log=True),
        powerdns_apikey=dict(type='str', required=True, no_log=True),
        powerdns_server=dict(type='str', required=True),
        source=dict(type='path', required=True),
        batch_size=dict(type='int', default=100),
    )

    result = dict(
        changed=False,
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    data = yaml.safe_load(open(module.params['source']))
    ttl = data['ttl']
    providers = dict(route53=Route53(module),
                     powerdns=PowerDNS(module))
    wanted = {}
    got = {}
    reverse_providers = {}
    reverse_nets = {}

    def zoneof(name):
        for zone in wanted['zones']:
            if name == zone or name.endswith(f".{zone}"):
                return zone
        return None

    # Wanted zones
    wanted['zones'] = []
    for zone in data['zones']['direct']:
        wanted['zones'].append(f"{zone}.")
    for subnet, provider in data['zones']['reverse'].items():
        subnet = ipaddress.ip_network(subnet)
        nibble = {4: 8,
                  6: 4}[subnet.version]
        prefixlen = nibble * math.ceil(subnet.prefixlen/nibble)
        for net in subnet.subnets(new_prefix=prefixlen):
            zone = net.network_address.reverse_pointer
            zone = zone.split(".", (net.max_prefixlen - prefixlen)//nibble)[-1]
            zone = f"{zone}."
            wanted['zones'].append(zone)
            reverse_providers[zone] = provider
            reverse_nets[zone] = net
    wanted['zones'].sort()

    # Wanted records
    wanted['records'] = []
    records = {}
    for entry in data['entries']:
        key = (entry["name"], entry["type"])
        if key not in records:
            records[key] = {entry["value"]}
        else:
            current = records[key]
            current.add(entry["value"])
    for key, value in records.items():
        name, type = key
        record = dict(name=name,
                      type=type,
                      values=sorted(list(value)))
        if zoneof(record['name']) is not None:
            wanted['records'].append(record)
    wanted['records'].sort(key=lambda k: (k['name'], k['type']))

    # Zones we already got
    got['zones'] = []
    for provider in providers.values():
        got['zones'].extend(provider.get_zones())

    got['zones'] = [zone
                    for zone in got['zones']
                    if zone in wanted['zones']]
    got['zones'].sort()

    # Records we've got
    got['records'] = []
    for zone, provider in data['zones']['direct'].items():
        got['records'].extend(providers[provider].get_records(f"{zone}.", ttl))
    for zone, provider in reverse_providers.items():
        got['records'].extend(providers[provider].get_records(zone, ttl))
    got['records'].sort(key=lambda k: (k['name'], k['type']))

    if got != wanted:
        result['changed'] = True
        if module._diff:
            result['diff'] = dict(
                before=yaml.dump(got),
                after=yaml.dump(wanted)
            )

    # Create mapping from reverse zones to nameservers. The dump file
    # is expected to be a mapping from reverse zone name (without
    # final dot) to a dictionary keyed with `net` for the network
    # associated with the zone (in CIDR) form and `ns` the list of
    # name servers (without final dot).
    #
    # 95.249.170.in-addr.arpa:
    #   net: 170.249.95.0/24
    #   ns:
    #   - ns-603.awsdns-11.net
    #   - ns-1367.awsdns-42.org
    #   - ns-1882.awsdns-43.co.uk
    #   - ns-465.awsdns-58.com
    def compute_reverses():
        result['reverses'] = {}
        for zone, provider in reverse_providers.items():
            servers = [ns[:-1]
                       for ns in providers[provider].get_ns(zone)]
            if servers:
                result['reverses'][zone[:-1]] = dict(
                    net=str(reverse_nets[zone]),
                    ns=servers)

    # Stop here if not change or if check mode
    if module.check_mode or not result['changed']:
        compute_reverses()
        module.exit_json(**result)

    # Create zones (only reverse)
    for zone in wanted['zones']:
        if zone in got['zones']:
            continue
        if zone in data['zones']['direct']:
            raise AnsibleError(f"cannot create direct zone {zone}")
        provider = reverse_providers[zone]
        providers[provider].create_zone(zone)

    # Create records
    existing_records = {(k['name'], k['type']): k for k in got['records']}
    for record in wanted['records']:
        key = record['name'], record['type']
        if key in existing_records and \
           existing_records[key] == record:
            continue
        zone = zoneof(record['name'])
        provider = data['zones']['direct'].get(zone[:-1]) or \
            reverse_providers[zone]
        providers[provider].create_rrset(zone, **record, ttl=ttl)

    for provider in providers:
        providers[provider].commit()

    # Delete old records
    wanted_records = {(k['name'], k['type']) for k in wanted['records']}
    for record in got['records']:
        if (record['name'], record['type']) in wanted_records:
            continue
        zone = zoneof(record['name'])
        provider = data['zones']['direct'].get(zone[:-1]) or \
            reverse_providers[zone]
        providers[provider].delete_rrset(zone, **record, ttl=ttl)

    for provider in providers:
        providers[provider].commit()

    compute_reverses()
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
