#!/usr/bin/env python3

import yaml
import copy
import pynetbox
import attr
import re
from packaging import version

from concurrent.futures import ThreadPoolExecutor, as_completed
from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleError

DOCUMENTATION = """
---
module: netbox_sync.py
short_description: Synchronize Netbox with changes from CMDB
options:
  source:
    required: true
    description:
      - YAML file to use as source
  api:
    required: true
    description:
      - API endpoint for Netbox
  token:
    required: true
    description:
      - Authentication token for Netbox
  cleanup:
    required: false
    description:
      - Cleanup old stuff
  max_workers:
    required: false
    description:
      - Number of workers to retrieve information from Netbox
"""

# To run locally:
#

"""
echo '{"ANSIBLE_MODULE_ARGS": {
    "_ansible_check_mode": false,
    "source": "'$PWD/../../../../output/none/netbox.yaml'",
    "api": "https://netbox.pp.blade.sh",
    "token": "..."}}' | python3 ./netbox_sync.py
"""


def slugify(s):
    # Adapted from:
    # https://github.com/netbox-community/netbox/blob/7a53e24f9721a8506008e8bafc25ddd04fa2f412/netbox/project-static/js/forms.js#L37
    s = re.sub(r'[^-.\w\s]', '', s)
    s = re.sub(r'^[\s.]+|[\s.]+$', '', s)
    s = re.sub(r'[.\s-]+', '-', s)
    return s.lower()


@attr.s(kw_only=True)
class SyncSomething(object):

    module = attr.ib()          # Ansible module
    netbox = attr.ib()          # Netbox API
    source = attr.ib()          # source of truth
    before = attr.ib()          # what's currently in Netbox
    after = attr.ib()           # what we want in Netbox

    # Attribute that should be present in concrete classes:
    # key = "name"             # what attribute to lookup for existing objects
    # app = "dcim"             # Netbox app containing the data
    # table = "manufacturers"  # Netbox table containing the data
    foreign = {}               # foreign attributes (attribute name → class)
    only_on_create = ()        # list of attributes to only use when creating
    remove_unused = None       # remove not managed anymore (max to remove)

    cache = None

    def wanted(self):
        """Extract from source of truth the set of wanted elements."""
        raise NotImplementedError()

    def get(self, ep, key):
        """Get current record from Netbox."""
        if self.cache is None:
            self.cache = {}
            for element in ep.filter(tag=["cmdb"]):
                self.cache[element[self.key]] = element
        try:
            return self.cache[key]
        except KeyError:
            return ep.get(**{self.key: key})

    def prepare(self):
        """Prepare for synchronization by looking what's currently in Netbox
        and what should be updated to match the source of truth.
        Return True if there is a change.

        """
        changed = False
        ep = getattr(getattr(self.netbox, self.app), self.table)
        self.before[self.table] = {}
        self.after[self.table] = {}

        # Check what should be added
        wanted = self.wanted()

        def process(key, details):
            current = self.get(ep, key)
            if current is not None:
                current = {k: v for k, v in dict(current).items()
                           if k in ('id',) + tuple(details.keys())}
                # When an attribute is a choice, use the value
                for attrib in current:
                    if type(current[attrib]) is dict and \
                       set(current[attrib].keys()) in ({"id", "label", "value"},
                                                       {"label", "value"}):
                        current[attrib] = current[attrib]["value"]
                if "tags" in current and current["tags"]:
                    if type(current["tags"][0]) is dict:
                        current["tags"] = [c["name"] for c in current["tags"]]
                    current["tags"].sort()
                # Before/after takes the current value
                self.before[self.table][key] = dict(current)
                self.after[self.table][key] = copy.deepcopy(dict(current))
                # Update attributes with the newest one
                for attrib in details:
                    if attrib in self.only_on_create:
                        continue
                    if attrib == "tags":
                        # Tags could be merged here. We choose not to
                        # because it's difficult to delete our own
                        # tags.
                        if "cmdb" not in details["tags"]:
                            details["tags"].append("cmdb")
                        details["tags"].sort()
                    self.after[self.table][key][attrib] = details[attrib]
                # Link foreign keys for "before"
                for fkey, fclass in self.foreign.items():
                    old = self.before[self.table][key][fkey]
                    if old is None:
                        continue
                    if fclass.key in old:
                        self.before[self.table][key][fkey] = old[fclass.key]
                    else:
                        # We do not have fclass.key directly here,
                        # let's search by ID!
                        id = old["id"]
                        for k, v in self.before[fclass.table].items():
                            if id == v["id"]:
                                self.before[self.table][key][fkey] = k
                                break
                        else:
                            raise RuntimeError("unable to find foreign key "
                                               f"{fkey} for {k}")
                # Is there a diff?
                for attrib in self.after[self.table][key]:
                    if attrib not in self.before[self.table][key] or \
                       self.after[self.table][key][attrib] != \
                       self.before[self.table][key][attrib]:
                        return True
            else:
                self.after[self.table][key] = details
                return True
            return False

        with ThreadPoolExecutor(
                max_workers=self.module.params['max_workers']) as executor:
            futures = (executor.submit(process, key, details)
                       for key, details in wanted.items())
            for future in as_completed(futures):
                changed |= future.result()

        # Check what should be removed
        if not self.remove_unused or \
           not self.module.params['cleanup'] or \
           not self.before["tags"]:
            return changed
        unused = 0
        for key, existing in self.cache.items():
            if key not in self.before[self.table]:
                changed = True
                unused += 1
                self.before[self.table][key] = {}

        if unused > self.remove_unused:
            raise AnsibleError(f"refuse to remove {unused} "
                               f"(more than {self.remove_unused}) "
                               f"objects from {self.table}")

        return changed

    def _normalize_tags(self, tags):
        """Normalize tags as a list of string with Netbox <= 2.8 or a list of
        dicts with more recent versions. The provided list is expected
        to contain strings and dicts but dicts may only be present
        because fetched through the API (internally, we should use
        strings only).
        """
        if version.parse(self.netbox.version) <= version.parse('2.8'):
            return tags
        return [{"name": t} if type(t) is str else t
                for t in tags]

    def synchronize(self):
        """After preparation, synchronize the changes in Netbox. Currently,
        only do a one-way synchronization."""
        ep = getattr(getattr(self.netbox, self.app), self.table)
        for key, details in self.after[self.table].items():
            if key not in self.before[self.table]:
                # We need to create the object
                for attrib in details:
                    if attrib in self.foreign:
                        details[attrib] = self.after[
                            self.foreign[attrib].table][details[attrib]]["id"]
                # New objects may not have tags
                details["tags"] = self._normalize_tags(list(set(
                    details.get("tags", [])).union({"cmdb"})))
                result = ep.create(**{self.key: key}, **details)
                details["id"] = result.id
            else:
                # Is there something to update?
                current = self.before[self.table][key]
                diff = False
                for attrib in details:
                    if attrib not in current or \
                       details[attrib] != current[attrib]:
                        diff = True
                        break
                if diff:
                    current = self.get(ep, key)
                    for attrib in details:
                        if attrib == "id":
                            continue
                        if attrib == "tags":
                            details["tags"] = self._normalize_tags(
                                details["tags"])
                        if attrib not in self.foreign:
                            setattr(current, attrib, details[attrib])
                        else:
                            # We cannot update a foreign key. Only do
                            # it if they differ (and die horribly).
                            if details[attrib] is None:
                                newid = None
                            else:
                                newid = self.after[self.foreign[attrib].table][
                                    details[attrib]]["id"]
                            if getattr(current, attrib) is None:
                                oldid = None
                            else:
                                oldid = getattr(current, attrib).id
                            if newid != oldid:
                                setattr(current, attrib, newid)
                    current.save()

    def cleanup(self):
        """Cleanup unused entries."""
        ep = getattr(getattr(self.netbox, self.app), self.table)
        for key in self.before[self.table]:
            if key in self.after[self.table]:
                continue
            current = self.get(ep, key)
            current.delete()


class SyncTags(SyncSomething):
    app = "extras"
    table = "tags"
    key = "name"

    def wanted(self):
        result = {"cmdb": dict(slug="cmdb",
                               color="8bc34a",
                               description="synced by network CMDB")}
        result.update({tag: dict(slug=tag,
                                 color="9e9e9e",
                                 description="synced by network CMDB")
                       for details in self.source['ips']
                       for tag in details.get("tags", [])})
        return result


class SyncTenants(SyncSomething):
    app = "tenancy"
    table = "tenants"
    key = "name"

    def wanted(self):
        return {"Network": dict(slug="network",
                                description="Network team")}


class SyncSites(SyncSomething):

    app = "dcim"
    table = "sites"
    key = "facility"
    only_on_create = ("name", "status", "slug")

    def wanted(self):
        result = set(details["datacenter"]
                     for details in self.source['devices'].values()
                     if "datacenter" in details)
        return {k: dict(name=k.upper(),
                        slug=k,
                        status="planned")
                for k in result}


class SyncManufacturers(SyncSomething):

    app = "dcim"
    table = "manufacturers"
    key = "name"

    def wanted(self):
        result = set(details["manufacturer"]
                     for details in self.source['devices'].values()
                     if "manufacturer" in details)
        return {k: {"slug": slugify(k)}
                for k in result}


class SyncDeviceTypes(SyncSomething):

    app = "dcim"
    table = "device_types"
    key = "model"
    foreign = {"manufacturer": SyncManufacturers}

    def wanted(self):
        result = set((details["manufacturer"], details["model"])
                     for details in self.source['devices'].values()
                     if "model" in details)
        return {k[1]: dict(manufacturer=k[0],
                           slug=slugify(k[1]))
                for k in result}


class SyncDeviceRoles(SyncSomething):

    app = "dcim"
    table = "device_roles"
    key = "name"
    only_on_create = ("slug")

    def wanted(self):
        result = set(details["role"]
                     for details in self.source['devices'].values()
                     if "role" in details)
        return {k: dict(slug=slugify(k),
                        color="8bc34a")
                for k in result}


class SyncDevices(SyncSomething):
    app = "dcim"
    table = "devices"
    key = "name"
    foreign = {"device_role": SyncDeviceRoles,
               "device_type": SyncDeviceTypes,
               "site": SyncSites,
               "tenant": SyncTenants}
    remove_unused = 10

    def wanted(self):
        return {name: dict(device_role=details["role"],
                           device_type=details["model"],
                           site=details["datacenter"],
                           tenant="Network")
                for name, details in self.source['devices'].items()
                if {"datacenter", "model", "role"} <= set(details.keys())}


class SyncIPs(SyncSomething):
    app = "ipam"
    table = "ip-addresses"
    key = "address"
    foreign = {"tenant": SyncTenants}
    remove_unused = 1000

    def get(self, ep, key):
        """Grab IP address from Netbox."""
        if self.cache is None:
            self.cache = {}
            for element in ep.filter(tag=["cmdb"]):
                # Current element if it exists is overriden. We do not
                # really handle the case where multiple addresses have
                # the cmdb tag.
                self.cache[element["address"]] = element

        try:
            return self.cache[key]
        except KeyError:
            pass

        # There may be duplicate. We need to grab the "best".
        results = ep.filter(**{self.key: key})
        results = [r for r in results]
        if len(results) == 0:
            return None
        scores = [0]*len(results)
        for idx, result in enumerate(results):
            if "cmdb" in [str(r) for r in result.tags]:
                scores[idx] += 10
            if getattr(result, "interface", None) is not None:
                scores[idx] += 5
            if getattr(result, "assigned_object", None) is not None:
                scores[idx] += 5
        return sorted(zip(scores, results),
                      reverse=True, key=lambda k: k[0])[0][1]

    def wanted(self):
        wanted = {}
        for details in self.source['ips']:
            if details['ip'] in wanted:
                wanted[details['ip']]['description'] = \
                    f"{details['device']} (and others)"
            else:
                wanted[details['ip']] = dict(
                    tenant="Network",
                    status="active",
                    dns_name="",        # information is present in DNS
                    description=f"{details['device']}: {details['interface']}",
                    tags=details.get('tags', []),
                    role=None,
                    vrf=None)
        return wanted


def run_module():
    module_args = dict(
        source=dict(type='path', required=True),
        api=dict(type='str', required=True),
        token=dict(type='str', required=True, no_log=True),
        cleanup=dict(type='bool', required=False, default=True),
        max_workers=dict(type='int', required=False, default=10)
    )

    result = dict(
        changed=False
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    source = yaml.safe_load(open(module.params['source']))
    for device, details in source['devices'].items():
        if details is None:
            source['devices'][device] = {}
    netbox = pynetbox.api(module.params['api'],
                          token=module.params['token'])

    sync_args = dict(
        module=module,
        netbox=netbox,
        source=source,
        before={},
        after={}
    )
    synchronizers = [synchronizer(**sync_args) for synchronizer in [
        SyncTags,
        SyncTenants,
        SyncSites,
        SyncManufacturers,
        SyncDeviceTypes,
        SyncDeviceRoles,
        SyncDevices,
        SyncIPs
    ]]

    # Check what needs to be synchronized
    failed = False
    try:
        for synchronizer in synchronizers:
            result['changed'] |= synchronizer.prepare()
    except AnsibleError as e:
        result['msg'] = e.message
        failed = True
    if module._diff:
        result['diff'] = dict(
            before=yaml.dump(sync_args["before"]),
            after=yaml.dump(sync_args["after"])
        )
    if failed:
        module.fail_json(**result)
    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    # Synchronize
    for synchronizer in synchronizers:
        synchronizer.synchronize()
    for synchronizer in synchronizers[::-1]:
        synchronizer.cleanup()
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
