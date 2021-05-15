#!/usr/bin/env python3

"""IP, ASN and provisioning assignments for an endpoint in some BGP design.

Following the documentation `Network Design 2019Q3-1
<https://wiki.blade.sh/network-design-2019q3-01>`_, this module will
provide the appropriate assignments for an endpoint:

 - AS number
 - private and public IP addresses
 - provisioning subnet (when applicable)

The inputs are:

 - the local hostname (with optional port)
 - the remote hostname (with optional port)
"""

import argparse
import collections
import ipaddress
import logging
import logging.handlers
import re
import sys
from enum import Enum, auto

logger = logging.getLogger(__name__)


class CustomFormatter(argparse.RawDescriptionHelpFormatter,
                      argparse.ArgumentDefaultsHelpFormatter):
    pass


# Convert a site to an offset to be used to compute some values.
SITE2OFFSET = {
    "sk1": 7,
    "ussfo03": 8,
}

# Extract site from a hostname
REGEXES = {
    "to": re.compile(r'to(?P<N>[12])-(?P<kind>p|sp|ap)(?P<pod>\d+)$'),
    "edge": re.compile(r'(?P<kind>edge)(?P<N>[12])$'),
    "spine1": re.compile(r'spine1-(?P<kind>compute|storage)-n(?P<N>[12])$'),
    "spine2": re.compile(r'(?P<kind>spine)(?P<N>\d+)$'),
    "s-spine1": re.compile(r'(?P<kind>s-spine)1-n(?P<N>[12])$'),
    "s-spine2": re.compile(r'(?P<kind>s-spine)(?P<N>\d+)$'),
    "juniper-port": re.compile(r'^(?:xe|et|ge)-0/0/(?P<port>\d+)$'),
    "cumulus-port": re.compile(r'^swp(?P<port>\d+)(?:s(?P<subport>[0-3]))?$'),
    "raw-index-port": re.compile(r'^index(?P<port>\d+)$')
}


def parse_args(args=sys.argv[1:]):
    """Parse arguments."""
    parser = argparse.ArgumentParser(
        description=sys.modules[__name__].__doc__,
        formatter_class=CustomFormatter)

    g = parser.add_mutually_exclusive_group()
    g.add_argument("--debug", "-d", action="store_true",
                   default=False,
                   help="enable debugging")
    g.add_argument("--silent", "-s", action="store_true",
                   default=False,
                   help="don't log to console")

    g = parser.add_argument_group("datacenter configuration")
    g.add_argument("--pods", metavar="N",
                   default=112,
                   type=int,
                   help="Number of PODs")
    g.add_argument("--last-storage-pod", metavar="N",
                   default=100,
                   type=int,
                   help="Last storage POD")
    g.add_argument("--ports-per-pod", metavar="N",
                   default=272,
                   type=int,
                   help="Number of ports per POD")
    g.add_argument("--spines", metavar="N",
                   default=16,
                   type=int,
                   help="Number of spines")
    g.add_argument("--ports-per-spine", metavar="N",
                   default=64,
                   type=int,
                   help="Number of ports per spine")
    g.add_argument("--s-spines", metavar="N",
                   default=16,
                   type=int,
                   help="Number of s-spines")
    g.add_argument("--ports-per-s-spine", metavar="N",
                   default=32,
                   type=int,
                   help="Number of ports per s-spine")
    g.add_argument("--edges", metavar="N",
                   default=8,
                   type=int,
                   help="Number of edges")
    g.add_argument("--ports-per-edge", metavar="N",
                   default=32,
                   type=int,
                   help="Number of ports per edge")
    g.add_argument("--public-prefix", metavar="NET/SIZE",
                   default="100.64.0.0/16",
                   type=ipaddress.ip_network,
                   help="Base prefix for public subnets")
    g.add_argument("--private-prefix", metavar="NET/SIZE",
                   default="10.64.0.0/16",
                   type=ipaddress.ip_network,
                   help="Base prefix for private subnets")
    g.add_argument("--provisioning-prefix", metavar="NET/SIZE",
                   default="10.128.0.0/15",
                   type=ipaddress.ip_network,
                   help="Base prefix for provisioning subnets")

    g = parser.add_argument_group("endpoint specifications")
    g.add_argument("site", metavar="SITE",
                   choices=SITE2OFFSET.keys(),
                   help="site name")
    g.add_argument("local_hostname", metavar="local",
                   help="Endpoint's local name (optional with port)")
    g.add_argument("remote_hostname", metavar="remote",
                   nargs="?",
                   help="Endpoint's remote name (optional with port)")

    return parser.parse_args(args)


def check_sizing(options):
    """Verify if the sizing of different options are correct.

    >>> check_sizing(parse_args(["sk1", ".", "."]))
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/16",
    ...     "--private-prefix=10.64.0.0/16",
    ...     "--provisioning-prefix=10.128.0.0/15",
    ...     "--pods=224",
    ...     "--ports-per-pod=136",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/17",
    ...     "--private-prefix=10.64.0.0/16",
    ...     "--provisioning-prefix=10.128.0.0/15",
    ...     "--pods=224",
    ...     "--ports-per-pod=136",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    Traceback (most recent call last):
        ...
    ValueError: ...
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/16",
    ...     "--private-prefix=10.64.0.0/17",
    ...     "--provisioning-prefix=10.128.0.0/15",
    ...     "--pods=224",
    ...     "--ports-per-pod=136",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    Traceback (most recent call last):
        ...
    ValueError: ...
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/16",
    ...     "--private-prefix=10.64.0.0/16",
    ...     "--provisioning-prefix=10.128.0.0/16",
    ...     "--pods=224",
    ...     "--ports-per-pod=136",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    Traceback (most recent call last):
        ...
    ValueError: ...
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/17",
    ...     "--private-prefix=10.64.0.0/17",
    ...     "--provisioning-prefix=10.128.0.0/16",
    ...     "--pods=100",
    ...     "--ports-per-pod=136",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    >>> check_sizing(parse_args([
    ...     "--public-prefix=100.64.0.0/15",
    ...     "--private-prefix=10.64.0.0/15",
    ...     "--provisioning-prefix=10.128.0.0/14",
    ...     "--pods=250",
    ...     "--ports-per-pod=256",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--spines=16",
    ...     "--ports-per-spine=64",
    ...     "--s-spines=16",
    ...     "--ports-per-s-spine=32",
    ...     "sk1", ".", "."]))
    """
    for prefix in [options.public_prefix,
                   options.private_prefix,
                   # Provisioning prefix needs to be twice as large as
                   # regular prefixes (/30 instead of /31).
                   next(options.provisioning_prefix.subnets())]:
        # Get the maximum number of PODs from the size of the prefix...
        allowed = prefix.num_addresses
        # ...divided by 2 since we need to allocate /31s...
        allowed //= 2
        # What do we get?
        got = options.pods * options.ports_per_pod + \
            options.spines * options.ports_per_spine + \
            options.s_spines * options.ports_per_s_spine
        if allowed < got:
            raise ValueError("not enough space for these "
                             "dimensions (allowed: {}, got: {})".format(
                                 allowed, got))


def get_prefix_with_offset(base, offset):
    """Compute prefix from base prefix plus offset.

    >>> get_prefix_with_offset(ipaddress.ip_network("10.0.0.0/16"), 0)
    IPv4Network('10.0.0.0/16')
    >>> get_prefix_with_offset(ipaddress.ip_network("10.0.0.0/16"), 3)
    IPv4Network('10.3.0.0/16')
    """
    return ipaddress.ip_network("{}/{}".format(
        base[0] +
        base.num_addresses * offset,
        base.prefixlen))


def parse_port(port):
    """Parse port to give an integer.

    >>> parse_port("xe-0/0/0")
    0
    >>> parse_port("xe-0/0/5")
    5
    >>> parse_port("et-0/0/5")
    5
    >>> parse_port("xe-1/0/5")
    Traceback (most recent call last):
        ...
    ValueError: ...
    >>> parse_port("swp1")
    0
    >>> parse_port("swp1s0")
    0
    >>> parse_port("swp1s1")
    1
    >>> parse_port("swp1s2")
    2
    >>> parse_port("swp1s3")
    3
    >>> parse_port("swp1s4")
    Traceback (most recent call last):
        ...
    ValueError: ...
    >>> parse_port("swp2")
    1
    >>> parse_port("swp2s0")
    4
    >>> parse_port("swp2s1")
    5
    >>> parse_port("swp32s0")
    124
    >>> parse_port("swp32s1")
    125
    >>> parse_port("swp32s2")
    126
    >>> parse_port("swp32s3")
    127
    >>> parse_port("swp18")
    17
    >>> parse_port("swp33")
    32
    >>> parse_port("swp34")
    33
    >>> parse_port("index55")
    55
    >>> parse_port("Flibuster-7")
    Traceback (most recent call last):
        ...
    ValueError: ...
    """
    mo = REGEXES['juniper-port'].match(port)
    if mo:
        return int(mo.group('port'))
    mo = REGEXES['cumulus-port'].match(port)
    if mo:
        port = int(mo.group('port'))
        if mo.group("subport"):
            # We assume all ports will use breakout syntax. If one
            # downstream port is not using breakout, the requester
            # should use the breakout syntax nonetheless: `swp18s0`
            # instead of `swp18`. Other exceptions should be handled
            # by providing port index directly (see `raw-index-port').
            subport = int(mo.group("subport"))
            return (port - 1) * 4 + subport
        return port-1
    mo = REGEXES['raw-index-port'].match(port)
    if mo:
        return int(mo.group('port'))
    raise ValueError('unknown access port: {}'.format(port))


def parse_hostname(hostname):
    """Parse hostname to extract characteristics. Return None if this is
    not a network equipment.

    >>> parse_hostname("to1-p10")
    host(kind='p', N=1, pod=10, port=None)
    >>> parse_hostname("to2-p10")
    host(kind='p', N=2, pod=10, port=None)
    >>> parse_hostname("to2-sp10")
    host(kind='sp', N=2, pod=10, port=None)
    >>> parse_hostname("to2-sp10:xe-0/1/2")
    host(kind='sp', N=2, pod=10, port='xe-0/1/2')
    >>> parse_hostname("spine1-compute-n1")
    host(kind='compute', N=1, port=None)
    >>> parse_hostname("spine1-storage-n1")
    host(kind='storage', N=1, port=None)
    >>> parse_hostname("s-spine1-n1")
    host(kind='s-spine', N=1, port=None)
    >>> parse_hostname("s-spine1-n2")
    host(kind='s-spine', N=2, port=None)
    >>> parse_hostname("spine1")
    host(kind='spine', N=1, port=None)
    >>> parse_hostname("spine5")
    host(kind='spine', N=5, port=None)
    >>> parse_hostname("s-spine3")
    host(kind='s-spine', N=3, port=None)
    >>> parse_hostname("not-s-spine1-n1") is None
    True
    """
    port = None
    if ":" in hostname:
        hostname, port = hostname.split(":", 1)
    mo = REGEXES["to"].match(hostname)
    if mo:
        return collections.namedtuple("host",
                                      "kind, N, pod, port")(
                                          mo.group("kind"),
                                          int(mo.group("N")),
                                          int(mo.group("pod")),
                                          port)
    for k in ("spine1", "spine2", "s-spine1", "s-spine2", "edge"):
        if not mo:
            mo = REGEXES[k].match(hostname)
    if mo:
        return collections.namedtuple("host",
                                      "kind, N, port")(mo.group("kind"),
                                                       int(mo.group("N")),
                                                       port)
    return None


def rank(hostname):
    """Rank the provided hostname with a tuple.

    >>> rank("to1-p10") > rank("to2-p10")
    True
    >>> rank("to1-p10") == rank("to1-p9")
    True
    >>> rank("edge1") < rank("spine1")
    True
    >>> rank("to1-p10") < rank("spine1-compute-n1")
    True
    >>> rank("to1-sp10") < rank("spine1-storage-n1")
    True
    >>> rank("to1-p10") < rank("spine1")
    True
    >>> rank("spine1-compute-n1") < rank("s-spine1-n1")
    True
    >>> rank("spine1-compute-n2") < rank("s-spine1-n1")
    True
    >>> rank("spine1-compute-n2") < rank("s-spine1-n2")
    True
    >>> rank("spine1") < rank("s-spine2")
    True
    >>> rank("spine1") < rank("s-spine1")
    True
    >>> rank("spine2") < rank("s-spine2")
    True
    """
    if isinstance(hostname, str):
        hostname = parse_hostname(hostname)
    if hostname is None:
        return (0,)
    return ({"edge": 0,
             "p": 1,
             "sp": 1,
             "ap": 1,
             "storage": 2,
             "compute": 3,
             "spine": 4,
             "s-spine": 5
             }[hostname.kind],
            -hostname.N)


def main(options):
    """Compute the various assignments and return them as a dictionary."""
    if options.remote_hostname is None:
        options.remote_hostname = options.local_hostname
        skip_ip = True
    else:
        skip_ip = False

    # Compute various helper values
    check_sizing(options)
    site_offset = SITE2OFFSET[options.site]
    private_prefix = get_prefix_with_offset(options.private_prefix,
                                            site_offset)
    logger.debug("private prefix for site is {}".format(private_prefix))
    public_prefix = get_prefix_with_offset(options.public_prefix,
                                           site_offset)
    logger.debug("public prefix for site is {}".format(public_prefix))
    provisioning_prefix = get_prefix_with_offset(options.provisioning_prefix,
                                                 site_offset)
    logger.debug("provisioning prefix is {}".format(provisioning_prefix))

    # Assignment algorithm
    local = parse_hostname(options.local_hostname)
    logger.debug("local hostname parsed to {}".format(local))
    remote = parse_hostname(options.remote_hostname)
    logger.debug("remote hostname parsed to {}".format(remote))

    if not local and not remote:
        raise RuntimeError("at least one endpoint should be a "
                           "network equipment")

    # Endpoints are paired
    l, r = local, remote
    offset = 0
    if rank(r) > rank(l):
        logger.debug("invert remote/local for offset calculation")
        l, r = remote, local
        offset = 1
    if not l.port and not skip_ip:
        raise RuntimeError("missing port information for {}".format(l))
    if not l.port and skip_ip:
        offset = None
    else:
        port = parse_port(l.port)
        logger.debug("{} offset is {}".format(l.port, port))
    if l.kind in {"p", "sp", "ap"} and not skip_ip:
        # IP assignment from ToR
        assert l.N in {1, 2}, "cannot handle more than 2 ToR"
        if l.N == 2:
            port += options.ports_per_pod//2
        assert port < options.ports_per_pod, \
            "port number cannot exceed max ports"
        if l.kind == "p":
            offset += ((l.pod - 1) * options.ports_per_pod + port) * 2
        elif l.kind == "sp":
            offset += ((options.last_storage_pod - l.pod + 1) *
                       options.ports_per_pod + port) * 2
        elif l.kind == "ap":
            offset += ((options.last_storage_pod + l.pod) *
                       options.ports_per_pod + port) * 2
        assert offset < options.pods * options.ports_per_pod * 2, \
            "offset unexpectedly too large"
    elif not skip_ip:
        offset += options.pods * options.ports_per_pod * 2
        if l.kind in {"storage", "compute", "spine"}:
            # IP assignment from spines
            assert l.N <= options.spines, \
                "cannot have more than {} spines".format(options.spines)
            if l.kind in {"storage", "compute"}:
                assert l.N <= 2, \
                    "cannot have more than 2 spine-compute/storage"
            assert port < options.ports_per_spine, \
                "port number cannot exceed max ports"
            if l.kind in {"compute", "spine"}:
                offset += ((l.N - 1) * options.ports_per_spine + port) * 2
            elif l.kind == "storage":
                offset += ((l.N + 1) * options.ports_per_spine + port) * 2
            assert offset < options.pods * options.ports_per_pod * 2 + \
                options.spines * options.ports_per_spine * 2, \
                "offset unexpectedly too large"
        else:
            offset += options.spines * options.ports_per_spine * 2
            if l.kind == "s-spine":
                # IP assignment from s-spines
                assert l.N <= options.s_spines, \
                    f"cannot have more than {options.s_spines} s-spines"
                assert port < options.ports_per_s_spine, \
                    "port number cannot exceed max ports"
                offset += ((l.N - 1) * options.ports_per_s_spine + port) * 2
                assert offset < options.pods * options.ports_per_pod * 2 + \
                    options.spines * options.ports_per_spine * 2 + \
                    options.s_spines * options.ports_per_s_spine * 2, \
                    "offset unexpectedly too large"
            else:
                offset += options.s_spines * options.ports_per_s_spine * 2
                # Special cases
                if l.kind == "edge":
                    offset += ((l.N - 1) * options.ports_per_edge + port) * 2
                else:
                    raise RuntimeError("unknown kind of equipment")

    if offset is not None:
        logger.debug("offset is {}".format(offset))

    # ASN
    asn = (4200 + site_offset) * 1000000
    if local:
        if local.kind == "s-spine":
            asn += 999992
        elif local.kind == "edge":
            asn += 999993 + local.N
        elif local.kind == "compute":
            asn += 999990
        elif local.kind == "spine":
            asn += 999980 + (local.N - 1)//2
        elif local.kind == "storage":
            asn += 999991
        elif local.kind == "p":
            asn += 990000 + local.N * 1000 + local.pod
        elif local.kind == "sp":
            asn += 980000 + local.N * 1000 + local.pod
        elif local.kind == "ap":
            asn += 970000 + local.N * 1000 + local.pod
        else:
            raise RuntimeError("cannot determine ASN for {}".format(
                options.local_hostname))
    elif remote.kind in ['p', 'sp', 'ap']:
        if remote.N == 1:
            asn += offset // 2
        else:
            # We assume servers are plugged symmetrically and ensure
            # they have the same ASN on both sides.
            asn += (offset - options.ports_per_pod) // 2
    else:
        raise RuntimeError("cannot determine ASN for {}".format(
            options.local_hostname))

    result = {
        'asn': asn,
    }
    if not skip_ip:
        result.update({
            'public': "{}/31".format(public_prefix[offset]),
            'private': "{}/31".format(private_prefix[offset]),
        })
        if local and not remote:
            result['provisioning'] = "{}/30".format(
                provisioning_prefix[offset*2 + 1])
        elif remote and not local:
            result['provisioning'] = "{}/30".format(
                provisioning_prefix[offset*2])

    return result
