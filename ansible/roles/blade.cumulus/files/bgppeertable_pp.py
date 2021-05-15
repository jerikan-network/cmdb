#! /usr/bin/python -u

"""Net-SNMP pass persist script for BGP4-MIB's bgpPeerTable with
support for showing peers in all VRFs.

The VRFs are hard-coded at the top of the script.
"""

#   pass_persist 1.3.6.1.2.1.15 /usr/share/snmp/bgppeertable_pp.py

import os
import sys
import re
import logging
import logging.handlers
import subprocess
import json
import snmp_passpersist as snmp
if sys.argv[1] == 'bird':
    import dateutil.parser
    from datetime import datetime
    import pytz
    from tzlocal import get_localzone

bgpPeerTable = ".1.3.6.1.2.1.15"
logger = logging.getLogger("bgppeertable_pp")

DEVNULL = open(os.devnull, 'w')
vrfs = ["private", "public"]

re_birdcli_bgp_begin = re.compile(
    r"^(\S+)\s+BGP\s+\S+\s+\S+\s+(\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).*$")
re_birdcli_bgp_peer = {
    "remoteRouterId": re.compile(r"^\s+Neighbor ID:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$"),
    "bgpState": re.compile(r"^\s+BGP state:\s+([a-zA-Z]+)$"),
    "hostLocal": re.compile(r"^\s+Source address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$"),
    "bgpPeerRemoteAddr": re.compile(r"^\s+Neighbor address:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$"),
    "remoteAs": re.compile(r"^\s+Neighbor AS:\s+([0-9]+)$"),
    "updatesRecv": re.compile(r"^\s+Import updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$"),
    "updatesSent": re.compile(r"^\s+Export updates:\s+([0-9]+)\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+\s+[0-9\-]+$"),
    "LastReset": re.compile(r"^\s+Last error:\s+([a-zA-Z0-9-_\ ]+)$")}

def vtysh(command):
    """Execute command in vtysh and return result."""
    proc = subprocess.Popen(
        ["vtysh",
         "-c",
         command],
        stdin=DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(None)
    stdout = stdout.decode('utf-8', 'replace')
    stderr = stderr.decode('utf-8', 'replace')
    if proc.returncode != 0:
        logger.error("{} error:\n{}\n{}".format(
            "vtysh",
            "\n".join([" O: {}".format(line)
                       for line in stdout.rstrip().split("\n")]),
            "\n".join([" E: {}".format(line)
                       for line in stderr.rstrip().split("\n")])))
        raise RuntimeError("Unable to execute vtysh")
    return stdout

def birdc(command):
    proc = subprocess.Popen(
        ["birdc",
         command],
        stdin=DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(None)
    stdout = stdout.decode('utf-8', 'replace')
    stderr = stderr.decode('utf-8', 'replace')
    if proc.returncode != 0:
        logger.error("{} error:\n{}\n{}".format(
            "birdc",
            "\n".join([" O: {}".format(line)
                       for line in stdout.rstrip().split("\n")]),
            "\n".join([" E: {}".format(line)
                       for line in stderr.rstrip().split("\n")])))
        raise RuntimeError("Unable to execute birdc")
    proto = {}
    current_proto = None
    timezone = get_localzone()
    current_time = datetime.now(pytz.utc)
    for line in stdout.split("\n"):
        if re_birdcli_bgp_begin.search(line):
            current_proto = re_birdcli_bgp_begin.search(line)
            proto[current_proto.group(1)]= {}
            timestamp = dateutil.parser.parse(current_proto.group(2))
            if not timestamp.tzinfo:
                timestamp = timezone.localize(timestamp)
            proto[current_proto.group(1)]["bgpTimerUpMsec"] = abs(current_time - timestamp).total_seconds() * 1000
        for peerprop_name, peerprop_re in list(re_birdcli_bgp_peer.items()):
            match = peerprop_re.search(line)
            if match and current_proto:
                proto[current_proto.group(1)][peerprop_name] = match.group(1)
        if not line:
            current_proto = None
    output = {}
    for proto, infos in proto.items():
        output[infos['bgpPeerRemoteAddr']] = infos
        output[infos['bgpPeerRemoteAddr']]['messageStats'] = {}
        output[infos['bgpPeerRemoteAddr']]['messageStats']['updatesRecv'] = infos['updatesRecv']
        output[infos['bgpPeerRemoteAddr']]['messageStats']['updatesSent'] = infos['updatesSent']
    return output

def update():
    peers= {}
    passives = []
    if sys.argv[1] == 'frr':
        for vrf in vrfs:
            # Grab JSON output
            stdout = vtysh('show ip bgp vrf {} neighbors json'.format(vrf))
            peers.update(json.loads(stdout))

            # Get passive connections to ignore them. Only reliable way is
            # through FRR configuration file.
            config = vtysh('show run')
            for line in config.split("\n"):
                mo = re.match("^neighbor ([0-9.]+) passive$", line.strip())
                if mo:
                    passives.append(mo.group(1))

    elif sys.argv[1] == 'bird':
        # Grab JSON output
        peers = birdc('show protocols all')

    for peer, details in peers.items():
        # Skip passive connections
        if peer in passives:
            continue
        # Skip ipv6 peer
        if ":" in peer:
            continue
        state = dict(Idle=1,
                     Connect=2,
                     Active=3,
                     OpenSent=4,
                     OpenConfirm=5,
                     Established=6).get(details['bgpState'])
        # bgpVersion
        pp.add_oct("1.0", '10')
        # bgpLocalAs
        pp.add_int("2.0", details.get('localAs', 0))
        # bgpPeerIdentifier
        pp.add_ip("3.1.1.{}".format(peer), details.get('remoteRouterId', 0))
        # bgpPeerState
        pp.add_int("3.1.2.{}".format(peer), state)
        # bgpPeerAdminStatus
        pp.add_int("3.1.3.{}".format(peer), 2)  # start
        # bgpPeerNegotiatedVersion
        pp.add_int("3.1.4.{}".format(peer),
                   details.get('bgpVersion', 0) if state in ("Established",
                                                             "OpenConfirm")
                   else 0)
        # bgpPeerLocalAddr
        pp.add_ip("3.1.5.{}".format(peer), details.get('hostLocal', '0.0.0.0'))
        # bgpPeerLocalPort
        pp.add_int("3.1.6.{}".format(peer), details.get('hostPort', 0))
        # bgpPeerRemoteAddr
        pp.add_ip("3.1.7.{}".format(peer), peer)
        # bgpPeerRemotePort
        pp.add_int("3.1.8.{}".format(peer), details.get('portForeign', 0))
        # bgpPeerRemoteAs
        pp.add_int("3.1.9.{}".format(peer), details.get('remoteAs', 0))
        # bgpPeerInUpdates
        pp.add_cnt_32bit("3.1.10.{}".format(peer),
                            details['messageStats']['updatesRecv'])
        # bgpPeerOutUpdates
        pp.add_cnt_32bit("3.1.10.{}".format(peer),
                            details['messageStats']['updatesSent'])
        # bgpPeerInTotalMessages
        pp.add_cnt_32bit("3.1.12.{}".format(peer),
                         details['messageStats'].get('totalRecv', 0))
        # bgpPeerOutTotalMessages
        pp.add_cnt_32bit("3.1.13.{}".format(peer),
                         details['messageStats'].get('totalSent', 0))
        # bgpPeerLastError
        pp.add_str("3.1.14.{}".format(peer),
                   details.get('lastReset', "never"))
        # bgpPeerFsmEstablishedTransition
        pp.add_cnt_32bit("3.1.15.{}".format(peer),
                         details.get('connectionsEstablished', 0))
        # bgpPeerFsmEstablishedTime
        pp.add_gau("3.1.16.{}".format(peer),
                   int(details.get('bgpTimerUpMsec', 0)) /1000)
        # bgpPeerConnectRetryInterval (unknown)
        # bgpPeerHoldTime (unknown)
        # bgpPeerKeepAlive (unknown)
        # bgpPeerHoldTimeConfigured (unknown)
        # bgpPeerKeepAliveConfigured (unknown)
        # bgpPeerMinASOriginationInterval (unknown)
        # bgpPeerMinRouteAdvertisementInterval (unknown)
        # bgpPeerInUpdateElapsedTime (unknown)


# Logging
root = logging.getLogger("")
root.setLevel(logging.WARNING)
logger.setLevel(logging.INFO)
facility = logging.handlers.SysLogHandler.LOG_DAEMON
sh = logging.handlers.SysLogHandler(address='/dev/log',
                                    facility=facility)
sh.setFormatter(logging.Formatter(
    "{0}[{1}]: %(message)s".format(
        logger.name,
        os.getpid())))
root.addHandler(sh)

# Pass persist
try:
    pp = snmp.PassPersist(bgpPeerTable)
    pp.debug = False
    if pp.debug:
        update()
    else:
        logger.info("starting")
        pp.start(update, 20)
except Exception as e:
    logger.exception("%s", e)
    sys.exit(1)
