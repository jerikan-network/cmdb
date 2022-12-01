"""Jinja templates for Jerikan."""

import os
import re
import functools
import subprocess
import netaddr
import shlex
import logging
import collections
import requests
import ipaddress
import inspect
from datetime import timedelta, datetime, time
import ansible.plugins.filter.core
import ansible_collections.ansible.netcommon.plugins.filter.ipaddr
from jinja2 import Environment, FileSystemLoader, \
    StrictUndefined, Undefined, \
    contextfunction, contextfilter
from jinja2 import TemplateRuntimeError
from jinja2.ext import Extension
from jinja2.nodes import CallBlock
from jinja2.nativetypes import NativeEnvironment

from . import bgptth
from .utils import TimeIt, wait_for

logger = logging.getLogger(__name__)
_registered_jinjafilters = []
_imported_jinjafilters = [
    (ansible.plugins.filter.core,
     ["regex_search",
      "regex_replace",
      "to_json",
      "to_yaml",
      "to_nice_yaml",
      "b64decode",
      ("get_hash", "hash"),
      ("get_encrypted_password", "password_hash")]),
    (ansible_collections.ansible.netcommon.plugins.filter.ipaddr,
     ["ipaddr",
      "ipmath",
      "ipsubnet",
      "ipv4",
      "ipv6",
      "cidr_merge",
      "hwaddr"])]


def jinjafilter(f):
    _registered_jinjafilters.append(f)
    return f


@jinjafilter
def ipv(address):
    """Return version of the given address.

    >>> ipv("192.168.1.1")
    4
    >>> ipv("192.168.1.0/24")
    4
    >>> ipv("2001:db8::1")
    6
    >>> ipv("2001:db8:1::/64")
    6
    """
    net = netaddr.IPNetwork(address)
    return net.version

@jinjafilter
@contextfilter
def ipv4toipv6(ctx, ipv4_to_convert, base_v6=None):
    """Encode an IPv4 inside an IPv6 prefix.

    >>> ipv4toipv6(None, "1.1.1.1", "2001:db8::/96")
    '2001:db8::101:101'
    >>> ipv4toipv6(None, "1.1.1.1/32", "2001:db8::/96")
    '2001:db8::101:101/128'
    >>> ipv4toipv6(None, "1.1.1.1/24", "2001:db8::/96")
    '2001:db8::101:101/120'
    """
    if base_v6 is None:
        base_v6 = ctx.call(ctx.parent["lookup"],
                           "topology", "base-public-6")
    base_v6 = ipaddress.ip_network(base_v6)
    assert base_v6.prefixlen == 96, "base-public-6 should be a /96"
    if "/" in ipv4_to_convert:
        ipv4_to_convert = ipaddress.ip_interface(ipv4_to_convert)
        return (f"{base_v6[int(ipv4_to_convert)]}/"
                f"{ipv4_to_convert.network.prefixlen + 96}")
    else:
        ipv4_to_convert = ipaddress.ip_address(ipv4_to_convert)
        return f"{base_v6[int(ipv4_to_convert)]}"


@jinjafilter
def mac2ipv6(address):
    """Convert a MAC address to an IPv6 LL address.

    >>> mac2ipv6("00:11:22:33:44:55")
    'fe80::211:22ff:fe33:4455'
    >>> mac2ipv6('FF:11:22:33:44:55')
    'fe80::fd11:22ff:fe33:4455'
    """
    mac = netaddr.EUI(address)
    return str(mac.ipv6_link_local())


@jinjafilter
def ippeer(address):
    """Compute peer IP address.

    >>> ippeer("192.1.1.0/31")
    '192.1.1.1'
    >>> ippeer("192.1.1.1/31")
    '192.1.1.0'
    >>> ippeer("192.1.1.1/30")
    '192.1.1.2'
    >>> ippeer("192.1.1.2/30")
    '192.1.1.1'
    >>> ippeer("192.1.1.1/29")
    Traceback (most recent call last):
        ...
    RuntimeError: Not a point-to-point network
    """
    net = netaddr.IPNetwork(address)
    if net.size == 2:
        return str(netaddr.IPAddress(int(net.ip) ^ 1))
    if net.size == 4:
        if int(net.ip) % 4 == 0:
            raise RuntimeError("Network address of /30 has no peer")
        if int(net.ip) % 4 == 3:
            raise RuntimeError("Broadcast address of /30 has no peer")
        return str(netaddr.IPAddress(int(net.ip) ^ 3))
    raise RuntimeError("Not a point-to-point network")


@jinjafilter
def ipoffset(base, offset):
    """Compute an IP address using a provide offset. The base should be a
    network. It is preserved if offset is an IP address or the mask is
    converted if not. Offset should not overflow the base address.

    >>> ipoffset('172.24.0.0/16', '0.0.15.10')
    '172.24.15.10/16'
    >>> ipoffset('172.24.0.0/16', '0.0.100.0/31')
    '172.24.100.0/31'
    >>> ipoffset('172.24.0.0/16', '0.1.100.0/31')
    Traceback (most recent call last):
        ...
    IndexError: ...
    >>> ipoffset('172.24.30.0/16', '0.0.15.10')
    '172.24.15.10/16'
    >>> ipoffset('172.24.30.0/16', (64, 27))
    '172.24.0.64/27'
    """
    base = netaddr.IPNetwork(base, flags=netaddr.NOHOST)
    offset = netaddr.IPNetwork(offset)
    result = base[offset.ip]
    return "{}/{}".format(str(result),
                          base.prefixlen
                          if offset.size == 1
                          else offset.prefixlen)

@jinjafilter
def dhcp_option119(fqdn):
    """Convert a FQDN to an hex-encoded DHCP option 119 (DNS search domain list, RFC 3397).

    >>> dhcp_option119("tx1.blade-group.net")
    '037478310b626c6164652d67726f7570036e657400'
    """
    result = ""
    for component in fqdn.split("."):
       result += "{:02x}{}".format(len(component), component.encode('ascii').hex())
    result += "00"
    return result

@jinjafilter
def torange(arg):

    """Convert a string representing a range to an actual range.

    >>> torange("1-4")
    [1, 2, 3, 4]
    >>> torange("1,2,3")
    [1, 2, 3]
    >>> torange("1-5,8,9")
    [1, 2, 3, 4, 5, 8, 9]
    >>> torange("5-1,9,10")
    [5, 4, 3, 2, 1, 9, 10]
    >>> torange("5/1,5/4,6/1-4")
    ['5/1', '5/4', '6/1', '6/2', '6/3', '6/4']
    """
    result = []
    for r in str(arg).split(","):
        if not r:
            continue
        if "-" in r:
            prefix = None
            if "/" in r:
                prefix, r = r.rsplit("/", 1)
            start, end = r.split("-", 1)
            start, end = int(start), int(end)
            if start <= end:
                partial_result = list(range(start, end + 1))
            else:
                partial_result = list(range(start, end - 1, -1))
            if prefix is None:
                result += partial_result
            else:
                result += ["{}/{}".format(prefix, c) for c in partial_result]
        else:
            try:
                result.append(int(r))
            except ValueError:
                result.append(r)
    return result


@jinjafilter
def tolist(arg):
    """Convert the argument to a list if it's not a list.

    >>> tolist(1)
    [1]
    >>> tolist("hello")
    ['hello']
    >>> tolist([1, 2, 3])
    [1, 2, 3]
    >>> tolist(Undefined())
    []
    """
    if isinstance(arg, list):
        return arg
    if isinstance(arg, Undefined):
        return []
    return [arg]


@jinjafilter
def slugify(arg):
    """Slugify its argument.

    >>> slugify("Hello World!")
    'helloworld'
    >>> slugify("Pac-Man")
    'pacman'
    """
    return "".join(filter(lambda x: x.isalnum(), arg.lower()))


def capitalize(arg):
    """Capitalize or upper depending on length.

    >>> capitalize('telia')
    'Telia'
    >>> capitalize('free peering')
    'Free peering'
    >>> capitalize('ix')
    'IX'
    >>> capitalize('man')
    'MAN'
    """
    if len(arg) <= 3:
        return arg.upper()
    return arg.capitalize()


@functools.lru_cache(maxsize=None)
def bgpq3(targetos, cache, name, *more):
    """Execute bgpq3 for the provided OS, using the provided filter name
    for a list of AS sets and arguments."""
    irrd_server = os.getenv("IRRD_SERVER", "rr.ntt.net")
    # Cache lookup
    cache = cache.unwrap()
    cachekey = ("bgpq3", irrd_server, targetos, name, *more)
    result = cache.get(cachekey)
    if result is not None:
        return result
    # Real lookup
    wait_for(irrd_server, 43)
    more = [arg for subargs in more for arg in shlex.split(subargs)]
    args = {"junos": ["-Jz"], "iosxr": ["-X"], "ios": []}[targetos]
    args += ["-h", irrd_server,
             "-Al", name,
             *more]
    with TimeIt("bgpq3 for {}".format(name)):
        result = subprocess.run(
            ["bgpq3", *args], check=True, capture_output=True, timeout=120
        )
    result = result.stdout.decode("ascii")
    # Store in cache, only until 1AM
    now = datetime.now()
    tomorrow = datetime.now() + timedelta(days=1)
    midnight = datetime.combine(tomorrow, time(hour=1), now.tzinfo)
    delta = midnight-now
    if delta > timedelta(days=1):
        delta -= timedelta(days=1)
    cache.set(cachekey, result, expire=(midnight-now).total_seconds())
    return result


@functools.lru_cache(maxsize=None)
def peeringdb(cache, asn):
    cache = cache.unwrap()
    cachekey = ("peeringdb", asn)
    cachekey_long = ("peeringdb-long", asn)
    result = cache.get(cachekey)
    if result is not None:
        return result
    try:
        r = requests.get("https://www.peeringdb.com/api/net",
                         params=dict(asn=asn),
                         timeout=10)
        r.raise_for_status()
    except requests.RequestException as exc:
        result = cache.get(cachekey_long)
        if result is None:
            raise
        logger.warning(f"unable to refresh PeeringDB ASN {asn}: {exc}")
        return result
    data = r.json()['data']
    assert len(data) == 1, "PeeringDB should contains exactly one match"
    result = data[0]
    cache.set(cachekey, result, expire=timedelta(days=1).total_seconds())
    cache.set(cachekey_long, result)
    return result


def recursion_detected(frame, keys):
    """Detect if we have a recursion by finding if we have already seen a
    call to this function with the same locals. Comparison is done
    only for the provided set of keys.

    """
    current = frame
    current_filename = current.f_code.co_filename
    current_function = current.f_code.co_name
    current_locals = {k: v
                      for k, v in current.f_locals.items()
                      if k in keys}
    while frame.f_back:
        frame = frame.f_back
        fname = frame.f_code.co_filename
        if not(fname.endswith(".py") or
               fname == "<template>"):
            return False
        if fname != current_filename or \
           frame.f_code.co_name != current_function:
            continue
        if ({k: v
             for k, v in frame.f_locals.items()
             if k in keys} == current_locals):
            return True
    return False


# Stolen from https://stackoverflow.com/questions/21778252/how-to-raise-an-exception-in-a-jinja2-macro
class ErrorExtension(Extension):
    """Extension providing {% error %} tag, allowing to raise errors
    directly from a Jinja template.
    """
    tags = frozenset(['error'])

    def parse(self, parser):
        """Parse the {% error %} tag, returning an AST node."""
        lineno = next(parser.stream).lineno
        message = parser.parse_expression()
        node = CallBlock(
            self.call_method('_raise', [message], lineno=lineno),
            [], [], [], lineno=lineno)
        return node

    def _raise(self, message, caller):
        """Execute the {% error %} statement, raising an exception."""
        raise TemplateRuntimeError(message)


class LruCacheIgnore(object):
    """Mark a parameter to be ignored by LRU cache.

    >>> i = 0
    >>> fn = functools.lru_cache()(lambda x: i)
    >>> fn(5)
    0
    >>> i = 10
    >>> fn(6)
    10
    >>> fn(LruCacheIgnore(5))
    10
    >>> i = 20
    >>> fn(LruCacheIgnore(6))
    10
    """
    def __init__(self, obj):
        self._obj = obj

    def __eq__(self, other):
        return type(self) is type(other)

    def __hash__(self):
        return 0

    def unwrap(self):
        return self._obj


class JerikanUndefined(StrictUndefined):
    '''Custom StructUndefined class which returns further Undefined
    objects on access instead of throwing an exception.
    '''
    def __getattr__(self, name):
        return self

    def __repr__(self):
        return "JerkianUndefined"


class TemplateRenderer(object):
    """Build Jinja templates."""

    def __init__(self, basepath, classifier, jerakia, devices, cache=None):
        def build_env(constructor):
            env = constructor(
                loader=FileSystemLoader(basepath),
                trim_blocks=True,
                lstrip_blocks=True,
                keep_trailing_newline=True,
                undefined=JerikanUndefined,
                extensions=[ErrorExtension, "jinja2.ext.do"]
            )

            # Use some filters from Ansible
            for mod, fs in _imported_jinjafilters:
                for f in fs:
                    try:
                        fn, name = f
                    except ValueError:
                        fn, name = f, f
                    env.filters[name] = getattr(mod, fn)

            # Register our own filters
            for f in _registered_jinjafilters:
                env.filters[f.__name__] = f
            env.filters["store"] = self._store_set

            # Register custom global functions
            env.globals["bgpq3"] = contextfunction(
                lambda ctx, *args: bgpq3(ctx.parent["os"],
                                         LruCacheIgnore(cache),
                                         *args))
            env.globals["peeringdb"] = lambda *args: peeringdb(
                                         LruCacheIgnore(cache),
                                         *args)
            env.globals["scope"] = classifier.scope
            env.globals["lookup"] = self._lookup
            env.globals["devices"] = self._devices
            env.globals["store"] = self._store_get
            env.globals["interface_description"] = self._interface_description
            return env

        self.env = build_env(Environment)
        self.native_env = build_env(NativeEnvironment)
        self.classifier = classifier
        self.jerakia = jerakia
        self.devices = devices
        self.store = collections.defaultdict(list)

        # BGPttH results (private IP) to check for dupes
        self._bgptth_results = {}

    @contextfilter
    def _store_set(self, ctx, value, key, *args):
        """Save arbitrary data to an internal store. The value stored is
        prefixed by the current device name and suffixed by additional
        arguments."""
        self.store[key].append((ctx.parent["device"], value, *args))
        return value

    def _store_get(self, key):
        """Retrieve data from the internal store."""
        return list(collections.OrderedDict.fromkeys(self.store[key]))

    @contextfunction
    def _interface_description(self, ctx, name):
        """Compute interface description."""
        interfaces = self._lookup(ctx, 'topology', 'interfaces')
        infos = interfaces[name]
        parent_infos = {}
        if "aggregate" in infos:
            parent_infos = interfaces[infos['aggregate']]
        elif "." in name:
            parent_infos = interfaces.get(name.split(".")[0], {})

        # Collect various bits of information
        dtype = capitalize(infos.get("type", parent_infos.get("type", "---")))
        dprovider = infos.get('provider', parent_infos.get('provider', ''))
        dremote = infos.get('remote', parent_infos.get('remote', ''))
        dcontract = "({})".format(infos['contract']) if 'contract' in infos else ''

        # Compute connectivity using parent interfaces if needed
        def connectivity(acc, name):
            if name in interfaces and "connectivity" in interfaces[name]:
                return acc + [interfaces[name]["connectivity"]]
            if "." in name:
                parent = name.split(".")[0]
                return connectivity(acc, parent)
            elif name.startswith(("ae", "Bundle-Ether")):
                parents = [pname
                           for pname in interfaces
                           if interfaces[pname].get("aggregate", None) == name]
                return acc + functools.reduce(connectivity, parents, acc)
            else:
                return acc
        speeds = connectivity([], name)
        if len(speeds) == 0:
            dspeed = "???"
        elif len(speeds) == 1:
            dspeed = speeds[0]
        else:
            dspeed = 0
            for speed in speeds:
                speed = speed.split("-")[0]
                assert speed.endswith("G"), "speed should end with 'G'"
                dspeed += int(speed[:-1])
            dspeed = f"{dspeed}G"

        # Get information from patchpanel
        patchpanels = self._lookup(ctx, 'topology', 'patchpanels') or {}
        ppinfo = ""
        for pp, ppinfos in patchpanels.items():
            for ppport, ppportinfos in ppinfos.get('ports', {}).items():
                if not ppportinfos:
                    continue
                if name == ppportinfos.get('port', None) and \
                   ctx.parent['shorthost'] == ppportinfos.get('device', None):
                    ppinfo = [pp,
                              "port:{}".format(ppport),
                              ppportinfos.get('reference', None)]
                    if ppinfo[2]:
                        ppinfo[2] = "ref:{}".format(ppinfo[2])
                    ppinfo = "{{{}}}".format(" ".join((i for i in ppinfo if i)))

        # Assemble description
        description = f"{dtype}: {dprovider} {dremote} [{dspeed}] {dcontract} {ppinfo}"
        description = re.sub(r'\s+', ' ', description.strip())

        if description == "---:":
            return None
        return description

    @contextfunction
    def _lookup(self, ctx, namespace, key, device=None):
        if device is None:
            device = ctx.parent["device"]
        if "." not in device and "environment" in ctx.parent:
            if ctx.parent["environment"] == "prod":
                location = ctx.parent["location"]
            else:
                location = "{}.{}".format(ctx.parent["environment"],
                                          ctx.parent["location"])
            device = "{}.{}.blade-group.net".format(device, location)
        if recursion_detected(inspect.currentframe(), {}):
            # When recursing, don't cache results
            return self._uncached_lookup(ctx, device, namespace, key)
        return self._cached_lookup(LruCacheIgnore(ctx), device, namespace, key)

    @functools.lru_cache(maxsize=None)
    def _cached_lookup(self, ctx, device, namespace, key):
        ctx = ctx.unwrap()
        return self._uncached_lookup(ctx, device, namespace, key)

    def _uncached_lookup(self, ctx, device, namespace, key):
        if namespace == "bgptth":
            return self._bgptth_lookup(device, key)
        result = self.jerakia.lookup(device, namespace, key)

        def render_template_jinja(something):
            if recursion_detected(inspect.currentframe(),
                                  {"something", "device", "namespace", "key"}):
                # When recursing, just give a bogus value
                return Undefined(name="RecursionReached")

            template = self.native_env.from_string(something)
            scope = self.classifier.scope(device)
            return template.render(device=device, **scope)

        def render_template_ip6_marker(previous):
            base = self.jerakia.lookup(device,
                                       "topology", "base-public-6")
            if base.startswith("~"):
                base = render_template_jinja(base[1:])
            return ipv4toipv6(ctx, previous, base)

        # Render templates in all values
        def render_template(something, previous=None):
            if isinstance(something, dict):
                return {render_template(key): render_template(value)
                        for key, value
                        in something.items()}
            if isinstance(something, str) and something.startswith("~"):
                try:
                    if something == "~^ip6":
                        # An ~^ip6 marker means we translate the
                        # previous element of a list to an IPv6
                        # address using base-public-6.
                        assert previous is not None, \
                            "~^ip6 marker should not be first"
                        return render_template_ip6_marker(previous)
                    # Otherwise, this is a Jinja template.
                    return render_template_jinja(something[1:])
                except Exception as exc:
                    raise RuntimeError(
                        "unable to render `{}' for {}: {}".format(
                            something[1:], device, str(exc))) from exc
            if isinstance(something, (list, set, tuple)):
                previous = None
                result = []
                for v in something:
                    got = render_template(v, previous)
                    previous = got
                    result.append(got)
                return type(something)(result)
            return something

        return render_template(result)

    def _bgptth_lookup(self, device, key):
        scope = self.classifier.scope(device)
        site = scope["location"]
        device = scope["shorthost"]
        args = shlex.split(key)
        # Add local device when an argument is missing
        if len(args) == 0:
            args = [device]
        elif len(args) == 1:
            args = [device, *args]
        elif len(args) > 2:
            raise RuntimeError("too many arguments provided for bgptth lookup")
        # Add local device if we only have a port
        for idx, arg in enumerate(args):
            if arg.startswith(":"):
                args[idx] = "{}{}".format(device, arg)
        args = [site, *args]
        # Apply overrides for some ports
        fargs = args[:]
        for idx, arg in enumerate(fargs):
            if ":" in arg:
                odevice, oport = arg.split(":", 1)
                overrides = self.jerakia.lookup(
                    f"{odevice}.{site}.blade-group.net",
                    "bgp", "bgptth-override") or {}
                if oport in overrides:
                    fargs[idx] = f"{odevice}:{overrides[oport]}"
        # Invoke bgpassignment main function
        logger.debug("invoke bgptth with {}".format(fargs))
        try:
            options = bgptth.parse_args(fargs)
        except SystemExit:
            raise RuntimeError("cannot parse bgptth key")
        result = bgptth.main(options)
        # Check we don't provide the same IP addresses to two
        # different ports (use args before port override)
        if 'private' in result:
            previous = self._bgptth_results.get(result['private'], None)
            if previous is not None and previous != args:
                raise RuntimeError(f"both `{' '.join(args)}' "
                                   f"and `{' '.join(previous)}' "
                                   f"collided to {result['private']}")
            self._bgptth_results[result['private']] = args
        return result

    @contextfunction
    def _devices(self, ctx, *matchers):
        current_scope = self.classifier.scope(ctx.parent["device"])
        result = []
        for device in self.devices:
            local_scope = self.classifier.scope(device)
            ok = True
            for matcher in matchers:
                mo = re.match(r"(?P<left>.*)(?P<operator>==|!=)(?P<right>.*)", matcher)
                if mo:
                    left = mo.group("left")
                    right = mo.group("right")
                    operator = mo.group("operator")
                else:
                    left = matcher
                    operator = "=="
                    right = current_scope.get(left, None)
                if left not in local_scope:
                    ok = False
                    break
                left = local_scope.get(left, None)
                if isinstance(left, list):
                    if [1 for el in left if right == el]:
                        if operator == "!=":
                            ok = False
                            break
                    else:
                        if operator == "==":
                            ok = False
                            break
                else:
                    if isinstance(left, int):
                        try:
                            right = int(right)
                        except ValueError:
                            pass
                    if right == left:
                        if operator == "!=":
                            ok = False
                            break
                    else:
                        if operator == "==":
                            ok = False
                            break
            if ok:
                result.append(device)
        return result

    def render(self, name, device):
        """Render a template."""
        template = self.env.get_template(name)
        scope = self.classifier.scope(device)
        return template.render(device=device, **scope)
