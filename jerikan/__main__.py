"""Blade network configuration builder with Jerakia.

The tool provide several subcommands. It requires a Jerakia server to
run.

The ``scope`` command computes the scope for a given device. The
``lookup`` command lookups a key for a given device.

The ``build`` command builds the templates for a selection of devices.
The set of devices to work on can be limited with the ``--limit`` flag
which accepts a list of devices. It is possible to use glob patterns.
The list of templates to build are taken by querying build/templates
key using the scope of each device. When using ``--device``, it is
possible to use a device name outside the ``devices.yaml`` file. This
is useful to have special devices like ``all``.

"""

import argparse
import fnmatch
import logging
import logging.handlers
import sys
import os
import yaml
import subprocess
import pytest
from diskcache import Cache
from jinja2.runtime import new_context

from .classifier import Classifier
from .jerakia import Jerakia
from .build import PytestPlugin
from .jinja import TemplateRenderer

logger = logging.getLogger("jerikan")


class CustomFormatter(
    argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter
):
    pass


def parse_args(args=sys.argv[1:]):
    """Parse arguments."""
    parser = argparse.ArgumentParser(
        description=sys.modules[__name__].__doc__, formatter_class=CustomFormatter
    )

    g = parser.add_mutually_exclusive_group()
    g.add_argument(
        "--debug", "-d", action="store_true", default=False, help="enable debugging"
    )
    g.add_argument(
        "--silent", "-s", action="store_true", default=False, help="don't log"
    )

    g = parser.add_argument_group("path to configuration files")
    g.add_argument(
        "--classifier", help="path to classifier YAML file", default="classifier.yaml"
    )
    g.add_argument("--devices", help="path to list of devices", default="devices.yaml")
    g.add_argument("--schema", help="path to schema file", default="schema.yaml")
    g.add_argument("--searchpaths", help="path to searchpaths method", default="searchpaths.py")
    g.add_argument("--data", help="path to data directory", default="data")

    subparsers = parser.add_subparsers(title="commands", dest="command")

    scope = subparsers.add_parser("scope", help="get scope for a device")
    scope.add_argument("device", metavar="DEVICE", help="device name")

    lookup = subparsers.add_parser("lookup", help="lookup a key for a device")
    lookup.add_argument("device", metavar="DEVICE", help="device name")
    lookup.add_argument("namespace", metavar="NS", help="namespace to query for key")
    lookup.add_argument("key", metavar="KEY", help="key to query")

    build = subparsers.add_parser("build", help="build templates")
    build.add_argument(
        "--limit", default="*", help="limit templates to build to a subset of devices"
    )
    build.add_argument(
        "--templates", default="templates", help="directory containing templates"
    )
    build.add_argument("--output", default="output",
                       help="output directory")
    build.add_argument("--cache-directory", default=".cache~",
                       help="cache directory between runs")
    build.add_argument("--cache-size", default="100",
                       type=int,
                       help="cache maximum size (in MiB)")
    build.add_argument("--skip-checks", default=False,
                       action="store_true",
                       help="skip checks")
    build.add_argument("--diff",
                       help="diff the generated configuration")

    return parser.parse_args(args)


def setup_logging(options):
    """Configure logging."""
    root = logging.getLogger("")
    root.setLevel(logging.WARNING)
    logger.setLevel(options.debug and logging.DEBUG or logging.INFO)
    if not options.silent:
        ch = logging.StreamHandler()
        ch._jerikan = True  # this will be removed when passing over to pytest
        ch.setFormatter(logging.Formatter("%(levelname)s[%(name)s] %(message)s"))
        root.addHandler(ch)


def do_scope(options, classifier, jerakia, devices):
    scope = classifier.scope(options.device)
    print("# Scope:")
    print(yaml.dump(scope))
    print("# Search paths:")
    for path in jerakia.searchpaths(scope):
        if os.path.isdir(os.path.join(options.data, path)):
            print(f"#  {path}")
        else:
            print(f"# ({path})")


def do_lookup(options, classifier, jerakia, devices):
    renderer = TemplateRenderer(basepath="",
                                classifier=classifier,
                                jerakia=jerakia,
                                devices=devices)
    scope = classifier.scope(options.device)
    result = renderer._lookup(
        new_context(renderer.env,
                    "internal lookup",
                    {},
                    vars=dict(device=options.device, **scope)),
        options.namespace,
        options.key)
    if result is not None:
        print(yaml.dump(result, sort_keys=False))


def do_build(options, classifier, jerakia, devices):
    # Linting
    logger.debug("YAML lint data directory (and ansible/)")
    subprocess.check_call(["yamllint",
                           ".yamllint",
                           "ansible",
                           options.data])

    # Building
    limits = options.limit.split(",")
    targets = []
    cache = Cache(options.cache_directory,
                  size_limit=options.cache_size*1024*1024)
    for device in devices:
        groups = classifier.scope(device).get("groups", [])
        for limit in limits:
            if fnmatch.fnmatch(device, limit):
                targets.append(device)
                break
            if any(fnmatch.fnmatch(group, limit) for group in groups):
                targets.append(device)
                break

        else:
            logger.debug("skip {}, not matching limits".format(device))
    ret = pytest.main(["-p", "no:cacheprovider"],
                      [PytestPlugin(templates=options.templates,
                                    output=options.output,
                                    skip_checks=options.skip_checks,
                                    diff=options.diff,
                                    cache=cache,
                                    classifier=classifier,
                                    jerakia=jerakia,
                                    devices=devices,
                                    targets=targets,
                                    debug=options.debug,
                                    silent=options.silent)])
    if ret != 0:
        sys.exit(1)


if __name__ == "__main__":
    options = parse_args()
    setup_logging(options)

    try:
        classifier = Classifier(yaml.safe_load(open(options.classifier)))
        jerakia = Jerakia(yaml.safe_load(open(options.schema)),
                          options.data,
                          classifier,
                          options.searchpaths)
        devices = yaml.safe_load(open(options.devices))["devices"]

        cmd = "do_{}".format(options.command)
        globals()[cmd](options, classifier, jerakia, devices)
    except Exception as e:
        logger.exception("%s", e)
        sys.exit(1)
    sys.exit(0)
