"""Build-related functions for Jerikan."""

import os
import sys
import pytest
import logging
import subprocess
import shlex
import hashlib
import errno
import tempfile
import shutil
import fnmatch
import functools
import operator
from datetime import timedelta

from .jinja import TemplateRenderer, tolist
from .utils import TimeIt

logger = logging.getLogger(__name__)
pytest_plugins = ["html"]       # dependencies


def execute_check(plugin, check, device):
    """Execute a check with optional cache."""

    def complete_filename(filename):
        return os.path.join(plugin.output,
                            device,
                            filename)

    command = shlex.split(check['script'])
    command.append(device)
    if "cache" in check:
        if isinstance(check["cache"], (str, list)):
            check["cache"] = dict(input=check["cache"], output=[])
        # Check if the result is in cache. Compute hash of everything:
        # - device name
        # - script content
        # - content of input files participating in the cache
        # - list of output files
        h = hashlib.new('sha1')
        h.update(device.encode('ascii'))
        h.update(open(check['script'], 'rb').read())
        for filename in tolist(check["cache"]["input"]):
            try:
                h.update(open(complete_filename(filename), 'rb').read())
            except FileNotFoundError:
                logger.info(
                    "skip check {} on {} due to missing input {}".format(
                        check['description'],
                        device,
                        filename))
                return "", 0
        for filename in tolist(check["cache"]["output"]):
            h.update(filename.encode('ascii'))
        # Check if final digest is in cache
        digest = h.hexdigest()
        value = plugin.cache.get(digest)
        if value:
            logger.debug("cache hit for {} on {}".format(check['description'],
                                                         device))
            output, ret, outputs = value
            # Write cached files
            for filename in tolist(check["cache"]["output"]):
                content = outputs[filename]
                with open(complete_filename(filename), "wb") as f:
                    f.write(content)
            return output, ret
        logger.debug("cache miss for {} on {}".format(check['description'],
                                                      device))

    # Execute the command and collect output
    with TimeIt("check {} on {}".format(check['description'], device)):
        p = subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(timeout=300)
    ret = p.returncode
    output = "\n".join([
        'P: {}'.format(" ".join(command)),
        'C: {}'.format(os.getcwd()),
        '\n'.join(['O: {}'.format(l)
                   for l in stdout.decode(
                           'ascii', 'ignore').strip().split('\n')]),
        '\n'.join(['E: {}'.format(l)
                   for l in stderr.decode(
                           'ascii', 'ignore').strip().split('\n')]),
        'S: {}'.format(ret),
        ''])

    # Put in cache if needed
    if "cache" in check and ret == 0:
        # Save result in cache
        outputs = {}
        for filename in tolist(check["cache"]["output"]):
            with open(complete_filename(filename), "rb") as f:
                outputs[filename] = f.read()
        plugin.cache.set(digest, (output, ret, outputs),
                         expire=timedelta(days=7).total_seconds())
    return output, ret


def build(request, plugin, template_render, device):
    """Build the provided device."""
    # Templates
    templates = plugin.jerakia.lookup(device, "build", "templates") or {}
    if not templates:
        pytest.skip("no templates defined")
    for destination, template in templates.items():
        logger.info("build template {} to {} for {}".format(template,
                                                            destination,
                                                            device))
        template_render(device, {"name": template,
                                 "destination": destination})
    # Checks
    checks = []
    if not plugin.skip_checks:
        checks = plugin.jerakia.lookup(device, "build", "checks") or []
    for check in checks:
        description = check['description']
        logger.info("execute check `{}' on {}".format(description, device))
        output, ret = execute_check(plugin, check, device)
        request.node.add_report_section("call", description, output)
        if ret:
            raise RuntimeError(
                "failure when executing `{}' on {}".format(description,
                                                           device))

    # Diff
    os.makedirs(os.path.join(plugin.output, device), exist_ok=True)
    targets = plugin.jerakia.lookup(device, "build", "diff") or []
    if not plugin.skip_checks and plugin.diff and targets:
        with tempfile.TemporaryDirectory() as tmp:
            master = os.path.join(tmp, "a", device)
            current = os.path.join(tmp, "b", device)
            os.makedirs(master)
            os.makedirs(current)
            targets = [(fnmatch.filter(templates.keys(), target)
                        if "*" in target else [target])
                       for target in targets]
            targets = functools.reduce(operator.concat, targets)
            for target in targets:
                try:
                    shutil.copy(
                        os.path.join(plugin.output, device, target),
                        os.path.join(current, target))
                except FileNotFoundError:
                    pass
                try:
                    shutil.copy(
                        os.path.join(plugin.diff, device, target),
                        os.path.join(master, target))
                except FileNotFoundError:
                    pass
            with open(os.path.join(plugin.output,
                                   device,
                                   "diff.txt"), "w") as diff:
                logger.info("diff for {} to {}".format(device,
                                                       diff.name))
                subprocess.run(["diff", "-Naur",
                                "a", "b"],
                               stdout=diff,
                               cwd=tmp)


class PytestPlugin(object):
    def __init__(self, *, templates, output, skip_checks, diff, cache,
                 classifier, jerakia, devices, targets, debug, silent):
        self.renderer = TemplateRenderer(basepath=templates,
                                         classifier=classifier,
                                         jerakia=jerakia,
                                         devices=devices,
                                         cache=cache)
        self.output = output
        self.targets = targets
        self.jerakia = jerakia
        self.cache = cache
        self.skip_checks = skip_checks
        self.diff = diff
        self.debug = debug
        self.silent = silent

    def pytest_load_initial_conftests(self, early_config, parser, args):
        # Remove logging
        root = logging.getLogger("")
        root.handlers = [h for h in root.handlers
                         if not hasattr(h, "_jerikan")]
        # Core configuration
        early_config.addinivalue_line("python_functions", "build")
        args += ["-v", "--showlocals",
                 "--log-level=debug" if self.debug else "--log-level=info",
                 "--tb=short" if self.silent else
                 "--tb=long" if self.debug else
                 "--tb=auto"]
        # Configure plugins
        args += ["--html", os.path.join(self.output, "report.html"),
                 "--self-contained-html"]
        args += ["--junitxml", os.path.join(self.output, "junit.xml")]
        # Add ourselve as the file to test
        args += [sys.modules[__name__].__file__]

    def pytest_generate_tests(self, metafunc):
        if "device" in metafunc.fixturenames:
            return metafunc.parametrize("device", self.targets)

    @pytest.fixture(scope='session')
    def template_render(self):
        def _render(device, template):
            result = self.renderer.render(template["name"], device)
            if not result or not result.strip():
                logger.info(
                    "skip empty template {} for {}".format(device,
                                                           template["name"]))
                return
            os.makedirs(os.path.join(self.output, device,
                                     os.path.dirname(template["destination"])),
                        exist_ok=True)
            with open(os.path.join(self.output,
                                   device,
                                   template["destination"]), "w") as f:
                f.write(result)
        return _render

    @pytest.fixture(scope="session")
    def plugin(self):
        return self
