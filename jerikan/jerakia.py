"""Key-value store functions."""

import logging
import yaml
import functools
import os
import copy
from yaml import CSafeLoader as SafeLoader

logger = logging.getLogger(__name__)


class Jerakia(object):

    def __init__(self, schema, datapath, classifier, searchpaths):
        self.classifier = classifier
        self.schema = schema
        self.datapath = datapath
        with open(searchpaths) as code:
            g = {}
            exec(compile(code.read(), "searchpaths.py", "exec"), g)
            self.searchpaths = g['searchpaths']

    @functools.lru_cache(maxsize=None)
    def yaml_load(self, path):
        if not os.path.exists(path):
            return None
        with open(path) as input:
            return yaml.load(input, Loader=SafeLoader)

    @functools.lru_cache(maxsize=None)
    def lookup(self, device, namespace, key):
        """Lookup a value in Jerakia for a given device."""
        scope = self.classifier.scope(device)
        merge = self.schema.get(namespace, {}).get(key, {}).get("merge", None)
        assert merge in (None, "hash", "array")
        found = None
        for path in self.searchpaths(scope):
            path = os.path.join(self.datapath, path, f"{namespace}.yaml")
            data = self.yaml_load(path)
            if data is None or not key in data:
                continue
            current = copy.deepcopy(data[key])
            if merge is None:
                return current
            if found is None:
                found = current
            elif merge == "hash":
                current.update(found)
                found = current
            elif merge == "array":
                found.extend(current)
        return found
