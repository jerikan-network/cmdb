"""Classifier-related functions."""

import re
import functools
import logging

logger = logging.getLogger(__name__)


class Classifier(object):

    def __init__(self, classifier):
        self.classifier = classifier

    @functools.lru_cache(maxsize=None)
    def scope(self, device):
        """Build scope for a given device from the classifier structure."""
        matchers = self.classifier["matchers"]
        scope = {}
        for matcher in matchers:
            for regex in matcher:
                mo = re.search(regex, device)
                if mo:
                    logger.debug("device {} match regex {}".format(device,
                                                                   regex))
                    for k, v in matcher[regex].items():
                        if isinstance(v, str):
                            scope[k] = mo.expand(v)
                        else:
                            scope[k] = v
        return scope
