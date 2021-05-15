def searchpaths(scope):
    """Iterator over search paths.

    >>> searchpaths(dict(host="titi"))
    ['host/titi', 'common']
    >>> searchpaths(dict(host="titi.sk1", shorthost="titi", location="sk1"))
    ['host/titi.sk1', 'host/sk1/titi', 'groups/sk1', 'common']
    >>> searchpaths(dict(groups=["tor","tor-bgp"], location="sk1", continent="oc"))
    ['groups/tor-bgp-sk1', 'groups/tor-sk1', 'groups/tor-bgp-oc', 'groups/tor-oc', 'groups/tor-bgp', 'groups/tor', 'groups/sk1', 'common']
    """
    paths = [
        "host/{scope[host]}",
        "host/{scope[environment]}.{scope[location]}/{scope[shorthost]}",
        "host/{scope[location]}/{scope[shorthost]}",
        *[f"groups/{group}{path}" for path in [
            "-{scope[os]}-{scope[model]}-member{scope[member]}",
            "-member{scope[member]}",
            "-{scope[environment]}.{scope[location]}-pod{scope[pod]}",
            "-{scope[location]}-pod{scope[pod]}",
            "-{scope[environment]}.{scope[location]}-{scope[sublocation]}",
            "-{scope[location]}-{scope[sublocation]}",
            "-{scope[environment]}.{scope[location]}",
            "-{scope[location]}",
            "-{scope[continent]}",
            "-{scope[os]}-{scope[model]}",
            "",
        ] for group in scope.get('groups', [])[::-1]],
        "groups/{scope[environment]}.{scope[location]}-{scope[sublocation]}",
        "groups/{scope[location]}-{scope[sublocation]}",
        "groups/{scope[environment]}.{scope[location]}",
        "groups/{scope[location]}",
        "os/{scope[os]}-{scope[model]}",
        "os/{scope[os]}-{scope[location]}",
        "os/{scope[os]}",
        'common'
    ]
    for idx in range(len(paths)):
        try:
            paths[idx] = paths[idx].format(scope=scope)
        except KeyError:
            paths[idx] = None
    return [path for path in paths if path]
