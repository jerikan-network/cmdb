# Install dependencies
FROM python:3.8-buster AS dependencies
WORKDIR /app
ENV PYTHONUSERBASE=/app/python
RUN pip install --user pipenv
COPY ci/jerikan/Pipfile* ./
RUN env PIP_USER=1 PIPENV_SYSTEM=1 /app/python/bin/pipenv install --deploy

# Run tests
FROM python:3.8-buster AS tests
WORKDIR /app/jerikan
ENV PYTHONUSERBASE=/app/python
COPY --from=dependencies $PYTHONUSERBASE $PYTHONUSERBASE
COPY jerikan jerikan/
# COPY tests tests/
RUN python3 -m pytest -v --doctest-modules --log-level=info

# Build final image, tailored to current user UID
FROM python:3.8-slim-buster
ARG uid
ARG gid
RUN test -n "$uid" || ( echo "build arg 'uid' not set"; false )
RUN test -n "$gid" || ( echo "build arg 'gid' not set"; false )
WORKDIR /app/jerikan
ENV PYTHONUSERBASE=/app/python
RUN apt-get -qqy update \
    && apt-get install -qqy --no-install-recommends \
        curl \
        bgpq3 \
        diffutils \
        ifupdown \
        iptables \
        nftables \
        keepalived \
        bird \
        frr \
        isc-dhcp-server \
        openssh-client \
        wait-for-it \
        python3-yaml \
        yamllint \
    && rm -rf /var/cache/apt \
    && chmod u+s /usr/sbin/nft
COPY --from=dependencies $PYTHONUSERBASE $PYTHONUSERBASE
RUN groupadd -o -g $gid jerikan && useradd --no-log-init -m -o -g jerikan -u $uid jerikan
USER jerikan
VOLUME ["/app/jerikan"]
ENTRYPOINT ["ci/jerikan/entrypoint"]
CMD ["--help"]
