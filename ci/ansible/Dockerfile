ARG sha

# Install dependencies
FROM python:3.8-buster AS dependencies
WORKDIR /app
ENV PYTHONUSERBASE=/app/python
RUN pip install --user pipenv
COPY Pipfile* ./
RUN env PIP_USER=1 PIPENV_SYSTEM=1 /app/python/bin/pipenv install --deploy

COPY ansible-galaxy.yaml ./ansible-galaxy.yaml
RUN mkdir -p /etc/ansible/roles /etc/ansible/collections \
    && $PYTHONUSERBASE/bin/ansible-galaxy role install --roles-path /etc/ansible/roles -r ./ansible-galaxy.yaml \
    && $PYTHONUSERBASE/bin/ansible-galaxy collection install --collections-path /etc/ansible/collections -r ./ansible-galaxy.yaml

# Build final image, tailored to current user UID
FROM python:3.8-slim-buster AS ansible
ARG uid
ARG gid
RUN test -n "$uid" || ( echo "build arg 'uid' not set"; false )
RUN test -n "$gid" || ( echo "build arg 'gid' not set"; false )
RUN apt-get -qqy update \
    && apt-get install -qqy --no-install-recommends \
        curl \
        openssh-client \
        ca-certificates \
        gnupg \
        sshpass \
        whois \
        apt-transport-https

# Google Cloud SDK
RUN cd /opt \
    && curl -sL https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-300.0.0-linux-x86_64.tar.gz | tar zxf - \
    && ln -s /opt/google-cloud-sdk/bin/gsutil /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/.

RUN groupadd -o -g $gid ansible && useradd --no-log-init -m -o -g ansible -u $uid ansible
COPY blade-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV PYTHONUSERBASE=/app/python
ENV PATH="${PYTHONUSERBASE}/bin:${PATH}"
COPY --from=dependencies $PYTHONUSERBASE $PYTHONUSERBASE
COPY --from=dependencies /etc/ansible/ /etc/ansible/

USER ansible

# Configure SSH
ENV SSH_AUTH_SOCK=/app/ssh-agent.sock

WORKDIR /app/ansible
VOLUME ["/app/ansible"]
ENTRYPOINT ["ansible-playbook"]
CMD ["--help"]

# When only running ansible, we also need the output volume
FROM ansible AS ansible-only
VOLUME ["/app/output"]

# Alternatively, we retrieve the output volume from GitLab
FROM registry.gitlab.com/blade-group/infra/network/cmdb:outputs-${sha} AS data
FROM ansible AS ansible-and-data
ARG sha
RUN test -n "$sha" || ( echo "build arg 'sha' not set"; false )
COPY --from=data /output/ /app/output/
