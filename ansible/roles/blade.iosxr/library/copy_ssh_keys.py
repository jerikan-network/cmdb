#!/usr/bin/env python3

import yaml
import textfsm
import io
import subprocess
import base64
import binascii
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.iosxr.plugins.module_utils.network.iosxr.iosxr import (
    copy_file,
    get_connection,
    run_commands,
)

DOCUMENTATION = """
---
module: copy_ssh_keys.py
short_description: Copy and enable SSH keys to IOSXR device
options:
  keys:
    required: true
    description:
      - dictionary mapping users to their SSH keys
"""


def ssh2cisco(sshkey):
    proc = subprocess.run(["ssh-keygen", "-f", "/dev/stdin", "-e", "-mPKCS8"],
                          input=sshkey.encode('ascii'),
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"unable to convert key: {sshkey}")
    decoded = base64.b64decode("".join(proc.stdout.decode(
        'ascii').split("\n")[1:-2]))
    return binascii.hexlify(decoded).decode('ascii').upper()


def run_module():
    module_args = dict(
        keys=dict(type='dict', required=True),  # user -> SSH key
    )

    result = dict(
        changed=False
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Get existing keys
    command = "show crypto key authentication rsa all"
    out = run_commands(module, command)

    # Parse keys

    # Key label: cedric
    # Type     : RSA public key authentication
    # Size     : 2048
    # Imported : 16:17:08 UTC Tue Aug 11 2020
    # Data     :
    #  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101
    #  00EBCBD5 3B9B0B7E E495B8A6 D297C983 20049AD8 7F4BE9BA 1BD17278 45E40DD6
    #  5D98BBD7 BB2B5B80 0DBD512B 3B76114E 079BE459 0CD1DF82 78623AC1 206EAAAB
    #  1E72F7D3 B45EA954 506BA7A8 1E6020F3 73D3F09C 875273C3 A718EA5D 104DA3C5
    #  9BAB5907 06F61C38 A98EBB04 FC79A96F B3165B54 AC4F1E0E FDD404D2 59D28314
    #  38510F34 5FDDC5FB A2754050 0672685F FC971839 3344B352 E9A1B1E6 A709BD7A
    #  ADBC90A1 93268B1B C9193846 86ACD095 FF51BF7D F7856A56 7BE6FBE9 1AB7B5DA
    #  BE735C66 6332E7BD E680B45B 570F9F5D 29424A8B FBF33B6C 14B398F1 994CD35D
    #  6186467D 87283F9C 575AB642 E3A743DE 3683D308 73304450 0B1CA3E9 11CC116B
    #  35020301 0001

    out = out[0].replace(' \n', '\n')
    template = r"""
Value Required Label (\w+)
Value Required,List Data ([A-F0-9 ]+)

Start
 ^Key label: ${Label}
 ^Data\s+: -> GetData

GetData
 ^ ${Data}
 ^$$ -> Record Start
""".lstrip()
    re_table = textfsm.TextFSM(io.StringIO(template))
    got = {data[0]: "".join(data[1]).replace(' ', '')
           for data in re_table.ParseText(out)}

    # Check what we want
    wanted = {k: ssh2cisco(v) for k, v in module.params['keys'].items()}

    if got != wanted:
        result['changed'] = True
        result['diff'] = dict(
            before=yaml.dump(got),
            after=yaml.dump(wanted)
        )

    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    # Copy changed or missing SSH keys
    conn = get_connection(module)
    for user in wanted:
        if user not in got or wanted[user] != got[user]:
            dst = f"/harddisk:/publickey_{user}.b64"
            with tempfile.NamedTemporaryFile() as src:
                decoded = base64.b64decode(
                    module.params['keys'][user].split()[1])
                src.write(decoded)
                src.flush()
                copy_file(module, src.name, dst)
        command = ("admin crypto key import authentication rsa "
                   f"username {user} harddisk:/publickey_{user}.b64")
        conn.send_command(command, prompt="yes/no", answer="yes")

    # Remove unwanted users
    for user in got:
        if user not in wanted:
            command = ("admin crypto key zeroize authentication rsa "
                       f"username {user}")
            conn.send_command(command, prompt="yes/no", answer="yes")

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
