from ansible.plugins.action import ActionBase
import yaml
class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()
        result['changed'] = False

        # Get current config
        got = self._low_level_execute_command("config -g config")
        if 'rc' in got and got['rc'] != 0:
            result['failed'] = True
            result['msg'] = 'unable to grab configuration'
            result['stderr'] = got['stderr']
            return result

        got = got['stdout_lines']

        # Get wanted config
        with open(module_args['conf']) as f:
            wanted = [l.strip() for
                      l in f.readlines()
                      if l.strip() and not l.startswith("#") ]

        # Adapt some values
        got.append(self._low_level_execute_command(r"sed -n 's/^root:\(\$1\$[^:]*\):.*/config.users.user1.password \1/p' /etc/config/shadow")['stdout_lines'][0])
        if 'rc' in got and got['rc'] != 0:
            result['failed'] = True
            result['msg'] = 'Error while reading shadow file'
            result['stderr'] = got['stderr']
            return result

        whitelist = []
        for d in wanted:
            d = d.split(" ")[0]
            d = d.split(".")
            assert d[0] == "config"
            if d[1] in ["ports", "ntp", "users"]:
                whitelist.append(f"config.{d[1]}.")
            elif len(d) > 3:
                whitelist.append(".".join(d[:3]) + ".")
            else:
                whitelist.append(".".join(d) + " ")

        whitelist = tuple(whitelist)
        got = [d
               for d in got
               if d.startswith(whitelist) and not d.startswith("config.users.user1.groups.total")]

        wanted.sort()
        got.sort()
        if got != wanted:
            result['changed'] = True
            result['diff'] = dict(
                before=yaml.dump(got),
                after=yaml.dump(wanted)
            )

        cmds = ["config -g config > /tmp/config.back"]
        for cmd in got:
            if cmd not in wanted:
                cmds.append("config -d {}".format(cmd.split(" ")[0]))
        for cmd in wanted:
            if cmd not in got:
                cmds.append("config -s '{}'".format(cmd.replace(' ', '=', 1)))
        cmds.append("config -a")
        result["cmds"] = cmds

        if self._play_context.check_mode or not result['changed']:
            return result

        self._low_level_execute_command("bash -es", in_data="\n".join(cmds))
        if 'rc' in got and got['rc'] != 0:
            result['failed'] = True
            result['msg'] = 'Error when apply configuration'
            result['stderr'] = got['stderr']
        return result
