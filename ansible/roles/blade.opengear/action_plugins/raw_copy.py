from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()
        result['changed'] = False

        # Get current config
        got = self._low_level_execute_command("cat {} ".format(module_args['dest_file']))
        if 'rc' in got and got['rc'] != 0:
            got = ""
        else:
            got = got['stdout'].replace('\r\n', '\n')
        # Get wanted config
        with open(module_args['src_file']) as f:
            wanted = f.read()

        if got != wanted:
            result['changed'] = True
            result['diff'] = dict(
                before=got,
                after=wanted
            )
        if self._play_context.check_mode or not result['changed']:
            return result
        # do the things
        self._low_level_execute_command("cat > {}".format(module_args['dest_file']), in_data=wanted)
        if 'rc' in got and got['rc'] != 0:
            result['failed'] = True
            result['stderr'] = got['stderr']
        return result
