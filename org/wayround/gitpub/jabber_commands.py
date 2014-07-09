
import org.wayround.xmpp.core


class JabberCommands:

    def __init__(self):
        self._environ = None

    def set_environ(self, environ):
        self._environ = environ

    def set_ssh_git_host(self, ssh_git_host):
        self._ssh_git_host = ssh_git_host

    def commands_dict(self):
        return dict(
            site=dict(
                register=self.register,
                login=self.login,
                set_key=self.set_key,
                home_list=self.home_list,
                help=self.help
                ),
            me=dict(
                status=self.status
                )
            )

    def status(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']
        ret_stanza = adds['ret_stanza']

        roles = self._environ.get_site_roles_for_jid(asker_jid)

        error = False

        jid_to_know = asker_jid

        len_args = len(args)

        if len_args == 0:
            pass

        elif len_args == 1:

            if roles['site_role'] == 'admin':

                jid_to_know = args[0]

                try:
                    org.wayround.xmpp.core.JID.new_from_str(jid_to_know)
                except:

                    messages.append(
                        {'type': 'error',
                         'text': "Invalid JID supplied"
                         }
                        )

                    error = True

            else:

                messages.append(
                    {'type': 'error',
                     'text': "You are not admin"}
                    )

                error = True

        else:

            messages.append(
                {'type': 'error',
                 'text': "Too many arguments"}
                )

            error = True

        if not error:

            roles_to_print = roles

            if roles['site_role'] == 'admin':
                roles_to_print = self._environ.get_site_roles_for_jid(
                    jid_to_know,
                    all_site_projects=True
                    )

            text = """
    {jid} site role: {site_role}

    {jid} project roles:
    """.format(
                site_role=roles_to_print['site_role'],
                jid=jid_to_know
                )

            projects = list(roles_to_print['project_roles'].keys())
            projects.sort()

            for i in projects:

                text += '    {}: {}\n'.format(
                    i,
                    roles_to_print['project_roles'][i]
                    )

            text += '\n'

            ret_stanza.body = [
                org.wayround.xmpp.core.MessageBody(
                    text=text
                    )
                ]

        return ret

    def register(self, comm, opts, args, adds):
        """
        Register self or new user

        [-r=role] [barejid]

        -r=role - role. one of 'admin', 'moder', 'user', 'guest'. only admin
                  can use this parameter

        barejid - user jid to register. leave empty to register self.
        """

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_jid(asker_jid)

        error = False

        role = 'user'
        jid_to_reg = asker_jid

        if roles['site_role'] == 'admin':
            if '-r' in opts:
                role = opts['-r']

            if len(args) == 1:
                jid_to_reg = args[0]

                try:
                    org.wayround.xmpp.core.JID.new_from_str(jid_to_reg)
                except:
                    messages.append(
                        {'type': 'error',
                         'text': "Can't parse supplied JID"}
                        )
                    error = True

        else:
            if '-r' in opts:
                messages.append(
                    {'type': 'error',
                     'text': "You are not admin and can't use -r option"}
                    )
                error = True

            if len(args) != 0:
                messages.append(
                    {'type': 'error',
                     'text': "You are not admin and can't use arguments"}
                    )
                error = True

        if error:
            pass
        else:

            registrant_role = \
                self._environ.rtenv.modules[self._environ.ttm].get_site_role(
                    jid_to_reg
                    )

            if (asker_jid == jid_to_reg
                    and roles['site_role'] != 'guest'):

                messages.append(
                    {'type': 'error',
                     'text': 'You already registered'}
                    )

                if not self._ssh_git_host.user_is_exists(jid_to_reg):
                    messages.append(
                        {'type': 'info',
                         'text': 'user not found in ssh git host. creating'}
                        )
                    self._ssh_git_host.user_create(jid_to_reg)

            elif registrant_role is not None:

                messages.append(
                    {
                        'type': 'error',
                        'text': '{} already have role: {}'.format(
                            jid_to_reg,
                            registrant_role.role
                            )
                        }
                    )

                if not self._ssh_git_host.user_is_exists(jid_to_reg):
                    messages.append(
                        {'type': 'info',
                         'text': 'user not found in ssh git host. creating'}
                        )
                    self._ssh_git_host.user_create(jid_to_reg)

            else:

                if ((roles['site_role'] == 'admin')
                    or
                    (roles['site_role'] != 'admin'
                     and self._environ.register_access_check(asker_jid))):

                    try:
                        self._environ.rtenv.modules[self._environ.ttm].\
                            add_site_role(
                                jid_to_reg,
                                role
                                )
                    except:
                        messages.append(
                            {'type': 'error',
                             'text': "can't add role. is already registered?"}
                            )
                    else:
                        messages.append(
                            {'type': 'info',
                             'text': 'registration successful'}
                            )

                        self._ssh_git_host.user_create(jid_to_reg)

                else:
                    messages.append(
                        {'type': 'error',
                         'text': "registration not allowed"}
                        )

        return ret

    def login(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_jid(asker_jid)

        cookie = None

        error = False

        if len(args) != 1:
            messages.append(
                {'type': 'error',
                 'text': "Cookie is required parameter"}
                )
            error = True
        else:
            cookie = args[0]

        if error:
            pass
        else:

            if roles['site_role'] == 'guest':
                messages.append(
                    {'type': 'error',
                     'text': "You are not registered"}
                    )
            else:

                session = self._environ.rtenv.modules[self._environ.ttm].\
                    get_session_by_cookie(
                        cookie
                        )

                if not session:
                    messages.append(
                        {'type': 'error',
                         'text': "Invalid session cookie"}
                        )
                else:

                    if ((roles['site_role'] == 'admin')
                        or (roles['site_role'] != 'admin'
                                    and
                                    self._environ.login_access_check(asker_jid)
                                    )
                        ):

                        self._environ.rtenv.modules[self._environ.ttm].\
                            assign_jid_to_session(
                                session,
                                asker_jid
                                )

                        messages.append(
                            {'type': 'info',
                             'text': "Logged in"}
                            )

                    else:

                        messages.append(
                            {'type': 'error',
                             'text': "Loggin forbidden"}
                            )

        return ret

    def set_key(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        roles = self._environ.get_site_roles_for_jid(asker_jid)

        error = False

        msg_msg_lines = stanza.get_body()[0].get_text().splitlines()

        msg = '\n'.join(msg_msg_lines[1:])

        who = asker_jid

        if '-j' in opts:
            if roles['site_role'] != 'admin':
                messages.append(
                    {'type': 'error',
                     'text': "Only admin allowed to use parameter -j"}
                    )
                error = True
            else:
                who = opts['-j']

        if not error:
            self._environ.rtenv.modules[self._environ.ttm].user_set_public_key(
                who, msg
                )

        if error:
            ret = 1

        return ret

    def home_list(self, comm, opts, args, adds):

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        error = False

        if not self._environ.check_permission(
                asker_jid,
                'can_read',
                '/'
                ):
            messages.append(
                {
                    'type': 'error',
                    'text': "Not allowed"
                    }
                )
            ret = 2

        else:
            res = self._ssh_git_host.home_list()
            messages.append(
                {
                    'type': 'text',
                    'text': repr(res)
                    }
                )

        if error:
            ret = 1

        return ret

    def home_create(self, comm, opts, args, adds):

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        error = False

        for_ = asker_jid

        asker_roles = self._environ.get_site_roles_for_jid(asker_jid)

        if '-j' in opts:
            for_ = opts['-j']

        if for_ != asker_jid and 'admin' not in asker_roles:
            messages.append(
                {
                    'type': 'error',
                    'text': "Not allowed"
                    }
                )
            ret = 3

        if ret == 0:

            if not self._environ.check_permission(
                    asker_jid,
                    'can_write',
                    '/'
                    ):
                messages.append(
                    {
                        'type': 'error',
                        'text': "Not allowed"
                        }
                    )
                ret = 2

            else:
                res = self._ssh_git_host.home_create()
                messages.append(
                    {
                        'type': 'text',
                        'text': repr(res)
                        }
                    )

        if error:
            ret = 1

        return ret

    def help(self, comm, opts, args, adds):

        if not self._environ:
            raise ValueError("use set_environ() method")

        ret = 0
        ret_stanza = adds['ret_stanza']

        text = """
help                          this command

status [JID]                  JID roles on site. defaults to asker. Only admin
                              can define JID

register [-r=ROLE] [JID]      register [self] or [somebody else](only admin can
                              do this) on site.

                              possible roles: 'admin', 'moder', 'user',
                                              'blocked'

                              default role is 'user'

                              already registered user can not be registered
                              again

                              non registered user has role 'guest'

                              when user registers self, he can not use -r
                              parameter, and -r will always be 'user'.

                              register will succeed only if it is not
                              prohibited on site.
"""
        ret_stanza.body = [
            org.wayround.xmpp.core.MessageBody(
                text=text
                )
            ]

        return ret
