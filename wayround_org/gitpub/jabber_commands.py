
import collections
import logging
import pprint

import wayround_org.xmpp.core
import wayround_org.gitpub.modules


class JabberCommands:

    def __init__(self):
        self._controller = None
        self._ssh_git_host = None
        return

    def set_controller(self, controller):
        self._controller = controller
        return

    def set_ssh_git_host(self, ssh_git_host):
        self._ssh_git_host = ssh_git_host
        return

    def commands_dict(self):
        return collections.OrderedDict(
            [
                ('set', self.set_set),
                ('register', self.register),
                ('status', self.stat),
                ('set-key', self.set_key),
                ('get-key', self.get_key),
                ('set-role', self.set_role),
                ('ls', self.ls)
                ]
        )

    def stat(self, comm, opts, args, adds):
        """
        Get status for You or some one JID on site, home or repository
        (using path)

        [-j=user] [path]

        If `path' is not specified, then status on site is returned, else
        the status and access permission on path is returned.

        Only owner can use -j parameter
        """

        if not self._controller:
            raise ValueError("use set_controller() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']
        ret_stanza = adds['ret_stanza']

        error = False

        jid_to_know = asker_jid

        len_args = len(args)

        if '-j' in opts:
            jid_to_know = opts['-j']

        path = '/'
        if len_args == 0:
            pass
        elif len_args == 1:
            path = args[0]
        else:
            messages.append(
                {'type': 'error',
                 'text': "Invalid arguments count"}
                )
            error = True

        try:
            jid_to_know = wayround_org.xmpp.core.jid_to_bare(jid_to_know)
        except:
            messages.append(
                {'type': 'error',
                 'text': "Can't parse interesting JID"}
                )
            error = True

        if not error:
            res = self._controller.status_by_path(
                asker_jid,
                jid_to_know,
                path,
                messages
                )

            messages.append(
                {'type': 'text',
                 'text': """
role:        {}
permissions: {}
""".format(res[0], ', '.join(res[1]))
                    }
                )

            ret = 0

        else:
            ret = int(error)

        return ret

    def register(self, comm, opts, args, adds):
        """
        Register self or new user (self by default)

        [-r=role] [barejid]

        Both option and argument can by used by owner only. Guests can register
        self only if this is permitted by configuration.

        -r=role - role. one of 'owner', 'user', 'guest', 'blocked'

        barejid - user jid to register. leave empty to register self
        """

        if not self._controller:
            raise ValueError("use set_controller() method")

        ret = 0
        asker_jid = adds['asker_jid']
        messages = adds['messages']

        len_args = len(args)

        error = False

        role = 'user'
        if '-r' in opts:
            role = opts['-r']

        target_jid = None
        if len_args == 0:
            target_jid = asker_jid
        elif len_args == 1:
            target_jid = args[0]
        else:
            messages.append(
                {'type': 'error',
                 'text': "Invalid arguments count"}
                )
            error = True

        try:
            target_jid = wayround_org.xmpp.core.JID.new_from_str(target_jid)
        except:
            messages.append(
                {'type': 'error',
                 'text': "Can't parse target JID"}
                )
            error = True

        if not error:
            ret = self._controller.register(
                asker_jid,
                target_jid,
                role,
                messages
                )
        else:
            ret = int(error)

        return ret

    def set_key(self, comm, opts, args, adds):
        """
        Set Your public key

        -j=JID    -  select for who set supplied key (this is for owner only)

        whis working following way (example):

        set-key [-j=JID]
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6nTLCVTT49cG0U3ELLoXq0bWAaZpiyE2
        7isZaH5ULNl8BpXxUSj/zr0Wt4Rr7g9ZBXvcXjyQvhr+mZgmdH+6f3C3R3TjIFFUEY2St9O
        BzEho6t53ycA+ubAS47cYhXIKTwtFVSDYq7o5B0ORojnsd78N7rdsV7YRwcUQy3JiEXXcJv
        cdi2XyfktdR1XTv81srikhkrToTE54MnhTc1Jgm6KrBy++4VOFj35gTASL39rK5mZxPzyW9
        PI/mAXo08CRzcxc0tNP5pxKx8gXSVy3weeUu4laqO8Hko6xWFZlNrkwMpC/brItphIAuuQm
        kgbv4rSfy7k5GpV97G/vzVjCZ animus@wayround.org

        where text below line with 'set-key' is copy/paste from Your .ssh/*.pub
        key
        """

        if not self._controller:
            raise ValueError("use set_controller() method")

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        roles = self._controller.get_role(asker_jid, asker_jid)

        error = False

        full_message_text = stanza.get_body()[0].get_text()

        target_jid = asker_jid

        if '-j' in opts:
            target_jid = opts['-j']

        if not error:
            self._controller.set_key(
                asker_jid,
                target_jid,
                full_message_text,
                messages
                )

        if error:
            ret = 1

        return ret

    def get_key(self, comm, opts, args, adds):
        """
        Print Your public key

        -j=JID    -  select who's key to get (this is for owner only)

        whis working following way (example):

        site get_key [-j=JID]
        """

        if not self._controller:
            raise ValueError("use set_controller() method")

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        roles = self._controller.get_role(asker_jid, asker_jid)

        error = False

        target_jid = asker_jid
        if '-j' in opts:
            target_jid = opts['-j']

        if not error:
            res = self._controller.get_key(
                asker_jid,
                target_jid,
                messages
                )
            if not isinstance(res, str):
                ret = 2
            else:
                messages.append(
                    {
                        'type': 'text',
                        'text': res
                    }
                    )

        if error:
            ret = 1

        return ret

    def ls(self, comm, opts, args, adds):
        """
        List homes on site or repositories in home
        """

        if not self._controller:
            raise ValueError("use set_controller() method")

        ret = 0
        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        error = False

        path = None
        
        len_args = len(args)
        
        if len_args == 0:
            messages.append(
                {
                    'type': 'error',
                    'text': "Path must be supplied"
                    }
                )
            error = True
        elif len_args == 1:
            path = args[0]
        else:
            messages.append(
                {
                    'type': 'error',
                    'text': "Invalid arguments count"
                    }
                )
            error = True

        if not error:

            res = self._controller.lst_by_path(
                asker_jid,
                asker_jid,
                path=path,
                messages=messages
                )

            if res is not None:
                messages.append(
                    {
                        'type': 'text',
                        'text': ' '.join(sorted(res))
                        }
                    )

            else:
                messages.append(
                    {
                        'type': 'error',
                        'text':
                            "Error getting list of"
                            " repositories in home `{}'".format(path)
                        }
                    )
                ret = 2

        else:
            ret = 1

        return ret

    def set_role(self, comm, opts, args, adds):
        """
        Set some one's role for site, home or repository.

        Usage: subject_jid path role

        Only owner can change roles for entire site.

        Home owner can change other's roles for own home or repositories only.

        Possible site roles are: ['owner', 'user', 'guest', 'blocked']
        Possible home roles are: ['owner', 'user', 'guest', 'blocked']
        Possible repo roles are: ['owner', 'user', 'guest', 'blocked']

        BUT: role which can be passed to this function are:

        Possible site roles are: ['owner', 'user', 'guest', 'blocked']
        Possible home roles are: ['user', 'guest', 'blocked']
        Possible repo roles are: ['user', 'guest', 'blocked']

        Keep in mind: site owner is allways has full access to everything on
                      site
        """

        ret = 0

        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        error = False

        subject_jid = None
        path = None
        role = None

        if not len(args) == 3:
            messages.append(
                {
                    'type': 'error',
                    'text': 'invalid count of arguments'
                }
                )
            error = True

        else:
            subject_jid, path, role = args

            try:
                subject_jid = wayround_org.xmpp.core.jid_to_bare(subject_jid)
            except:
                messages.append(
                    {'type': 'error',
                     'text': "Can't parse Your JID"}
                    )
                error = True

        if not error:

            try:
                self._controller.set_role_by_path(
                    asker_jid,
                    subject_jid,
                    path=path,
                    role=role,
                    messages=messages
                    )
            except Exception as e:
                messages.append(
                    {'type': 'error',
                     'text': e.args[0]}
                    )
                error = True

        return ret

    def set_set(self, comm, opts, args, adds):

        ret = 0

        asker_jid = adds['asker_jid']
        stanza = adds['stanza']
        messages = adds['messages']

        path = '/'
        name = None
        value = None

        args_l = len(args)

        if args_l == 0:
            messages.append(
                {
                    'type': 'error',
                    'text': "path - is required argument"
                    }
                )
            ret = 1

        else:

            if args_l > 0:
                path = args[0]

            if args_l > 1:
                name = args[1]

            if args_l > 2:
                value = args[2]

            if args_l > 3:
                messages.append(
                    {
                        'type': 'error',
                        'text': "Too many arguments"
                        }
                    )
                ret = 2

        if ret == 0:

            try:
                res = self._controller.set_setting_by_path(
                    asker_jid,
                    path,
                    name,
                    value,
                    messages
                    )
            except Exception as e:
                logging.exception("error")
                messages.append(
                    {'type': 'error',
                     'text': e.args[0]}
                    )
                ret = 3
            else:

                if res == 1:
                    messages.append(
                        {
                            'type': 'error',
                            'text': "Error returned: {}".format(res)
                            }
                        )
                    ret = 4
                else:
                    messages.append(
                        {'type': 'text',
                         'text': pprint.pformat(res)}
                        )

        return ret

    set_set.__doc__ = """
        Get/Set some site/home/repo setting

        path [name [value]]

        If name not given - list all settings and values for path

        If value not given - get value, else - set value

        acceptable site setting names are:
            {}
        acceptable home setting names are:
            {}
        acceptable repo setting names are:
            {}
        """.format(
        ', '.join(
            list(
                wayround_org.gitpub.modules.GitPub.ACCEPTABLE_SITE_SETTINGS.keys())
            ),
        ', '.join(
            list(
                wayround_org.gitpub.modules.GitPub.ACCEPTABLE_HOME_SETTINGS.keys())
            ),
        ', '.join(
            list(
                wayround_org.gitpub.modules.GitPub.ACCEPTABLE_REPO_SETTINGS.keys())
            ),
        )
