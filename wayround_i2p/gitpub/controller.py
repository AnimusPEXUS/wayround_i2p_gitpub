
import os
import collections


import wayround_i2p.xmpp.core
import wayround_i2p.sshgithost.sshgithost


import wayround_i2p.gitpub.web_server


class Controller:

    def __init__(
            self,
            owner_jid='example@ex.nonexisting'
            ):

        self.owner_jid = owner_jid

        self.ttm = 'wayround_i2p_gitpub_modules_GitPub'

        self.rtenv = None
        self.bot = None
        self._ssh_git_host = None
        self.repo_view_site = None

        return

    def set_bot(self, bot):
        self.bot = bot
        return

    def set_repo_view_site(self, repo_view_site):
        if repo_view_site is not None and not isinstance(
                repo_view_site,
                wayround_i2p.gitpub.view_repo_server.GitPubViewRepoServer
                ):
            raise TypeError("`repo_view_site' - invalid type")
        self.repo_view_site = repo_view_site
        return

    def get_repo_view_site(self):
        return self.repo_view_site

    def set_ssh_git_host(self, ssh_git_host):
        self._ssh_git_host = ssh_git_host
        self._ssh_git_host.set_callbacks(
            {'check_key': self.check_key,
             'check_permission': self.check_permission_exported
             }
            )
        return

    def get_ssh_git_host(self):
        return self._ssh_git_host

    def set_rtenv(self, rtenv):
        self.rtenv = rtenv
        return

    def unregister(
            self,
            actor_jid,
            target_jid,
            messages
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        target_jid = wayround_i2p.xmpp.core.jid_to_bare(target_jid)

        actor_jid_role = self.get_role(actor_jid, actor_jid)

        error = False

        if actor_jid_role != 'owner':
            if actor_jid != target_jid:
                messages.append(
                    {'type': 'error',
                     'text':
                        "You are not owner and not allowed"
                        " to ungegister anybody except yourself"
                     }
                    )
                error = True

        if not error:

            self._ssh_git_host.home_delete(target_jid)

            self.rtenv.modules[self.ttm].del_home_and_user(target_jid)

        return int(error)

    def register(
            self,
            actor_jid,
            target_jid=None,
            target_role='user',
            messages=None
            ):

        if messages is None:
            raise ValueError("`messages' is required parameter")

        if target_jid is None:
            target_jid = actor_jid

        actor_jid_bare = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        target_jid_bare = wayround_i2p.xmpp.core.jid_to_bare(target_jid)

        actor_jid_role = self.get_role(actor_jid_bare, actor_jid_bare)

        error = False

        if actor_jid_role != 'owner':
            if target_role != 'user':
                messages.append(
                    {'type': 'error',
                     'text':
                        "You are not owner and can't select user target role"}
                    )
                error = True

            if actor_jid_bare != target_jid_bare:
                messages.append(
                    {'type': 'error',
                     'text':
                        "You are not owner and can't select target user jid"}
                    )
                error = True

        if not error:

            if (actor_jid_bare == target_jid_bare
                    and actor_jid_role != 'guest'):

                messages.append(
                    {'type': 'info',
                     'text': 'You already registered'}
                    )

                if not self._ssh_git_host.home_is_exists(target_jid_bare):
                    messages.append(
                        {'type': 'info',
                         'text': 'home not found in ssh git host. creating'}
                        )
                    self._ssh_git_host.home_create(target_jid_bare)

            else:

                target_jid_actual_role = \
                    self.rtenv.modules[self.ttm].get_site_role(
                        target_jid_bare
                        )

                if target_jid_actual_role != 'guest':

                    messages.append(
                        {
                            'type': 'info',
                            'text': '{} already have role: {}'.format(
                                target_jid_bare,
                                target_jid_actual_role
                                )
                            }
                        )

                    if not self._ssh_git_host.home_is_exists(target_jid_bare):
                        messages.append(
                            {'type': 'info',
                             'text': 'home not found in ssh git host. creating'}
                            )
                        self._ssh_git_host.home_create(target_jid_bare)

                else:

                    if ((actor_jid_role == 'owner')
                            or
                            (actor_jid_role == 'guest'
                             and self.get_setting(
                                 self.owner_jid,
                                 None,
                                 None,
                                 'guest_can_register_self',
                                         messages
                                 )
                             )
                        ):

                        try:
                            self.rtenv.modules[self.ttm].\
                                set_site_role(
                                    target_jid_bare,
                                    target_role
                                    )
                        except:
                            messages.append(
                                {'type': 'error',
                                 'text':
                                    "can't add role. is already registered?"
                                 }
                                )
                        else:
                            messages.append(
                                {'type': 'info',
                                 'text': 'registration successful'}
                                )

                            self._ssh_git_host.home_create(target_jid_bare)

                    else:
                        messages.append(
                            {'type': 'error',
                             'text': "registration not allowed"}
                            )

        return int(error)

    def status(
            self,
            actor_jid,
            home_level=None,
            repo_level=None,
            rest=None,
            messages=None
            ):

        path = wayround_i2p.sshgithost.sshgithost.join_levels(
            home_level,
            repo_level,
            rest
            )

        if ret == 0:
            ret = self.status_by_path(
                actor_jid,
                subject_jid,
                path,
                messages
                )

        return ret

    def status_by_path(
            self,
            actor_jid,
            jid_to_know=None,
            path=None,
            messages=None
            ):

        ret = 'guest', ['none']

        if path is None:
            path = '/'

        if jid_to_know is None:
            jid_to_know = actor_jid

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        jid_to_know = wayround_i2p.xmpp.core.jid_to_bare(jid_to_know)

        actor_role = self.get_role(actor_jid, actor_jid)

        error = False

        if actor_role != 'owner':
            if jid_to_know != actor_jid:
                messages.append(
                    {'type': 'error',
                     'text': "You are not owner, and can't select JID to know"
                     }
                    )
                error = True

        if not error:
            ret = (
                self.get_role_by_path(
                    actor_jid,
                    jid_to_know,
                    path,
                    messages
                    ),
                self.get_permissions_by_path(
                    actor_jid,
                    jid_to_know,
                    path,
                    messages
                    )
                )

        else:
            ret = 1

        return ret

    def get_role_by_path(
            self,
            actor_jid,
            subject_jid,
            path,
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        return self.get_role(
            actor_jid,
            subject_jid,
            home_level,
            repo_level
            )

    def get_role(
            self,
            actor_jid,
            subject_jid,
            home_level=None,
            repo_level=None,
            messages=None
            ):

        check_level_value_combination(home_level, repo_level)

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        ret = 'guest'

        if self.owner_jid == subject_jid:
            ret = 'owner'

        else:

            subject_jid_site_role = \
                self.rtenv.modules[self.ttm].get_site_role(subject_jid)

            if subject_jid_site_role == 'owner':
                ret = 'owner'

            else:

                if not self._ssh_git_host.home_is_exists(subject_jid):
                    ret = 'guest'
                else:

                    if home_level == repo_level is None:

                        ret = subject_jid_site_role

                    elif home_level is not None and repo_level is None:

                        ret = self.rtenv.modules[self.ttm].get_home_role(
                            home_level,
                            subject_jid
                            )

                    elif home_level is not None and repo_level is not None:

                        subject_jid_home_role = \
                            self.rtenv.modules[self.ttm].get_home_role(
                                home_level, subject_jid
                                )

                        if subject_jid_home_role == 'owner':

                            ret = 'owner'

                        else:

                            ret = self.rtenv.modules[self.ttm].get_repo_role(
                                home_level, repo_level, subject_jid
                                )

                    else:
                        ret = 'guest'

        return ret

    def set_role_by_path(
            self,
            actor_jid,
            subject_jid,
            path=None,
            role='guest',
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        return self.set_role(
            actor_jid,
            subject_jid,
            home_level,
            repo_level,
            role,
            messages
            )

    def set_role(
            self,
            actor_jid,
            subject_jid,
            home_level=None,
            repo_level=None,
            role='guest',
            messages=None
            ):

        check_level_value_combination(home_level, repo_level)

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        error = False

        actor_role = self.get_role(actor_jid, actor_jid)

        # owner can edit any roles everythere
        if actor_role != 'owner':

            # non-owner actor can edit only own home or repo
            if home_level != actor_jid:

                messages.append(
                    {
                        'type': 'error',
                        'text': "You are not owner - not allowed"
                    }
                    )
                error = True

            else:

                if actor_jid == subject_jid:
                    messages.append(
                        {
                            'type': 'error',
                            'text':
                                "You are allways owner of own resources."
                                " Action canceled"
                            }
                        )
                    error = True

        if not error:

            if home_level == repo_level is None:
                self.rtenv.modules[self.ttm].set_site_role(
                    subject_jid,
                    role
                    )

            elif home_level is not None and repo_level is None:
                self.rtenv.modules[self.ttm].set_home_role(
                    home_level,
                    subject_jid,
                    role
                    )

            elif home_level is not None and repo_level is not None:
                self.rtenv.modules[self.ttm].set_repo_role(
                    home_level,
                    subject_jid,
                    repo_level,
                    role
                    )

            else:
                raise ValueError("Invalid parameter combination")

        return int(error)

    def get_permissions_by_path(
            self,
            actor_jid,
            subject_jid,
            path,
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        return self.get_permissions(
            actor_jid,
            subject_jid,
            home_level,
            repo_level,
            messages
            )

    def get_permissions(
            self,
            actor_jid,
            subject_jid,
            home_level=None,
            repo_level=None,
            messages=None
            ):

        check_level_value_combination(home_level, repo_level)

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        ret = []

        for i in ['can_read', 'can_write']:
            if self.check_permission(
                    actor_jid,
                    subject_jid,
                    i,
                    home_level,
                    repo_level,
                    messages
                    ):
                ret.append(i)

        return ret

    def check_permission_by_path(
            self,
            actor_jid,
            subject_jid,
            what,
            path,
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        return self.check_permission(
            actor_jid,
            subject_jid,
            what,
            home_level,
            repo_level,
            messages
            )

    def _is_can_read_site(
            self,
            actor_jid,
            subject_jid,
            messages
            ):

        subject_jid_site_role = self.get_role(
            actor_jid,
            subject_jid
            )

        ret = False

        if subject_jid_site_role in ['guest', 'blocked']:

            # if guest or blocked

            if self.get_setting(
                    self.owner_jid,
                    None,
                    None,
                    'guest_can_list_homes',
                    messages
                    ):

                # if guests can list homes

                ret = True
            else:
                messages.append(
                    {
                        'type': 'error',
                        'text':
                            "subject is `{}'. "
                            "guests not allowed to "
                            "read root".format(
                                subject_jid_site_role
                                )
                        }
                    )

        else:
            # simple users and owner are allowed
            ret = True

        return ret

    def _is_can_read_home(
            self,
            actor_jid,
            subject_jid,
            home_level,
            messages
            ):

        ret = False

        if not self.check_permission(
                actor_jid,
                subject_jid,
                'can_read',
                home_level=None,
                repo_level=None,
                messages=messages
                ):

            # if can't list homes - can't list repositories eather

            messages.append(
                {
                    'type': 'error',
                    'text':
                        "so, subject is not allowed"
                        " to read home of `{}'".format(
                            home_level
                            )
                    }
                )

            ret = False

        else:

            # can list homes, deciding is can list repos

            subject_jid_home_role = self.get_role(
                actor_jid,
                subject_jid,
                home_level
                )

            if subject_jid_home_role == 'owner':
                # if owner of this home - sure can
                ret = True
            elif subject_jid_home_role in ['guest', 'blocked']:

                # if guest or blocked - can if guests allowed

                if self.get_setting(
                        self.owner_jid,
                        home_level,
                        None,
                        'guest_can_list_repos',
                        messages
                        ):
                    ret = True
                else:
                    messages.append(
                        {
                            'type': 'error',
                            'text':
                                "`{}' not allowed "
                                "to read home `{}'".format(
                                    subject_jid_home_role,
                                    home_level
                                    )
                            }
                        )

            elif subject_jid_home_role == 'user':
                # only users left. they can view
                if self.get_setting(
                        self.owner_jid,
                        home_level,
                        None,
                        'user_can_list_repos',
                        messages
                        ):
                    ret = True

            else:
                raise Exception("programming error")

        return ret

    def _is_can_read_repo(
            self,
            actor_jid,
            subject_jid,
            home_level,
            repo_level,
            messages
            ):

        ret = False

        if not self.check_permission(
                actor_jid,
                subject_jid,
                'can_read',
                home_level=home_level,
                repo_level=None,
                messages=messages
                ):
            # can't view if can't list home
            ret = False

        else:
            subject_jid_repo_role = self.get_role(
                actor_jid,
                subject_jid,
                home_level,
                repo_level
                )

            if subject_jid_repo_role == 'owner':
                # owner - can view
                ret = True

            elif subject_jid_repo_role in [
                    'guest', 'blocked'
                    ]:

                # if guest or blocked - can if guests allowed

                if self.get_setting(
                        self.owner_jid,
                        home_level,
                        repo_level,
                        'guest_can_read',
                        messages
                        ):
                    ret = True
                else:
                    messages.append(
                        {
                            'type': 'error',
                            'text':
                                "`{}' not allowed "
                                "to read repo `{}/{}'".format(
                                    subject_jid_repo_role,
                                    home_level,
                                    repo_level
                                    )
                            }
                        )
            elif subject_jid_repo_role == 'user':
                if self.get_setting(
                        self.owner_jid,
                        home_level,
                        repo_level,
                        'user_can_read',
                        messages
                        ):
                    ret = True
            else:
                ret = True

        return ret

    def check_permission_exported(
            self,
            subject_jid,
            what,
            home_level=None,
            repo_level=None
            ):
        messages = []
        return self.check_permission(
            self.owner_jid,
            subject_jid,
            what,
            home_level,
            repo_level,
            messages
            )

    def check_permission(
            self,
            actor_jid,
            subject_jid,
            what,
            home_level=None,
            repo_level=None,
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        check_level_value_combination(home_level, repo_level)

        if what not in ['can_read', 'can_write']:
            raise ValueError("invalid `what' value")

        if messages is None:
            raise ValueError("`messages' must be defined")

        ret = False

        subject_jid_site_role = self.get_role(
            actor_jid,
            subject_jid
            )

        if subject_jid_site_role == 'owner' or self.owner_jid == subject_jid:
            ret = True

        else:

            if what == 'can_read':

                if home_level is None and repo_level is None:

                    ret = self._is_can_read_site(
                        actor_jid,
                        subject_jid,
                        messages
                        )

                elif home_level is not None and repo_level is None:

                    # someone's home

                    ret = self._is_can_read_home(
                        actor_jid,
                        subject_jid,
                        home_level,
                        messages
                        )

                elif home_level is not None and repo_level is not None:

                    # some repo in someone's home

                    ret = self._is_can_read_repo(
                        actor_jid,
                        subject_jid,
                        home_level,
                        repo_level,
                        messages
                        )

                else:
                    raise Exception("invalid param combination")

            elif what == 'can_write':

                # manage: create, destroy

                if home_level is None and repo_level is None:

                    if self.get_role(actor_jid, subject_jid) == 'owner':
                        ret = True
                    else:
                        # nobody can write to root. registration - is
                        # absolutely different case in separate method
                        ret = False

                elif home_level is not None and repo_level is None:

                    if self.check_permission(
                            actor_jid,
                            subject_jid,
                            'can_read',
                            home_level=home_level,
                            repo_level=None,
                            messages=messages
                            ):

                        if self.get_role(
                                actor_jid,
                                subject_jid,
                                home_level
                                ) == 'owner':
                            ret = True

                elif home_level is not None and repo_level is not None:

                    if self.check_permission(
                            actor_jid,
                            subject_jid,
                            'can_read',
                            home_level=home_level,
                            repo_level=repo_level,
                            messages=messages
                            ):

                        subject_jid_repo_role = \
                            self.get_role(
                                actor_jid,
                                subject_jid,
                                home_level,
                                repo_level
                                )

                        if subject_jid_repo_role == 'owner':
                            ret = True

                        elif subject_jid_repo_role == 'user':
                            if self.get_setting(
                                    self.owner_jid,
                                    home_level,
                                    repo_level,
                                    'user_can_write',
                                    messages
                                    ):
                                ret = True

                        elif subject_jid_repo_role == 'guest':
                            if self.get_setting(
                                    self.owner_jid,
                                    home_level,
                                    repo_level,
                                    'guest_can_write',
                                    messages
                                    ):
                                ret = True
                        elif subject_jid_repo_role == 'blocked':
                            ret = False
                        else:
                            raise Exception("programming error")

                else:
                    raise Exception("invalid param combination")

            else:
                raise Exception("invalid `what' value")

        return ret

    def lst_by_path(
            self,
            actor_jid,
            subject_jid,
            path,
            messages=None
            ):

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        ret = 0

        if repo_level is not None or rest is not None:
            messages.append(
                {
                    'type': 'error',
                    'text':
                        "'repo_level' or 'rest' parts of path are"
                        " not allowed for this command"
                    }
                )
            ret = 1

        if ret == 0:
            ret = self.lst(
                actor_jid,
                subject_jid,
                home_level,
                messages
                )

        return ret

    def lst(
            self,
            actor_jid,
            subject_jid,
            home_level=None,
            messages=None
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        subject_jid = wayround_i2p.xmpp.core.jid_to_bare(subject_jid)

        ret = None

        if not self.check_permission(
                actor_jid,
                subject_jid,
                'can_read',
                home_level,
                None,
                messages
                ):
            messages.append(
                {
                    'type': 'error',
                    'text': "Can't list contents. permission related errors."
                    }
                )
            ret = None

        else:

            if home_level is None:
                ret = self._ssh_git_host.home_list()

            else:
                ret = self._ssh_git_host.repository_list(home_level)

        return ret

    def check_key(self, username, key):
        """
        return False or user bare jid
        """

        ret = False

        b64 = key.get_base64()

        error = False
        if len(b64) < 5:
            error = True

        if not error:

            type_ = 'ssh-rsa'

            res = self.rtenv.modules[self.ttm].get_jid_by_base64(
                type_,
                b64
                )

            ret = username in res

        if error:
            ret = False

        return ret

    def set_key(
            self,
            actor_jid,
            target_jid,
            full_message_text,
            messages
            ):

        ret = 0

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        target_jid = wayround_i2p.xmpp.core.jid_to_bare(target_jid)

        actor_role = self.get_role(actor_jid, actor_jid)

        error = False

        msg_msg_lines = full_message_text.splitlines()

        msg = ''.join(msg_msg_lines[1:])

        if actor_jid != target_jid:
            if actor_role != 'owner':
                messages.append(
                    {'type': 'error',
                     'text': "Only owner allowed to set keys for other users"}
                    )
                error = True

        if not error:
            ret = self.rtenv.modules[self.ttm].set_public_key(
                target_jid,
                msg
                )

            if ret != 0:
                messages.append(
                    {'type': 'error',
                     'text':
                        "Error setting key. Is there some wrong data supplied"}
                    )

        if error:
            ret = 1

        return ret

    def get_key(
            self,
            actor_jid,
            target_jid,
            messages
            ):

        ret = 0

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)
        target_jid = wayround_i2p.xmpp.core.jid_to_bare(target_jid)

        actor_role = self.get_role(actor_jid, actor_jid)

        error = False

        if actor_jid != target_jid:
            if actor_role != 'owner':
                messages.append(
                    {'type': 'error',
                     'text': "Only owner allowed to get keys for other users"}
                    )
                error = True

        if not error:
            ret = self.rtenv.modules[self.ttm].get_public_key(target_jid)

            if not isinstance(ret, dict):
                messages.append(
                    {'type': 'error',
                     'text':
                        "Error getting key."}
                    )
                ret = 2
            else:
                ret = ret['msg']

        if error:
            ret = 1

        return ret

    def get_setting_by_path(
            self,
            actor_jid,
            path,
            name,
            messages
            ):
        return self.set_setting_by_path(
            actor_jid,
            path,
            name,
            None,
            messages
            )

    def get_setting(
            self,
            actor_jid,
            home_level,
            repo_level,
            name,
            messages
            ):
        return self.set_setting(
            actor_jid,
            home_level,
            repo_level,
            name,
            None,
            messages
            )

    def set_setting_by_path(
            self,
            actor_jid,
            path,
            name,
            value,
            messages
            ):

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)

        home_level, repo_level, rest = \
            wayround_i2p.sshgithost.sshgithost.get_levels('/', path)

        return self.set_setting(
            actor_jid,
            home_level,
            repo_level,
            name,
            value,
            messages
            )

    def set_setting(
            self,
            actor_jid,
            home_level,
            repo_level,
            name,
            value,
            messages
            ):

        ret = 0

        check_level_value_combination(home_level, repo_level)

        actor_jid = wayround_i2p.xmpp.core.jid_to_bare(actor_jid)

        actor_role = self.get_role(actor_jid, actor_jid)

        error = False

        if home_level is None and repo_level is None:
            if value is not None:
                if actor_role != 'owner':
                    messages.append(
                        {'type': 'error',
                         'text': "Only owner allowed to change site settings"}
                        )
                    error = True

                else:

                    self.rtenv.modules[self.ttm].set_site_setting(
                        name, value
                        )

            else:
                if name is not None:
                    ret = self.rtenv.modules[self.ttm].get_site_setting(
                        name
                        )
                else:
                    ret = collections.OrderedDict()
                    for i in self.rtenv.modules[self.ttm].\
                            ACCEPTABLE_SITE_SETTINGS.keys():
                        ret[i] = self.get_setting(
                            actor_jid,
                            None,
                            None,
                            i,
                            messages
                            )

        elif home_level is not None and repo_level is None:
            if value is not None:
                if home_level != actor_jid:
                    messages.append(
                        {'type': 'error',
                         'text':
                            "Only owner allowed to change it's home settings"}
                        )
                    error = True

                else:
                    self.rtenv.modules[self.ttm].set_home_setting(
                        home_level, name, value
                        )
            else:
                if name is not None:
                    ret = self.rtenv.modules[self.ttm].get_home_setting(
                        home_level,
                        name
                        )
                else:
                    ret = collections.OrderedDict()
                    for i in self.rtenv.modules[self.ttm].\
                            ACCEPTABLE_HOME_SETTINGS.keys():
                        ret[i] = self.get_setting(
                            actor_jid,
                            home_level,
                            None,
                            i,
                            messages
                            )

        elif home_level is not None and repo_level is not None:
            if value is not None:
                if home_level != actor_jid:
                    messages.append(
                        {'type': 'error',
                         'text':
                            "Only owner allowed to change it's repo settings"}
                        )
                    error = True

                else:
                    self.rtenv.modules[self.ttm].set_repo_setting(
                        home_level, repo_level, name, value
                        )
            else:
                if name is not None:
                    ret = self.rtenv.modules[self.ttm].get_repo_setting(
                        home_level,
                        repo_level,
                        name
                        )
                else:
                    ret = collections.OrderedDict()
                    for i in self.rtenv.modules[self.ttm].\
                            ACCEPTABLE_REPO_SETTINGS.keys():
                        ret[i] = self.get_setting(
                            actor_jid,
                            home_level,
                            repo_level,
                            i,
                            messages
                            )

        else:
            raise ValueError("Invalid parameter combination")

        if error:
            ret = 1

        return ret


def check_level_value_combination(home_level, repo_level):
    if home_level is None and repo_level is None:
        pass

    elif home_level is not None and repo_level is None:
        pass

    elif home_level is not None and repo_level is not None:
        pass

    else:
        raise ValueError("Invalid parameter combination")

    return


def install_launcher(path):

    if not os.path.exists(path):
        os.makedirs(path)

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'site'))
    dst_dir = path

    wayround_i2p.utils.file.copytree(
        src_dir,
        dst_dir,
        overwrite_files=True,
        clear_before_copy=False,
        dst_must_be_empty=False
        )
