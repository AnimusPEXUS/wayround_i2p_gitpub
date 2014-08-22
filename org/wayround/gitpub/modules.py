
import collections
import os.path

import persistent

import org.wayround.xmpp.core

import org.wayround.softengine.rtenv

GITPUB_MODULE_NAME = 'org_wayround_gitpub_modules_GitPub'


class GitPub(org.wayround.softengine.rtenv.ModulePrototype):

    ACCEPTABLE_SITE_SETTINGS = collections.OrderedDict([
        ('site_title', "No title"),
        ('guest_can_list_homes', False),
        ('guest_can_register_self', False)
        ])

    ACCEPTABLE_HOME_SETTINGS = collections.OrderedDict([
        ('title', "No title"),
        ('description', "No description"),
        ('site', ''),
        ('user_can_list_repos', False),
        ('guest_can_list_repos', False)
        ])

    ACCEPTABLE_REPO_SETTINGS = collections.OrderedDict([
        ('title', "No title"),
        ('description', "No description"),
        ('site', ''),
        ('user_can_read', False),
        ('user_can_write', False),
        ('guest_can_read', False),
        ('guest_can_write', False)
        ])

    def __init__(self, rtenv):

        self.module_name = GITPUB_MODULE_NAME

        self.session_lifetime = 24 * 60 * 60

        self.site_roles = [
            'admin', 'user', 'guest', 'blocked'
            ]

        self.home_roles = [
            'owner', 'user', 'guest', 'blocked'
            ]

        self.repo_roles = [
            'owner', 'user', 'guest', 'blocked'
            ]

        self.template_dir = \
            os.path.join(os.path.dirname(__file__), 'templates')
        self.css_dir = os.path.join(os.path.dirname(__file__), 'css')
        self.js_dir = os.path.join(os.path.dirname(__file__), 'js')

        self.rtenv = rtenv

        self.rtenv.modules[self.module_name] = self

        db_connection = self.rtenv.db.open()

        db_root = db_connection.root

        # site settings: {name -> value}
        if not hasattr(db_root, 'org_wayround_gitpub_settings'):
            db_root.org_wayround_gitpub_settings = \
                persistent.PersistentMapping()

        # {home -> {name -> value}}
        if not hasattr(db_root, 'org_wayround_gitpub_home_settings'):
            db_root.org_wayround_gitpub_home_settings = \
                persistent.PersistentMapping()

        # {home -> {repo -> {name -> value}}}
        if not hasattr(db_root, 'org_wayround_gitpub_repo_settings'):
            db_root.org_wayround_gitpub_repo_settings = \
                persistent.PersistentMapping()

        # {jid -> role}
        if not hasattr(db_root, 'org_wayround_gitpub_roles'):
            db_root.org_wayround_gitpub_roles = \
                persistent.PersistentMapping()

        # home -> {jid -> role}
        if not hasattr(db_root, 'org_wayround_gitpub_home_roles'):
            db_root.org_wayround_gitpub_home_roles = \
                persistent.PersistentMapping()

        # home -> {repo -> {jid -> role}}
        if not hasattr(db_root, 'org_wayround_gitpub_repo_roles'):
            db_root.org_wayround_gitpub_repo_roles = \
                persistent.PersistentMapping()

        # jid -> { 'msg' -> 'txt',
        #          'msg_type_part' -> 'txt',
        #          'msg_base64_part' -> 'txt'
        #          'msg_jid_part' -> 'txt'}
        if not hasattr(db_root, 'org_wayround_gitpub_public_keys'):
            db_root.org_wayround_gitpub_public_keys = \
                persistent.PersistentMapping()

        return

    def get_site_setting(self, name):

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        con_root = self.rtenv.db.open().root

        ret = self.ACCEPTABLE_SITE_SETTINGS[name]

        if name in con_root.org_wayround_gitpub_settings:
            ret = con_root.org_wayround_gitpub_settings[name]

        return ret

    def set_site_setting(self, name, value):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        if not isinstance(value, type(self.ACCEPTABLE_SITE_SETTINGS[name])):
            raise TypeError(
                "invalid site setting `{}' value type".format(name)
                )

        con_root = self.rtenv.db.open().root
        con_root.org_wayround_gitpub_settings[name] = value

        return

    def get_home_setting(self, home, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        con_root = self.rtenv.db.open().root

        ret = self.ACCEPTABLE_HOME_SETTINGS[name]

        if home in con_root.org_wayround_gitpub_home_settings:
            if name in con_root.org_wayround_gitpub_home_settings[home]:
                ret = con_root.org_wayround_gitpub_home_settings[home][name]

        return ret

    def set_home_setting(self, home, name, value):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        if not isinstance(value, type(self.ACCEPTABLE_HOME_SETTINGS[name])):
            raise TypeError(
                "invalid home setting `{}' value type".format(name)
                )

        con_root = self.rtenv.db.open().root

        if not home in con_root.org_wayround_gitpub_home_settings:
            con_root.org_wayround_gitpub_home_settings[home] = \
                persistent.PersistentMapping()

        con_root.org_wayround_gitpub_home_settings[home][name] = value

        return

    def get_repo_setting(self, home, repo, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_REPO_SETTINGS:
            raise ValueError("invalid `name'")

        con_root = self.rtenv.db.open().root

        ret = self.ACCEPTABLE_HOME_SETTINGS[name]

        if home in con_root.org_wayround_gitpub_repo_settings:
            if repo in con_root.org_wayround_gitpub_repo_settings[home]
                if name in con_root.org_wayround_gitpub_repo_settings[
                        home
                        ][repo]:
                    ret = con_root.org_wayround_gitpub_repo_settings[
                        home
                        ][
                        repo
                        ][
                        name]

        return ret

    def set_repo_setting(self, home, repo, name, value, _assume_absent=False):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        if not isinstance(value, type(self.ACCEPTABLE_HOME_SETTINGS[name])):
            raise TypeError(
                "invalid home setting `{}' value type".format(name)
                )

        con_root = self.rtenv.db.open().root

        if not home in con_root.org_wayround_gitpub_repo_settings:
            con_root.org_wayround_gitpub_repo_settings[home] = \
                persistent.PersistentMapping()

        if not repo in con_root.org_wayround_gitpub_repo_settings[home]:
            con_root.org_wayround_gitpub_repo_settings[home][repo] = \
                persistent.PersistentMapping()

        con_root.org_wayround_gitpub_repo_settings[home][name][repo] = value

        return

    def dict_site_roles(self):

        con_root = self.rtenv.db.open().root

        ret = dict(con_root.org_wayround_gitpub_roles)

        return ret

    def get_site_role(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        con_root = self.rtenv.db.open().root

        if jid in con_root.org_wayround_gitpub_roles:
            ret = con_root.org_wayround_gitpub_roles[jid]

        return ret

    def set_site_role(self, jid, role):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['admin', 'user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        con_root = self.rtenv.db.open().root

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_roles:
                del con_root.org_wayround_gitpub_roles[jid]

        else:

            con_root.org_wayround_gitpub_roles[jid] = role

        return

    def del_site_role(self, jid):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_site_role(jid, 'guest')
        return

    def dict_home_roles(self, home):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        con_root = self.rtenv.db.open().root

        ret = {}

        if home in con_root.org_wayround_gitpub_home_roles:
            ret = dict(con_root.org_wayround_gitpub_home_roles[home])

        return ret

    def get_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        con_root = self.rtenv.db.open().root

        if home == jid:
            ret = 'owner'
        else:

            if home in con_root.org_wayround_gitpub_home_roles:
                if jid in con_root.org_wayround_gitpub_home_roles[home]:
                    ret = con_root.org_wayround_gitpub_home_roles[home][jid]

        return ret

    def set_home_role(self, home, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        con_root = self.rtenv.db.open().root

        if not home in con_root.org_wayround_gitpub_home_roles:
            con_root.org_wayround_gitpub_home_roles[home] = \
                persistent.PersistentMapping()

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_home_roles[home]:
                del con_root.org_wayround_gitpub_home_roles[home][jid]

        else:

            con_root.org_wayround_gitpub_home_roles[home][jid] = value

        return

    def del_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_home_role(home, jid, 'guest')
        return

    def dict_repo_roles(self, home, repo):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        con_root = self.rtenv.db.open().root

        ret = {}

        if home in con_root.org_wayround_gitpub_repo_roles:
            if repo in con_root.org_wayround_gitpub_repo_roles[home]:
                ret = dict(con_root.org_wayround_gitpub_repo_roles[home][repo])

        return ret

    def get_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        con_root = self.rtenv.db.open().root

        if home == jid:
            ret = 'owner'
        else:

            if home in con_root.org_wayround_gitpub_home_roles:
                if repo in con_root.org_wayround_gitpub_home_roles[home]:
                    if jid in con_root.org_wayround_gitpub_home_roles[home][
                            repo
                            ]:
                        ret = con_root.org_wayround_gitpub_home_roles[
                            home
                            ][
                            repo
                            ][
                            jid]

        return ret

    def set_repo_role(self, home, repo, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        con_root = self.rtenv.db.open().root

        if not home in con_root.org_wayround_gitpub_repo_roles:
            con_root.org_wayround_gitpub_repo_roles[home] = \
                persistent.PersistentMapping()

        if not repo in con_root.org_wayround_gitpub_repo_roles[home]:
            con_root.org_wayround_gitpub_repo_roles[home][repo] = \
                persistent.PersistentMapping()

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_repo_roles[home][repo]:
                del con_root.org_wayround_gitpub_repo_roles[home][repo][jid]

        else:

            con_root.org_wayround_gitpub_repo_roles[home][repo][jid] = value

        return

    def del_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_repo_role(home, repo, jid, 'guest')
        return

    def get_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        con_root = self.rtenv.db.open().root

        ret = None

        if jid in con_root.org_wayround_gitpub_public_keys:
            res = con_root.org_wayround_gitpub_public_keys[jid]
            if is_correct_public_key_data(res['msg']):
                ret = res

        return ret

    def user_is_has_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        con_root = self.rtenv.db.open().root

        ret = None

        return (
            jid in con_root.org_wayround_gitpub_public_keys
            and
            is_correct_public_key_data(
                con_root.org_wayround_gitpub_public_keys[jid]['msg']
                )
            )

    def set_public_key(self, jid, msg):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 0

        if not is_correct_public_key_data(msg):
            ret = 1

        if ret == 0:

            con_root = self.rtenv.db.open().root

            splitted_msg = msg.split()

            if len(splitted_msg) != 3:
                ret = 2

        if ret == 0

            msg_jid = splitted_msg[2]

            msg_jid = msg_jid.lower()

            msg_jid = org.wayround.xmpp.core.jid_to_bare(msg_jid)

            if msg_jid != jid:
                ret = 3

        if ret == 0

            con_root.org_wayround_gitpub_public_keys[jid] = {
                'msg': msg
                'msg_type_part': parsed_msg[0]
                'msg_base64_part': ''.join(parsed_msg[1].splitlines())
                'msg_jid_part': msg_jid
                }

            ret = 0

        return ret

    def del_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        con_root = self.rtenv.db.open().root

        if jid in con_root.org_wayround_gitpub_public_keys:
            del con_root.org_wayround_gitpub_public_keys[jid]

        return

    def get_jid_by_base64(self, type_, base64):

        con_root = self.rtenv.db.open().root

        b64_1 = ''.join(base64.splitlines())

        ret = set()

        for k, v in con_root.org_wayround_gitpub_public_keys:
            if v['msg_type_part'] == type_:
                if b64_1 == ''.join(v['msg_base64_part'].splitlines()):
                    ret.add(org.wayround.xmpp.core.jid_to_bare(k))

        return list(ret)

    def del_home_and_role(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        con_root = self.rtenv.db.open().root

        if jid in db_root.org_wayround_gitpub_home_settings:
            del db_root.org_wayround_gitpub_home_settings[jid]

        if jid in db_root.org_wayround_gitpub_repo_settings:
            del db_root.org_wayround_gitpub_repo_settings[jid]

        if jid in db_root.org_wayround_gitpub_home_roles:
            del db_root.org_wayround_gitpub_home_roles[jid]

        if jid in db_root.org_wayround_gitpub_repo_roles:
            del db_root.org_wayround_gitpub_repo_roles[jid]

        self.del_site_role(jid)

        return


def _value_to_bool(value):
    if isinstance(value, str):
        value = value.lower()

    ret = False

    if isinstance(value, int):
        ret = value != 0
    else:
        ret = value in [True, 1, '1', 'yes', 'true', 'ok', 'y']

    return ret


def is_correct_public_key_data(msg):

    ret = False

    pkey = msg

    if pkey is not None:
        parsed_msg = pkey.msg.split()

        error = False

        if parsed_msg[0] != pkey['msg_type_part']:
            error = True

        if parsed_msg[1] != pkey['msg_base64_part']:
            error = True

        if parsed_msg[2] != pkey['msg_jid_part']:
            error = True

        # TODO: add more checks

        if not error:
            ret = True

    return ret
