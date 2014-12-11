
import collections
import os.path

import persistent.mapping
import persistent.list

import transaction

import org.wayround.xmpp.core
import org.wayround.utils.types

import org.wayround.softengine.rtenv

GITPUB_MODULE_NAME = 'org_wayround_gitpub_modules_GitPub'


class GitPub(org.wayround.softengine.rtenv.ModulePrototype):

    ACCEPTABLE_SITE_SETTINGS = collections.OrderedDict([
        ('title', "No title"),
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
        ('home_site_url', ''),
        ('site_branch_name', ''),
        ('user_can_read', False),
        ('user_can_write', False),
        ('guest_can_read', False),
        ('guest_can_write', False)
        ])

    def __init__(self, rtenv):

        self.module_name = GITPUB_MODULE_NAME

        self.session_lifetime = 24 * 60 * 60

        self.site_roles = [
            'owner', 'user', 'guest', 'blocked'
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
                persistent.mapping.PersistentMapping()

        # {home -> {name -> value}}
        if not hasattr(db_root, 'org_wayround_gitpub_home_settings'):
            db_root.org_wayround_gitpub_home_settings = \
                persistent.mapping.PersistentMapping()

        # {home -> {repo -> {name -> value}}}
        if not hasattr(db_root, 'org_wayround_gitpub_repo_settings'):
            db_root.org_wayround_gitpub_repo_settings = \
                persistent.mapping.PersistentMapping()

        # {jid -> role}
        if not hasattr(db_root, 'org_wayround_gitpub_roles'):
            db_root.org_wayround_gitpub_roles = \
                persistent.mapping.PersistentMapping()

        # home -> {jid -> role}
        if not hasattr(db_root, 'org_wayround_gitpub_home_roles'):
            db_root.org_wayround_gitpub_home_roles = \
                persistent.mapping.PersistentMapping()

        # home -> {repo -> {jid -> role}}
        if not hasattr(db_root, 'org_wayround_gitpub_repo_roles'):
            db_root.org_wayround_gitpub_repo_roles = \
                persistent.mapping.PersistentMapping()

        # jid -> { 'msg' -> 'txt',
        #          'msg_type_part' -> 'txt',
        #          'msg_base64_part' -> 'txt'
        #          'msg_jid_part' -> 'txt'}
        if not hasattr(db_root, 'org_wayround_gitpub_public_keys'):
            db_root.org_wayround_gitpub_public_keys = \
                persistent.mapping.PersistentMapping()

        transaction.commit()
        db_connection.close()

        return

    def get_site_setting(self, name):

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = self.ACCEPTABLE_SITE_SETTINGS[name]

        if name in con_root.org_wayround_gitpub_settings:
            ret = con_root.org_wayround_gitpub_settings[name]

        transaction.commit()
        db_con.close()

        return ret

    def set_site_setting(self, name, value):

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        if isinstance(self.ACCEPTABLE_SITE_SETTINGS[name], bool):
            value = org.wayround.utils.types.value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_SITE_SETTINGS[name])):
            raise TypeError(
                "invalid site setting `{}' value type".format(name)
                )

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        con_root.org_wayround_gitpub_settings[name] = value

        transaction.commit()
        db_con.close()

        return

    def get_home_setting(self, home, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = self.ACCEPTABLE_HOME_SETTINGS[name]

        if home in con_root.org_wayround_gitpub_home_settings:
            if name in con_root.org_wayround_gitpub_home_settings[home]:
                ret = con_root.org_wayround_gitpub_home_settings[home][name]

        transaction.commit()
        db_con.close()

        return ret

    def set_home_setting(self, home, name, value):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        if isinstance(self.ACCEPTABLE_HOME_SETTINGS[name], bool):
            value = org.wayround.utils.types.value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_HOME_SETTINGS[name])):
            raise TypeError(
                "invalid home setting `{}' value type".format(name)
                )

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if not home in con_root.org_wayround_gitpub_home_settings:
            con_root.org_wayround_gitpub_home_settings[home] = \
                persistent.mapping.PersistentMapping()

        con_root.org_wayround_gitpub_home_settings[home][name] = value

        transaction.commit()
        db_con.close()

        return

    def get_repo_setting(self, home, repo, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_REPO_SETTINGS:
            raise ValueError("invalid `name'")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = self.ACCEPTABLE_REPO_SETTINGS[name]

        if home in con_root.org_wayround_gitpub_repo_settings:
            if repo in con_root.org_wayround_gitpub_repo_settings[home]:
                if name in con_root.org_wayround_gitpub_repo_settings[
                        home
                        ][repo]:
                    ret = con_root.org_wayround_gitpub_repo_settings[
                        home
                        ][
                        repo
                        ][
                        name]

        transaction.commit()
        db_con.close()

        return ret

    def set_repo_setting(self, home, repo, name, value):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_REPO_SETTINGS:
            raise ValueError("invalid `name'")

        if isinstance(self.ACCEPTABLE_REPO_SETTINGS[name], bool):
            value = org.wayround.utils.types.value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_REPO_SETTINGS[name])):
            raise TypeError(
                "invalid home setting `{}' value type".format(name)
                )

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if not home in con_root.org_wayround_gitpub_repo_settings:
            con_root.org_wayround_gitpub_repo_settings[home] = \
                persistent.mapping.PersistentMapping()

        if not repo in con_root.org_wayround_gitpub_repo_settings[home]:
            con_root.org_wayround_gitpub_repo_settings[home][repo] = \
                persistent.mapping.PersistentMapping()

        con_root.org_wayround_gitpub_repo_settings[home][name][repo] = value

        transaction.commit()
        db_con.close()

        return

    def dict_site_roles(self):

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = dict(con_root.org_wayround_gitpub_roles)

        transaction.commit()
        db_con.close()

        return ret

    def get_site_role(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if jid in con_root.org_wayround_gitpub_roles:
            ret = con_root.org_wayround_gitpub_roles[jid]

        transaction.commit()
        db_con.close()

        return ret

    def set_site_role(self, jid, role):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['owner', 'user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_roles:
                del con_root.org_wayround_gitpub_roles[jid]

        else:

            con_root.org_wayround_gitpub_roles[jid] = role

        transaction.commit()
        db_con.close()

        return

    def del_site_role(self, jid):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_site_role(jid, 'guest')
        return

    def dict_home_roles(self, home):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = {}

        if home in con_root.org_wayround_gitpub_home_roles:
            ret = dict(con_root.org_wayround_gitpub_home_roles[home])

        transaction.commit()
        db_con.close()

        return ret

    def get_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if home == jid:
            ret = 'owner'
        else:

            if home in con_root.org_wayround_gitpub_home_roles:
                if jid in con_root.org_wayround_gitpub_home_roles[home]:
                    ret = con_root.org_wayround_gitpub_home_roles[home][jid]

        transaction.commit()
        db_con.close()

        return ret

    def set_home_role(self, home, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if not home in con_root.org_wayround_gitpub_home_roles:
            con_root.org_wayround_gitpub_home_roles[home] = \
                persistent.mapping.PersistentMapping()

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_home_roles[home]:
                del con_root.org_wayround_gitpub_home_roles[home][jid]

        else:

            con_root.org_wayround_gitpub_home_roles[home][jid] = role

        transaction.commit()
        db_con.close()

        return

    def del_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_home_role(home, jid, 'guest')
        return

    def dict_repo_roles(self, home, repo):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = {}

        if home in con_root.org_wayround_gitpub_repo_roles:
            if repo in con_root.org_wayround_gitpub_repo_roles[home]:
                ret = dict(con_root.org_wayround_gitpub_repo_roles[home][repo])

        transaction.commit()
        db_con.close()

        return ret

    def get_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        db_con = self.rtenv.db.open()
        con_root = db_con.root

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

        transaction.commit()
        db_con.close()

        return ret

    def set_repo_role(self, home, repo, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if not home in con_root.org_wayround_gitpub_repo_roles:
            con_root.org_wayround_gitpub_repo_roles[home] = \
                persistent.mapping.PersistentMapping()

        if not repo in con_root.org_wayround_gitpub_repo_roles[home]:
            con_root.org_wayround_gitpub_repo_roles[home][repo] = \
                persistent.mapping.PersistentMapping()

        if role == 'guest':

            if jid in con_root.org_wayround_gitpub_repo_roles[home][repo]:
                del con_root.org_wayround_gitpub_repo_roles[home][repo][jid]

        else:

            con_root.org_wayround_gitpub_repo_roles[home][repo][jid] = role

        transaction.commit()
        db_con.close()

        return

    def del_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_repo_role(home, repo, jid, 'guest')
        return

    def get_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = None

        if jid in con_root.org_wayround_gitpub_public_keys:
            res = con_root.org_wayround_gitpub_public_keys[jid]
            if is_correct_public_key_data(res['msg'], jid):
                ret = res

        transaction.commit()
        db_con.close()

        return ret

    def user_is_has_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        ret = (
            jid in con_root.org_wayround_gitpub_public_keys
            and
            is_correct_public_key_data(
                con_root.org_wayround_gitpub_public_keys[jid]['msg'],
                jid
                )
            )

        transaction.commit()
        db_con.close()

        return ret

    def set_public_key(self, jid, msg):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 0

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if not is_correct_public_key_data(msg, jid):
            ret = 1

        if ret == 0:

            splitted_msg = msg.split()

            if len(splitted_msg) != 3:
                ret = 2

        if ret == 0:

            msg_jid = splitted_msg[2]

            msg_jid = msg_jid.lower()

            msg_jid = org.wayround.xmpp.core.jid_to_bare(msg_jid)

            if msg_jid != jid:
                ret = 3

        if ret == 0:

            con_root.org_wayround_gitpub_public_keys[jid] = {
                'msg': msg,
                'msg_type_part': splitted_msg[0],
                'msg_base64_part': ''.join(splitted_msg[1].splitlines()),
                'msg_jid_part': msg_jid
                }

            ret = 0

        transaction.commit()
        db_con.close()

        return ret

    def del_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if jid in con_root.org_wayround_gitpub_public_keys:
            del con_root.org_wayround_gitpub_public_keys[jid]

        transaction.commit()
        db_con.close()

        return

    def get_jid_by_base64(self, type_, base64):

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        b64_1 = ''.join(base64.splitlines())

        ret = set()

        for k, v in con_root.org_wayround_gitpub_public_keys.items():
            if v['msg_type_part'] == type_:
                if b64_1 == ''.join(v['msg_base64_part'].splitlines()):
                    ret.add(org.wayround.xmpp.core.jid_to_bare(k))

        transaction.commit()
        db_con.close()

        return list(ret)

    def del_home_and_role(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        db_con = self.rtenv.db.open()
        con_root = db_con.root

        if jid in con_root.org_wayround_gitpub_home_settings:
            del con_root.org_wayround_gitpub_home_settings[jid]

        if jid in con_root.org_wayround_gitpub_repo_settings:
            del con_root.org_wayround_gitpub_repo_settings[jid]

        if jid in con_root.org_wayround_gitpub_home_roles:
            del con_root.org_wayround_gitpub_home_roles[jid]

        if jid in con_root.org_wayround_gitpub_repo_roles:
            del con_root.org_wayround_gitpub_repo_roles[jid]

        self.del_site_role(jid)

        transaction.commit()
        db_con.close()

        return


def is_correct_public_key_data(msg, jid):

    jid = org.wayround.xmpp.core.jid_to_bare(jid)

    pkey = msg

    error = False

    if pkey is not None:
        parsed_msg = pkey.split()

        if len(parsed_msg) != 3:
            error = True

    if not error:
        if parsed_msg[0] != 'ssh-rsa':
            error = True

    if not error:
        if len(parsed_msg[1]) < 10:
            error = True

    if not error:
        if not org.wayround.xmpp.core.jid_to_bare(parsed_msg[2]) == jid:
            error = True

    # TODO: add more checks

    return not error
