
import collections
import os.path


import org.wayround.xmpp.core

import sqlalchemy.orm.exc

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

        class Session(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Sessions'

            sid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            session_cookie = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            session_valid_till = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

        class SiteSetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_SiteSettings'

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            value = sqlalchemy.Column(
                sqlalchemy.PickleType,
                nullable=False
                )

        class HomeSetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_HomeSettings'

            hosid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            value = sqlalchemy.Column(
                sqlalchemy.PickleType,
                nullable=False
                )

        class RepositorySetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_RepositorySettings'

            resid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            repo = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            value = sqlalchemy.Column(
                sqlalchemy.PickleType,
                nullable=False
                )

        class SiteRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_SiteRoles'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='guest'
                )

        class HomeRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_HomeRoles'

            hrid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='guest'
                )

        class RepositoryRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_RepositoryRoles'

            rrid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            repo = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='guest'
                )

        class PublicKey(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_PublicKeys'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True,
                nullable=True,
                default=None
                )

            msg = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            msg_type_part = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            msg_base64_part = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            msg_jid_part = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

        self.rtenv.models[self.module_name] = {
            'Session': Session,
            'SiteSetting': SiteSetting,
            'HomeSetting': HomeSetting,
            'RepositorySetting': RepositorySetting,
            'SiteRole': SiteRole,
            'HomeRole': HomeRole,
            'RepositoryRole': RepositoryRole,
            'PublicKey': PublicKey
        }

    def get_site_setting(self, name):

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        res = None
        ret = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteSetting']
            ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:

            self.set_site_setting(
                name,
                self.ACCEPTABLE_SITE_SETTINGS[name],
                _assume_absent=True
                )

            ret = self.get_site_setting(name)

        else:
            ret = res

        return ret

    def set_site_setting(self, name, value, _assume_absent=False):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_SITE_SETTINGS:
            raise ValueError("invalid `name'")

        if value is not None:
            if isinstance(self.ACCEPTABLE_SITE_SETTINGS[name], bool):

                value = _value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_SITE_SETTINGS[name])):
            raise TypeError(
                "invalid site setting `{}' value type".format(name)
                )

        res = None
        if not _assume_absent:
            res = self.get_site_setting(name)

        if res is None:
            res = self.rtenv.models[self.module_name]['SiteSetting']()
            self.rtenv.db.sess.add(res)

        res.name = name
        res.value = value

        self.rtenv.db.sess.commit()

        return

    def get_home_setting(self, home, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        res = None
        ret = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['HomeSetting']
            ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:

            self.set_home_setting(
                home,
                name,
                self.ACCEPTABLE_HOME_SETTINGS[name],
                _assume_absent=True
                )

            ret = self.get_home_setting(home, name)

        else:
            ret = res

        return ret

    def set_home_setting(self, home, name, value, _assume_absent=False):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_HOME_SETTINGS:
            raise ValueError("invalid `name'")

        if value is not None:
            if isinstance(self.ACCEPTABLE_HOME_SETTINGS[name], bool):

                value = _value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_HOME_SETTINGS[name])):
            raise TypeError(
                "invalid home setting `{}' value type".format(name)
                )

        res = None
        if not _assume_absent:
            res = self.get_home_setting(name, name)

        if res is None:
            res = self.rtenv.models[self.module_name]['HomeSetting']()
            self.rtenv.db.sess.add(res)

        res.home = home
        res.name = name
        res.value = value

        self.rtenv.db.sess.commit()

        return

    def get_repo_setting(self, home, repo, name):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_REPO_SETTINGS:
            raise ValueError("invalid `name'")

        res = None
        ret = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['RepositorySetting']
            ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:

            self.set_repo_setting(
                home,
                repo,
                name,
                self.ACCEPTABLE_REPO_SETTINGS[name],
                _assume_absent=True
                )

            ret = self.get_repo_setting(home, repo, name)

        else:
            ret = res

        return ret

    def set_repo_setting(self, home, repo, name, value, _assume_absent=False):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        if name not in self.ACCEPTABLE_REPO_SETTINGS:
            raise ValueError("invalid `name'")

        if value is not None:
            if isinstance(self.ACCEPTABLE_REPO_SETTINGS[name], bool):

                value = _value_to_bool(value)

        if not isinstance(value, type(self.ACCEPTABLE_REPO_SETTINGS[name])):
            raise TypeError(
                "invalid repo setting `{}' value type".format(name)
                )

        res = None
        if not _assume_absent:
            res = self.get_repo_setting(name, repo, name)

        if res is None:
            res = self.rtenv.models[self.module_name]['RepositorySetting']()
            self.rtenv.db.sess.add(res)

        res.home = home
        res.repo = repo
        res.name = name
        res.value = value

        self.rtenv.db.sess.commit()

        return

    def dict_site_roles(self):

        ret = {}

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteRole']
            ).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            for i in res:
                ret[i.jid] = i.role

        return ret

    def get_site_role(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteRole']
            ).filter_by(jid=jid).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res.role

            if ret not in self.site_roles or ret is 'guest':
                self.rtenv.db.sess.delete(res)
                self.rtenv.db.sess.commit()

                ret = 'guest'

        return ret

    def set_site_role(self, jid, role):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['admin', 'user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        if role == 'guest':

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['SiteRole']
                ).filter_by(jid=jid).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                for i in res:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['SiteRole']
                ).filter_by(jid=jid).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass

            len_res = len(res)

            p = None

            if len_res == 0:

                p = self.rtenv.models[self.module_name]['SiteRole']()
                p.jid = jid
                p.enabled = True
                self.rtenv.db.sess.add(p)

            else:

                for i in res[1:]:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

                p = res[0]

            p.role = role

            self.rtenv.db.sess.commit()

        return

    def del_site_role(self, jid):
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_site_role(jid, 'guest')
        return

    def dict_home_roles(self, home):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        ret = {}

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['HomeRole']
            ).filter_by(home=home).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            for i in res:
                ret[i.jid] = i.role

        return ret

    def get_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        if home == jid:
            ret = 'owner'
        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['HomeRole']
                ).filter_by(home=home, jid=jid).one()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                ret = res.role

                if ret not in self.home_roles or ret is 'guest':
                    self.rtenv.db.sess.delete(res)
                    self.rtenv.db.sess.commit()

                    ret = 'guest'

        return ret

    def set_home_role(self, home, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        if role == 'guest':

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['HomeRole']
                ).filter_by(home=home, jid=jid).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                for i in res:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['HomeRole']
                ).filter_by(home=home, jid=jid).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass

            len_res = len(res)

            p = None

            if len_res == 0:

                p = self.rtenv.models[self.module_name]['HomeRole']()
                p.home = home
                p.jid = jid
                self.rtenv.db.sess.add(p)

            else:

                for i in res[1:]:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

                p = res[0]

            p.role = role

            self.rtenv.db.sess.commit()

        return

    def del_home_role(self, home, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_home_role(home, jid, 'guest')
        return

    def dict_repo_roles(self, home, repo):
        home = org.wayround.xmpp.core.jid_to_bare(home)

        ret = {}

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['RepositoryRole']
            ).filter_by(
                home=home,
                repo=repo
            ).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            for i in res:
                ret[i.jid] = i.role

        return ret

    def get_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 'guest'

        if home == jid:
            ret = 'owner'
        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['RepositoryRole']
                ).filter_by(
                    home=home,
                    repo=repo,
                    jid=jid
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                ret = res.role

                if ret not in self.repo_roles or ret is 'guest':
                    self.rtenv.db.sess.delete(res)
                    self.rtenv.db.sess.commit()

                    ret = 'guest'

            return ret

    def set_repo_role(self, home, repo, jid, role):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if not role in ['user', 'guest', 'blocked']:
            raise ValueError("invalid `role' value")

        if role == 'guest':

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['RepositoryRole']
                ).filter_by(
                    home=home,
                    repo=repo,
                    jid=jid
                ).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                for i in res:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['RepositoryRole']
                ).filter_by(
                    home=home,
                    repo=repo,
                    jid=jid
                ).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass

            len_res = len(res)

            p = None

            if len_res == 0:

                p = self.rtenv.models[self.module_name]['RepositoryRole']()
                p.home = home
                p.repo = repo
                p.jid = jid
                self.rtenv.db.sess.add(p)

            else:

                for i in res[1:]:
                    self.rtenv.db.sess.delete(i)
                self.rtenv.db.sess.commit()

                p = res[0]

            p.role = role

            self.rtenv.db.sess.commit()

        return

    def del_repo_role(self, home, repo, jid):
        home = org.wayround.xmpp.core.jid_to_bare(home)
        jid = org.wayround.xmpp.core.jid_to_bare(jid)
        self.set_repo_role(home, repo, jid, 'guest')
        return

    def get_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['PublicKey']
            ).filter_by(jid=jid).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res

        return ret

    def user_is_has_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = False

        pkey = self.get_public_key(jid)

        if pkey is not None:
            ret = True

        return ret

    def is_correct_public_key_data(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = False

        pkey = self.get_public_key(jid)

        if pkey is not None:
            parsed_msg = pkey.msg.split()

            error = False

            if parsed_msg[0] != pkey.msg_type_part:
                error = True

            if parsed_msg[1] != pkey.msg_base64_part:
                error = True

            if parsed_msg[2] != pkey.msg_jid_part:
                error = True

            # TODO: add more checks

            if not error:
                ret = True

        return ret

    def set_public_key(self, jid, msg):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        if self.user_is_has_public_key(jid):
            self.del_public_key(jid)

        ret = 0
        parsed_msg = msg.split()

        if len(parsed_msg) != 3:
            ret = 2
        else:
            pk = self.rtenv.models[self.module_name]['PublicKey']()
            pk.jid = jid
            pk.msg = msg
            pk.msg_type_part = parsed_msg[0]
            pk.msg_base64_part = parsed_msg[1]
            pk.msg_jid_part = parsed_msg[2].lower()

            self.rtenv.db.sess.add(pk)

            self.rtenv.db.sess.commit()

        if not self.is_correct_public_key_data(jid):
            ret = 1

        return ret

    def del_public_key(self, jid):

        jid = org.wayround.xmpp.core.jid_to_bare(jid)

        ret = 0

        pk = self.get_public_key(jid)

        if pk is None:
            ret = 1
        else:
            self.rtenv.db.sess.delete(pk)
            self.rtenv.db.sess.commit()

        return ret

    def get_jid_by_base64(self, type_, base64):

        res = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['PublicKey']
            ).filter_by(
                msg_type_part=type_,
                msg_base64_part=base64
                ).all()

        ret = set()

        for i in res:
            ret.add(org.wayround.xmpp.core.jid_to_bare(jidi.jid))

        return sorted(list(ret))

    def del_home_and_user(self, home):

        home = org.wayround.xmpp.core.jid_to_bare(home)

        self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['HomeSetting']
            ).filter_by(home=home).delete()

        self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['RepositorySetting']
            ).filter_by(home=home).delete()

        self.del_site_role(home)

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
