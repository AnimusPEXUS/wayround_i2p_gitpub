import os.path

import sqlalchemy.orm.exc

import org.wayround.softengine.rtenv


class GitPub(org.wayround.softengine.rtenv.ModulePrototype):

    def __init__(self, rtenv):

        self.module_name = 'org_wayround_gitpub_modules_GitPub'

        self.session_lifetime = 24 * 60 * 60

        self.site_roles = [
            'admin', 'user', 'guest'
            ]

        self.home_roles = [
            'admin', 'user', 'guest'
            ]

        self.repository_roles = [
            'admin', 'user', 'guest'
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
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

        class HomeSetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_HomeSettings'

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            enabled = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
                )

            guests_can_view = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
                )

        class RepositorySetting(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_RepositorySettings'

            reid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
                )

            home = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            repository = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            description = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            guests_can_view = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=False
                )

        class SiteRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_SiteRoles'

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True,
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='guest'
                )

            enabled = sqlalchemy.Column(
                sqlalchemy.Boolean,
                nullable=False,
                default=True
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
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='read'
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

            repository = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False
                )

            jid = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
                )

            role = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=True,
                default=None
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

    def get_site_setting(self, name, default=None):

        ret = default

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteSetting']
            ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res.value

        return ret

    def set_site_setting(self, name, value):

        res = self.get_site_setting(name, None)

        if res is None:
            res = self.rtenv.models[self.module_name]['SiteSetting']()
            res.name = name
            res.value = value

            self.rtenv.db.sess.add(res)
        else:
            res.value = value

        self.rtenv.db.sess.commit()

        return

    def list_homes(self):

        ret = set()

        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['HomeSetting']
            ).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        else:
            for i in p:
                ret.add(i.home)

        return sorted(list(ret))

    def get_home_setting(self, home):
        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['HomeSetting']
            ).filter_by(home=home).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return p

    def set_home_setting(self, data):

        p = self.get_home_setting(data.home)

        if p is None:
            self.rtenv.db.sess.add(data)

        self.rtenv.db.sess.commit()

        return

    def list_repositories(self, home):

        ret = set()

        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['RepositorySetting']
            ).filter_by(home=home).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        else:
            for i in p:
                ret.add(i.repository)

        return sorted(list(ret))

    def get_repository_setting(self, home, repository):
        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['RepositorySetting']
            ).filter_by(
                home=home,
                repository=repository
            ).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return p

    def set_repository_setting(self, data):

        p = self.get_repository_setting(data.home, data.repository)

        if p is None:
            self.rtenv.db.sess.add(data)

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

        if role in [None, 'guest']:

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
        self.set_site_role(jid, None)
        return

    def dict_home_roles(self, home):

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

        ret = 'guest'

        if home == jid:
            ret = 'admin'
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

        if role in [None, 'guest']:

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
        self.set_home_role(home, jid, None)
        return

    def dict_repository_roles(self, home, repository):

        ret = {}

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['RepositoryRole']
            ).filter_by(
                home=home,
                repository=repository
            ).all()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            for i in res:
                ret[i.jid] = i.role

        return ret

    def get_repository_role(self, home, repository, jid):

        ret = 'guest'

        if home == jid:
            ret = 'admin'
        else:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['RepositoryRole']
                ).filter_by(
                    home=home,
                    repository=repository,
                    jid=jid
                ).one()
            except sqlalchemy.orm.exc.NoResultFound:
                pass
            else:
                ret = res.role

                if ret not in self.repository_roles or ret is 'guest':
                    self.rtenv.db.sess.delete(res)
                    self.rtenv.db.sess.commit()

                    ret = 'guest'

            return ret

    def set_repository_role(self, home, repository, jid, role):

        if role in [None, 'guest']:

            try:
                res = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['RepositoryRole']
                ).filter_by(
                    home=home,
                    repository=repository,
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
                    repository=repository,
                    jid=jid
                ).all()
            except sqlalchemy.orm.exc.NoResultFound:
                pass

            len_res = len(res)

            p = None

            if len_res == 0:

                p = self.rtenv.models[self.module_name]['RepositoryRole']()
                p.home = home
                p.repository = repository
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

    def del_repository_role(self, repository, jid):
        self.set_repository_role(repository, jid, None)
        return

    def get_public_key(self, jid):
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

        ret = False

        pkey = self.get_public_key(jid)

        if pkey is not None:
            ret = True

        return ret

    def is_correct_public_key_data(self, jid):

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

        if self.is_has_public_key(jid):
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
            pk.msg_jid_part = parsed_msg[2]

            self.rtenv.db.sess.add(pk)

            self.rtenv.db.sess.commit()

        if not self.is_correct_public_key_data(jid):
            ret = 1

        return ret

    def del_public_key(self, jid):
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
            ret.add(i.jid)

        return sorted(list(ret))
