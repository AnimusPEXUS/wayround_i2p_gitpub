
import datetime
import hashlib
import os.path
import random

import bottle
from mako.template import Template
import sqlalchemy.orm.exc

import org.wayround.softengine.rtenv
import org.wayround.gitpub.env


class WrongPageAction(Exception):
    pass


class CreatingAlreadyExistingProject(Exception):
    pass


class EditingNotExistingProject(Exception):
    pass


class GitPub(org.wayround.softengine.rtenv.ModulePrototype):

    def __init__(self, rtenv):

        self.module_name = 'org_wayround_gitpub_modules_GitPub'

        self.session_lifetime = 24 * 60 * 60

        self.site_roles = [
            'admin', 'moder', 'user', 'guest'
            ]

        self.project_roles = [
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

        class Project(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_Projects'

            name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                primary_key=True
                )

            title = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Name not set'
                )

            creation_date = sqlalchemy.Column(
                sqlalchemy.DateTime,
                nullable=True,
                default=None
                )

            description = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default='Name not set'
                )

            guests_access_allowed = sqlalchemy.Column(
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
                default='user'
                )

        class ProjectRole(self.rtenv.db.db_base):

            __tablename__ = self.module_name + '_ProjectRoles'

            prid = sqlalchemy.Column(
                sqlalchemy.Integer,
                primary_key=True,
                autoincrement=True
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

            project_name = sqlalchemy.Column(
                sqlalchemy.UnicodeText,
                nullable=False,
                default=''
                )

        self.rtenv.models[self.module_name] = {
            'Project':       Project,
            'SiteRole':      SiteRole,
            'ProjectRole':   ProjectRole,
            'Session':       Session,
            'SiteSetting':   SiteSetting,
            }

        self.rtenv.templates[self.module_name] = {}

        for i in [
            'html',
            'admin',
            'project_page',
            'project_list',
            'project_roles',
            'edit_project',
            'actions',
            'session',
            'site_settings',
            'site_roles'
            ]:
            self.rtenv.templates[self.module_name][i] = Template(
                filename=os.path.join(self.template_dir, '{}.html'.format(i)),
                format_exceptions=False
                )

    def html_tpl(self, title, actions, body, session=''):
        return self.rtenv.templates[self.module_name]['html'].render(
            title=title, session=session, actions=actions, body=body,
            js=[], css=['default.css']
            )

    def site_roles_tpl(
        self,
        admins,
        moders,
        users,
        blocked
        ):
        return self.rtenv.templates[self.module_name]['site_roles'].render(
            admins=admins,
            moders=moders,
            users=users,
            blocked=blocked
            )

    def project_roles_tpl(
        self,
        admins,
        moders,
        users,
        blocked,
        site_admins,
        site_moders,
        site_users,
        site_blocked,
        god
        ):
        return self.rtenv.templates[self.module_name]['project_roles'].render(
            admins=admins,
            moders=moders,
            users=users,
            blocked=blocked,
            site_admins=site_admins,
            site_moders=site_moders,
            site_users=site_users,
            site_blocked=site_blocked,
            god=god
            )

    def site_settings_tpl(
        self,
        site_title,
        site_description,
        user_can_register_self,
        user_can_create_projects
        ):
        return self.rtenv.templates[self.module_name]['site_settings'].render(
            site_title=site_title,
            site_description=site_description,
            user_can_register_self=user_can_register_self,
            user_can_create_projects=user_can_create_projects
            )

    def register_tpl(self):
        return self.rtenv.templates[self.module_name]['register'].render()

    def login_tpl(self):
        return self.rtenv.templates[self.module_name]['login'].render()

    def project_page_tpl(
        self,
        project_name,
        open_issue_table='',
        closed_issue_table='',
        deleted_issue_table=''
        ):
        return self.rtenv.templates[self.module_name]['project_page'].render(
            project_name=project_name,
            open_issue_table=open_issue_table,
            closed_issue_table=closed_issue_table,
            deleted_issue_table=deleted_issue_table
            )

    def project_list_tpl(self, projects, rts_object):
        return self.rtenv.templates[self.module_name]['project_list'].render(
            projects=projects,
            rts_object=rts_object
            )

    def actions_tpl(self, actions, session_actions):

        for i in actions:
            if not isinstance(i, org.wayround.gitpub.env.PageAction):
                raise WrongPageAction("Wrong page action type")

        return self.rtenv.templates[self.module_name]['actions'].render(
            actions=actions,
            session_actions=session_actions
            )

    def session_tpl(
        self,
        rts_object=None
        ):

        if not  isinstance(rts_object, org.wayround.gitpub.env.Session):
            raise ValueError(
                "rts_object must be of type org.wayround.gitpub.env.Session"
                )

        return self.rtenv.templates[self.module_name]['session'].render(
            rts_object=rts_object
            )

    def edit_project_tpl(
        self,
        mode,
        name='',
        title='',
        description='',
        guests_access_allowed=False
        ):

        if not mode in ['new', 'edit']:
            raise ValueError("Wrong mode value: `{}'".format(mode))

        return self.rtenv.templates[self.module_name]['edit_project'].render(
            mode=mode,
            name=name,
            title=title,
            description=description,
            guests_access_allowed=guests_access_allowed
            )

    def css(self, filename):
        return bottle.static_file(filename, root=self.css_dir)

    def js(self, filename):
        return bottle.static_file(filename, root=self.js_dir)

    def get_random_bytes(self):

        ret = []
        pool = range(256)

        random.seed()

        i = 0
        while i != 512:
            ret.append(random.choice(pool))
            i += 1

        return bytes(ret)

    def hash_for_get_random_bytes(self, buffer):
        h = hashlib.sha512()
        h.update(buffer)
        ret = h.hexdigest()
        return ret

    def get_random_hash(self):
        return self.hash_for_get_random_bytes(self.get_random_bytes())

    def _get_session_by_x(self, data, what):

        if not what in ['jid', 'cookie']:
            raise ValueError("Wrong `what' parameter")

        self.cleanup_sessions()

        ret = None

        try:
            if what == 'cookie':
                ret = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(session_cookie=data).one()

            if what == 'jid':
                ret = self.rtenv.db.sess.query(
                    self.rtenv.models[self.module_name]['Session']
                    ).filter_by(jid=data).one()

        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:

            if ret.session_cookie == None or ret.session_valid_till == None:
                ret = None

        return ret

    def get_session_by_cookie(self, cookie):
        return self._get_session_by_x(cookie, 'cookie')

    def get_session_by_jid(self, jid):
        return self._get_session_by_x(jid, 'jid')

    def new_session(self):

        new_hash = self.get_random_hash()

        while self.get_session_by_cookie(new_hash) != None:
            new_hash = self.get_random_hash()

        s = self.rtenv.models[self.module_name]['Session']()
        s.session_cookie = new_hash

        self.rtenv.db.sess.add(s)
        self.rtenv.db.sess.commit()
        self.renew_session(s)

        return s

    def renew_session(self, session):
        """
        Keeps alive already existing session
        """

        if not isinstance(
            session, self.rtenv.models[self.module_name]['Session']
            ):
            raise TypeError(
                "`session' parameter must be of type `{}', but it is `{}'".\
                    format(
                        type(
                            self.rtenv.models[self.module_name]['Session']
                            ),
                        session
                        )
                )

        session.session_valid_till = (
            datetime.datetime.now() +
            datetime.timedelta(seconds=self.session_lifetime)
            )

        self.rtenv.db.sess.commit()

        return

    def assign_jid_to_session(self, session, jid):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        for i in sessions:
            if i.jid == jid:
                self.rtenv.db.sess.delete(i)

        session.jid = jid

        self.rtenv.db.sess.commit()

        return

    def cleanup_sessions(self):

        sessions = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Session']
            ).all()

        for i in sessions[:]:
            if i.session_cookie == None or i.session_valid_till == None:
                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        for i in sessions[:]:
            if i.session_valid_till < datetime.datetime.now():
                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        for i in sessions[:]:
            if i.session_valid_till > (
                datetime.datetime.now() +
                datetime.timedelta(
                    seconds=self.session_lifetime
                    )
                ):

                self.rtenv.db.sess.delete(i)
                sessions.remove(i)

        self.rtenv.db.sess.commit()

        return

    def get_projects(self):
        return self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['Project']
            ).all()

    def get_project(self, name):
        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return p

    def new_project(self, name, title, description, guests_access_allowed):

        p = None
        try:
            p = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['Project']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            p = self.rtenv.models[self.module_name]['Project']()
            p.name = name
            p.title = title
            p.description = description
            p.guests_access_allowed = guests_access_allowed
            self.rtenv.db.sess.add(p)

        else:
            raise CreatingAlreadyExistingProject(
                "Trying to create already existing project"
                )

        self.rtenv.db.sess.commit()

        return p

    def edit_project(self, name, title, description, guests_access_allowed):

        p = None
        try:
            p = self.get_project(name)

        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if not p:
            raise EditingNotExistingProject(
                "Trying to edit non-existing project"
                )

        else:
            p.title = title
            p.description = description
            p.guests_access_allowed = guests_access_allowed

        self.rtenv.db.sess.commit()

        return p

    def get_site_role(self, jid):

        ret = None

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteRole']
                ).filter_by(jid=jid).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass
        else:
            ret = res

            if not ret.role in self.site_roles:

                self.rtenv.db.sess.delete(ret)

                ret = None

                self.rtenv.db.sess.commit()

        return ret

    def get_site_roles(self):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['SiteRole']
            ).all()

        for i in ret[:]:
            if not i.role in self.site_roles:

                self.rtenv.db.sess.delete(i)

                while i in ret:
                    ret.remove(i)

        self.rtenv.db.sess.commit()

        return ret

    def get_site_roles_dict(self):

        ret = {}

        res = self.get_site_roles()

        for i in res:
            ret[i.jid] = i.role

        return ret

    def set_site_roles(self, roles):

        old_roles = self.get_site_roles()

        for i in old_roles:
            if not i.jid in roles.keys():
                self.rtenv.db.sess.delete(i)

        for i in roles.keys():

            role_found = False

            for j in old_roles:

                if j.jid == i:
                    role_found = j
                    break

            if role_found == False:

                role = self.rtenv.models[self.module_name]['SiteRole']()

                role.jid = i
                role.role = roles[i]

                self.rtenv.db.sess.add(role)

            else:

                role = role_found

                role.role = roles[i]

        self.rtenv.db.sess.commit()

        return

    def add_site_role(self, jid, role='user'):

        siterole = self.rtenv.models[self.module_name]['SiteRole']()

        siterole.jid = jid
        siterole.role = role

        self.rtenv.db.sess.add(siterole)

        self.rtenv.db.sess.commit()

        return

    def get_project_role(self, jid, project_name):

        ret = None

        try:
            ret = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['ProjectRole']
                ).filter_by(jid=jid, project_name=project_name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        return ret

    def get_project_roles_of_jid(self, jid):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['ProjectRole']
            ).filter_by(jid=jid).all()

        return ret

    def get_project_roles_of_jid_dict(self, jid):

        roles = self.get_project_roles_of_jid(jid)

        ret = {}

        for i in roles:
            ret[i.project_name] = i.role

        return ret

    def get_project_roles(self, project_name):

        ret = self.rtenv.db.sess.query(
            self.rtenv.models[self.module_name]['ProjectRole']
            ).filter_by(project_name=project_name).all()

        for i in ret[:]:
            if not i.role in self.project_roles:

                self.rtenv.db.sess.delete(i)

                while i in ret:
                    ret.remove(i)

        self.rtenv.db.sess.commit()

        return ret

    def get_project_roles_dict(self, project_name):

        roles = self.get_project_roles(project_name)

        ret = {}

        for i in roles:
            ret[i.jid] = i.role

        return ret

    def set_project_roles(self, project_name, roles):

        old_roles = self.get_project_roles(project_name)

        for i in old_roles:
            if not i.jid in roles.keys():
                self.rtenv.db.sess.delete(i)

        for i in roles.keys():

            role_found = False

            for j in old_roles:

                if j.jid == i:
                    role_found = j
                    break

            if role_found == False:

                role = self.rtenv.models[self.module_name]['ProjectRole']()

                role.jid = i
                role.role = roles[i]
                role.project_name = project_name

                self.rtenv.db.sess.add(role)

            else:

                role = role_found

                role.role = roles[i]

        self.rtenv.db.sess.commit()

        return

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

        res = None

        try:
            res = self.rtenv.db.sess.query(
                self.rtenv.models[self.module_name]['SiteSetting']
                ).filter_by(name=name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            pass

        if res == None:
            res = self.rtenv.models[self.module_name]['SiteSetting']()
            res.name = name
            res.value = value

            self.rtenv.db.sess.add(res)
        else:
            res.value = value

        self.rtenv.db.sess.commit()

        return
