
import os.path
import urllib.parse

import bottle

# bottle.Request.MEMFILE_MAX = 10 * 1024 * 1024
# bottle.Request.MAX_PARAMS = 100
# bottle.request.MEMFILE_MAX = 10 * 1024 * 1024
# bottle.request.MAX_PARAMS = 100

import org.wayround.utils.bottle
import org.wayround.utils.file


class Session:

    def __init__(self):

        self.id = None
        self.jid = None
        self.site_role = None
        self.repository_roles = {}
        self.session_valid_till = None


class PageAction:

    def __init__(self, title, href):

        self.title = title
        self.href = href


class Environment:

    def __init__(
            self,
            rtenv,
            host='localhost',
            port=8080,
            admin_jid='example@ex.nonexisting'
            ):

        self.ttm = 'org_wayround_gitpub_modules_GitPub'

        self.session_cookie_name = 'org_wayround_gitpub_session_cookie'

        self._bot = None

        self.admin_jid = admin_jid

        self.rtenv = rtenv

        self.host = host
        self.port = port

        self.app = bottle.Bottle()

        self.app.route('/', 'GET', self.index)

        # self.app.route(
        #    '/css/<filename>', 'GET', self.rtenv.modules[self.ttm].css
        #    )

#         self.app.route('/settings', 'GET', self.site_settings)
#         self.app.route('/settings', 'POST', self.site_settings_post)
# 
#         self.app.route('/roles', 'GET', self.site_roles)
#         self.app.route('/roles', 'POST', self.site_roles_post)
# 
#         self.app.route('/logout', 'GET', self.logout)
# 
#         self.app.route('/new_repository', 'GET', self.new_repository)
#         self.app.route('/new_repository', 'POST', self.new_repository_post)
# 
#         self.app.route(
#             '/repository/<repository_name>',
#             'GET',
#             self.repository_view
#             )
#         self.app.route(
#             '/repository/<repository_name>/',
#             'GET',
#             self.redirect_to_repository_view
#             )
# 
#         self.app.route(
#             '/repository/<repository_name>/issues',
#             'GET',
#             self.repository_issues
#             )
# 
#         self.app.route(
#             '/repository/<repository_name>/activities',
#             'GET',
#             self.repository_activities
#             )
# 
#         self.app.route(
#             '/repository/<repository_name>/settings',
#             'GET',
#             self.edit_repository
#             )
#         self.app.route(
#             '/repository/<repository_name>/settings',
#             'POST',
#             self.edit_repository_post
#             )
# 
#         self.app.route(
#             '/repository/<repository_name>/roles',
#             'GET',
#             self.repository_roles
#             )
#         self.app.route(
#             '/repository/<repository_name>/roles',
#             'POST',
#             self.repository_roles_post
#             )

        return

    def set_bot(self, bot):
        self._bot = bot

    def set_ssh_git_host(self, ssh_git_host):
        self._ssh_git_host = ssh_git_host
        self._ssh_git_host.set_callbacks(
            {'check_key': self.check_key}
            )

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

            res = self.rtenv.modules[self.ttm].username_get_by_base64(
                type_,
                b64
                )

            ret = username in res

        if error:
            ret = False

        return ret

    def start(self):
        self.server = org.wayround.utils.bottle.WSGIRefServer(
            host=self.host, port=self.port
            )

        return bottle.run(
            self.app,
            host=self.host,
            port=self.port,
            server=self.server
            )

    def stop(self):
        self.server.srv.shutdown()
#        print("bottle.default_app = {}".format(bottle.default_app))
#        bottle.default_app[0].close()
#        self.app.close()

    def get_page_actions(
            self,
            mode=None,
            rts_object=None,
            repository_name=None,
            issue_id=None
            ):

        if not isinstance(rts_object, Session):
            raise TypeError("rts_object must be a Session object")

        lst = []

        lst.append(PageAction('Project List', '/'))

        if mode == 'index' and rts_object.site_role == 'admin':
            lst.append(PageAction('New Project', '/new_repository'))

        if repository_name:

            lst.append(
                PageAction(
                    'Project',
                    '/repository/{}'.format(
                        urllib.parse.quote(repository_name)
                        )
                    )
                )

        if repository_name:
            if (rts_object.site_role == 'admin' or
                (repository_name in rts_object.repository_roles and
                 rts_object.repository_roles[repository_name] == 'admin')):

                lst.append(
                    PageAction(
                        'Project Settings',
                        '/repository/{}/settings'.format(
                            urllib.request.quote(repository_name)
                            )
                        )
                    )
                lst.append(
                    PageAction(
                        'Project Roles',
                        '/repository/{}/roles'.format(
                            urllib.request.quote(repository_name)
                            )
                        )
                    )

        if rts_object.site_role == 'admin':
            lst.append(PageAction('Site Settings', '/settings'))
            lst.append(PageAction('Site Roles', '/roles'))

        ret = self.rtenv.modules[self.ttm].actions_tpl(
            lst,
            session_actions=self.rtenv.modules[self.ttm].session_tpl(
                rts_object=rts_object
                )
            )

        return ret

    def generate_rts_object(self):
        """
        rts - run time session
        """

        s = None

        if self.session_cookie_name not in bottle.request.cookies:
            s = self.rtenv.modules[self.ttm].new_session()
            bottle.response.set_cookie(
                self.session_cookie_name,
                s.session_cookie
                )
        else:

            s = self.rtenv.modules[self.ttm].get_session_by_cookie(
                bottle.request.cookies.get(self.session_cookie_name, None)
                )

            if s:
                self.rtenv.modules[self.ttm].renew_session(s)
            else:

                s = self.rtenv.modules[self.ttm].new_session()

                bottle.response.set_cookie(
                    self.session_cookie_name,
                    s.session_cookie
                    )

        ret = Session()
        ret.id = s.session_cookie
        ret.jid = s.jid
        ret.session_valid_till = s.session_valid_till

        roles = self.get_site_roles_for_jid(s.jid)

        ret.site_role = roles['site_role']

        return ret

    def get_site_roles_for_jid(self, jid=None, all_site_repositories=False):

        ret = {}

        ret['site_role'] = 'guest'

        if jid == self.admin_jid:
            ret['site_role'] = 'admin'
        else:
            site_role = self.rtenv.modules[self.ttm].get_site_role(jid)

            if site_role is None:
                ret['site_role'] = 'guest'
            else:
                if site_role.role not in ['admin', 'user', 'blocked']:
                    ret['site_role'] = 'guest'
                else:
                    ret['site_role'] = site_role.role

        return ret

    def index(self):

        rts = self.generate_rts_object()

        repositories = self.rtenv.modules[self.ttm].get_repositories()

        repository_list = self.rtenv.modules[self.ttm].repository_list_tpl(
            repositories,
            rts_object=rts
            )

        actions = self.get_page_actions(
            mode='index',
            rts_object=rts
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title=self.rtenv.modules[self.ttm].get_site_setting(
                'site_title',
                'Not titled'
                ),
            actions=actions,
            body=repository_list
            )

        return ret

    def get_role(
            self, subject_jid, home_level=None, repo_level=None
            ):

        ret = None

        if self.admin_jid == subject_jid:
            ret = 'admin'

        if ret is None:

            subject_jid_site_role = \
                self.rtenv.modules[self.ttm].get_site_role(subject_jid)

            if subject_jid_site_role == 'admin':
                ret = 'admin'

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

                    if subject_jid_home_role == 'admin':

                        ret = 'admin'

                    else:

                        ret = self.rtenv.modules[self.ttm].get_repository_role(
                            subject_jid, repo_level
                            )

                else:
                    ret = 'guest'

        return ret

    def get_access_mode(
            self, subject_jid, home_level=None, repo_level=None
            ):

        # TODO: is this method used?

        ret = 'none'

        subject_jid_site_role = self.get_role(subject_jid)

        if subject_jid_site_role == 'admin':
            ret = 'full'

        else:

            if home_level == repo_level is None:
                if subject_jid_site_role == 'guest':

                    if self.rtenv.modules[self.ttm].get_site_setting(
                            'guest_can_read_index',
                            False
                            ):

                        ret = 'read'

                if subject_jid_site_role == 'user':

                    ret = 'read'

            elif home_level is not None and repo_level is None:

                if home_level == subject_jid:
                    ret = 'full'
                else:
                    if self.get_access_mode(
                            subject_jid
                            ) != 'none':

                        hs = self.rtenv.modules[self.ttm].get_home_setting(
                            home_level
                            )

                        if hs is not None and hs.guests_can_view:
                            ret = 'read'
                        else:
                            ret = 'none'

            elif home_level is not None and repo_level is not None:
                if home_level == subject_jid:
                    ret = 'full'
                else:
                    if self.get_access_mode(
                            subject_jid,
                            home_level
                            ) != 'none':

                        hs = self.rtenv.modules[self.ttm].\
                            get_repository_setting(
                                home_level
                                )

                        if hs is not None and hs.guests_can_view:
                            ret = 'read'
                        else:
                            ret = 'none'

            else:
                ret = 'none'

        return ret

    def check_permission(
            self,
            subject_jid,
            what,
            home_level=None,
            repo_level=None
            ):

        ret = False

        subject_jid_site_role = self.get_role(subject_jid)

        if subject_jid_site_role == 'admin' or self.admin_jid == subject_jid:
            ret = True

        else:

            if what == 'can_read':

                if home_level is None and repo_level is None:

                    if subject_jid_site_role == 'guest':

                        if self.rtenv.modules[self.ttm].get_site_setting(
                                'guest_can_list_homes',
                                False
                                ):
                            ret = True
                    else:

                        ret = True

                elif home_level is not None and repo_level is None:

                    subject_jid_home_role = \
                        self.get_role(subject_jid, home_level)

                    if subject_jid_home_role == 'admin':
                        ret = True
                    else:

                        if subject_jid_home_role == 'guest':

                            home_setting = \
                                self.rtenv.modules[self.ttm].get_home_setting(
                                    subject_jid
                                    )

                            if (home_setting is not None
                                    and home_setting.guests_can_view):
                                ret = True

                        else:
                            ret = True

                elif home_level is not None and repo_level is not None:

                    subject_jid_repository_role = \
                        self.get_role(subject_jid, home_level, repo_level)

                    if subject_jid_repository_role == 'admin':
                        ret = True
                    else:

                        if subject_jid_repository_role == 'guest':

                            repository_setting = self.rtenv.modules[self.ttm].\
                                get_repository_setting(
                                    subject_jid
                                    )

                            if (repository_setting is not None
                                    and repository_setting.guests_can_view):
                                ret = True

                        else:
                            ret = True

                else:
                    raise Exception("invalid param combination")

            elif what == 'can_write':

                # manage: create, destroy

                if home_level is None and repo_level is None:

                    if self.get_role(subject_jid) == 'admin':
                        ret = True

                elif home_level is not None and repo_level is None:

                    if self.get_role(subject_jid, home_level) == 'admin':
                        ret = True

                elif home_level is not None and repo_level is not None:

                    subject_jid_repository_role = \
                        self.get_role(subject_jid, home_level, repo_level)

                    if subject_jid_repository_role in ['admin', 'user']:
                        ret = True

                else:
                    raise Exception("invalid param combination")

            else:
                raise Exception("invalid `what' value")

        return ret


def install_launcher(path):

    if not os.path.exists(path):
        os.makedirs(path)

    src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'site'))
    dst_dir = path

    org.wayround.utils.file.copytree(
        src_dir,
        dst_dir,
        overwrite_files=True,
        clear_before_copy=False,
        dst_must_be_empty=False
        )
