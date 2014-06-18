
import os.path
import urllib.parse

import bottle

#bottle.Request.MEMFILE_MAX = 10 * 1024 * 1024
#bottle.Request.MAX_PARAMS = 100
#bottle.request.MEMFILE_MAX = 10 * 1024 * 1024
#bottle.request.MAX_PARAMS = 100

import org.wayround.utils.bottle
import org.wayround.utils.file
import org.wayround.utils.http
from org.wayround.utils.list import (
    list_strip_remove_empty_remove_duplicated_lines
    )

import org.wayround.softengine.rtenv


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

        self.app.route(
            '/js/<filename>', 'GET', self.rtenv.modules[self.ttm].js
            )
        self.app.route(
            '/css/<filename>', 'GET', self.rtenv.modules[self.ttm].css
            )

        self.app.route('/settings', 'GET', self.site_settings)
        self.app.route('/settings', 'POST', self.site_settings_post)

        self.app.route('/roles', 'GET', self.site_roles)
        self.app.route('/roles', 'POST', self.site_roles_post)

        self.app.route('/logout', 'GET', self.logout)

        self.app.route('/new_repository', 'GET', self.new_repository)
        self.app.route('/new_repository', 'POST', self.new_repository_post)

        self.app.route(
            '/repository/<repository_name>',
            'GET',
            self.repository_view
            )
        self.app.route(
            '/repository/<repository_name>/',
            'GET',
            self.redirect_to_repository_view
            )

        self.app.route(
            '/repository/<repository_name>/issues',
            'GET',
            self.repository_issues
            )

        self.app.route(
            '/repository/<repository_name>/activities',
            'GET',
            self.repository_activities
            )

        self.app.route(
            '/repository/<repository_name>/settings',
            'GET',
            self.edit_repository
            )
        self.app.route(
            '/repository/<repository_name>/settings',
            'POST',
            self.edit_repository_post
            )

        self.app.route(
            '/repository/<repository_name>/roles',
            'GET',
            self.repository_roles
            )
        self.app.route(
            '/repository/<repository_name>/roles',
            'POST',
            self.repository_roles_post
            )

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

        if not self.session_cookie_name in bottle.request.cookies:
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

            if site_role == None:
                ret['site_role'] = 'guest'
            else:
                if not site_role.role in ['admin', 'user', 'blocked']:
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

    def site_settings_access_check(self, rts):

        if rts.site_role != 'admin':
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def site_settings(self):

        rts = self.generate_rts_object()

        self.site_settings_access_check(rts)

        actions = self.get_page_actions(
            mode='settings',
            rts_object=rts
            )

        site_title = self.rtenv.modules[self.ttm].get_site_setting(
            'site_title',
            'Not titled'
            )

        site_description = self.rtenv.modules[self.ttm].get_site_setting(
            'site_description',
            'None'
            )

        user_can_register_self = self.rtenv.modules[self.ttm].get_site_setting(
            'user_can_register_self',
            False
            ) == '1'

        user_can_create_repositories = \
            self.rtenv.modules[self.ttm].get_site_setting(
                'user_can_create_repositories',
                False
                ) == '1'

        settings_page = self.rtenv.modules[self.ttm].site_settings_tpl(
            site_title,
            site_description,
            user_can_register_self,
            user_can_create_repositories
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change site settings",
            actions=actions,
            body=settings_page
            )

        return ret

    def site_settings_post(self):

        rts = self.generate_rts_object()

        self.site_settings_access_check(rts)

        for i in [
            'site_title',
            'site_description',
            ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        org.wayround.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
            'user_can_register_self',
            'user_can_create_repositories'
            ]
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'site_title',
            decoded_params['site_title']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'site_description',
            decoded_params['site_description']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'user_can_register_self',
            decoded_params['user_can_register_self']
            )

        self.rtenv.modules[self.ttm].set_site_setting(
            'user_can_create_repositories',
            decoded_params['user_can_create_repositories']
            )

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        return

    site_roles_access_check = site_settings_access_check

    def site_roles(self):

        rts = self.generate_rts_object()

        self.site_roles_access_check(rts)

        actions = self.get_page_actions(
            mode='settings',
            rts_object=rts
            )

        roles = self.rtenv.modules[self.ttm].get_site_roles_dict()

        admins = []
        moders = []
        users = []
        blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                admins.append(i)

            if roles[i] == 'moder':
                moders.append(i)

            if roles[i] == 'user':
                users.append(i)

            if roles[i] == 'blocked':
                blocked.append(i)

        admins.sort()
        moders.sort()
        users.sort()
        blocked.sort()

        roles_page = self.rtenv.modules[self.ttm].site_roles_tpl(
            admins='\n'.join(admins),
            moders='\n'.join(moders),
            users='\n'.join(users),
            blocked='\n'.join(blocked)
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change site roles",
            actions=actions,
            body=roles_page
            )

        return ret

    def site_roles_post(self):

        rts = self.generate_rts_object()

        self.site_roles_access_check(rts)

        for i in [
            'admins',
            'moders',
            'users',
            'blocked'
            ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        admins = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['admins'].splitlines()
            )

        moders = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['moders'].splitlines()
            )

        users = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['users'].splitlines()
            )

        blocked = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['blocked'].splitlines()
            )

        roles = {}

        for i in admins:
            roles[i] = 'admin'

        del admins

        for i in moders:
            roles[i] = 'moder'

        del moders

        for i in users:
            roles[i] = 'user'

        del users

        for i in blocked:
            roles[i] = 'blocked'

        del blocked

        roles = self.rtenv.modules[self.ttm].set_site_roles(roles)

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        return

    def new_repository_access_check(self, rts):

        if (rts.site_role != 'admin' and
            self.rtenv.modules[self.ttm].get_site_setting(
                'user_can_create_repositories',
                False
                ) != '1'
            ):
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def new_repository(self):

        rts = self.generate_rts_object()

        self.new_repository_access_check(rts)

        actions = self.get_page_actions(
            mode='edit_repository',
            rts_object=rts
            )

        edit_repository_tpl = self.rtenv.modules[self.ttm].edit_repository_tpl(
            mode='new'
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Create new repository",
            actions=actions,
            body=edit_repository_tpl
            )

        return ret

    def new_repository_post(self):

        rts = self.generate_rts_object()

        self.new_repository_access_check(rts)

        for i in ['name', 'title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        org.wayround.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
            'guests_access_allowed'
            ]
            )

        name = decoded_params['name']

        self.rtenv.modules[self.ttm].new_repository(
            name,
            decoded_params['title'],
            decoded_params['description'],
            decoded_params['guests_access_allowed']
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Project creation result",
            actions='',
            body=''
            )

        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/repository/{}'.format(urllib.parse.quote(name))
            )

        return ret

    def edit_repository_access_check(self, rts, repository_record):

        allowed = False

        if rts.site_role == 'admin':
            allowed = True

        if repository_record.name in rts.repository_roles \
            and rts.repository_roles[repository_record.name] == 'admin':
            allowed = True

        if not allowed:
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def edit_repository(self, repository_name):

        rts = self.generate_rts_object()

        ret = ''

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        self.edit_repository_access_check(rts, p)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='edit_repository',
                rts_object=rts,
                repository_name=repository_name
                )

            edit_repository_tpl = self.rtenv.modules[self.ttm].edit_repository_tpl(
                mode='edit',
                name=repository_name,
                title=p.title,
                description=p.description,
                guests_access_allowed=p.guests_access_allowed
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="Edit repository",
                actions=actions,
                body=edit_repository_tpl
                )

        return ret

    def edit_repository_post(self, repository_name):

        rts = self.generate_rts_object()

        for i in ['title', 'description']:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        org.wayround.utils.http.convert_cb_params_to_boolean(
            decoded_params,
            [
            'guests_access_allowed'
            ]
            )

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        self.edit_repository_access_check(rts, p)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        p = self.rtenv.modules[self.ttm].edit_repository(
            repository_name,
            decoded_params['title'],
            decoded_params['description'],
            decoded_params['guests_access_allowed']
            )

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/repository/{}'.format(
                urllib.parse.quote(repository_name)
                )
            )

        return

    repository_roles_access_check = edit_repository_access_check

    def repository_roles(self, repository_name):

        rts = self.generate_rts_object()

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        self.repository_roles_access_check(rts, p)

        del p

        actions = self.get_page_actions(
            mode='repository_roles',
            rts_object=rts,
            repository_name=repository_name
            )

        roles = self.rtenv.modules[self.ttm].get_site_roles_dict()

        site_admins = []
        site_moders = []
        site_users = []
        site_blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                site_admins.append(i)

            if roles[i] == 'moder':
                site_moders.append(i)

            if roles[i] == 'user':
                site_users.append(i)

            if roles[i] == 'blocked':
                site_blocked.append(i)

        site_admins.sort()
        site_moders.sort()
        site_users.sort()
        site_blocked.sort()

        roles = self.rtenv.modules[self.ttm].get_repository_roles_dict(
            repository_name
            )

        admins = []
        moders = []
        users = []
        blocked = []

        for i in roles.keys():

            if roles[i] == 'admin':
                admins.append(i)

            if roles[i] == 'moder':
                moders.append(i)

            if roles[i] == 'user':
                users.append(i)

            if roles[i] == 'blocked':
                blocked.append(i)

        admins.sort()
        moders.sort()
        users.sort()
        blocked.sort()

        roles_page = self.rtenv.modules[self.ttm].repository_roles_tpl(
            admins='\n'.join(admins),
            moders='\n'.join(moders),
            users='\n'.join(users),
            blocked='\n'.join(blocked),
            site_admins='\n'.join(site_admins),
            site_moders='\n'.join(site_moders),
            site_users='\n'.join(site_users),
            site_blocked='\n'.join(site_blocked),
            god=self.admin_jid
            )

        ret = self.rtenv.modules[self.ttm].html_tpl(
            title="Change repository roles",
            actions=actions,
            body=roles_page
            )

        return ret

    def repository_roles_post(self, repository_name):

        rts = self.generate_rts_object()

        self.repository_roles_access_check(rts)

        for i in [
            'admins',
            'moders',
            'users',
            'blocked'
            ]:
            if not i in bottle.request.params:
                raise KeyError("parameter `{}' must be passed".format(i))

        decoded_params = bottle.request.params.decode('utf-8')

        admins = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['admins'].splitlines()
            )

        moders = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['moders'].splitlines()
            )

        users = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['users'].splitlines()
            )

        blocked = list_strip_remove_empty_remove_duplicated_lines(
            decoded_params['blocked'].splitlines()
            )

        roles = {}

        for i in admins:
            roles[i] = 'admin'

        del admins

        for i in moders:
            roles[i] = 'moder'

        del moders

        for i in users:
            roles[i] = 'user'

        del users

        for i in blocked:
            roles[i] = 'blocked'

        del blocked

        roles = self.rtenv.modules[self.ttm].set_site_roles(roles)

        bottle.response.status = 303
        bottle.response.set_header('Location', '')

        return

    def login_access_check(self, jid):

        ret = True

        role = self.rtenv.modules[self.ttm].get_site_role(jid)

        if not role or role.role == 'blocked':
            ret = False

        return ret

    def register_access_check(self, jid):

        ret = True

        role = self.rtenv.modules[self.ttm].get_site_role(jid)

        if role or not self.rtenv.modules[self.ttm].get_site_setting(
            'user_can_register_self',
            False
            ):

            ret = False

        return ret

    def logout(self):
        bottle.response.delete_cookie(self.session_cookie_name)
        bottle.response.status = 303
        bottle.response.set_header('Location', '/')
#        bottle.response.set_header('Cache-Control', 'no-cache')
#        bottle.redirect('/', code=200)

    def redirect_to_repository_view(self, repository_name):
        bottle.response.status = 303
        bottle.response.set_header(
            'Location', '/repository/{}'.format(urllib.parse.quote(repository_name))
            )

    def repository_view_access_check(self, rts, repository_record):

        allowed = False

        if rts.site_role == 'admin':
            allowed = True

        if repository_record.name in rts.repository_roles:

            if rts.repository_roles[repository_record.repository_name] != 'blocked':
                allowed = True

        else:

            if repository_record.guests_access_allowed:
                allowed = True

        if not allowed:
            raise bottle.HTTPError(403, "Not Allowed")

        return

    def repository_view(self, repository_name):

        ret = ''

        rts = self.generate_rts_object()

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            self.repository_view_access_check(rts, p)

            actions = self.get_page_actions(
                mode='repository',
                repository_name=repository_name,
                rts_object=rts
                )

            opened = self.rtenv.modules[self.ttm].get_repository_issues(
                repository_name, 'open', 0, 100
                )

            closed = self.rtenv.modules[self.ttm].get_repository_issues(
                repository_name, 'closed', 0, 100
                )

            deleted = self.rtenv.modules[self.ttm].get_repository_issues(
                repository_name, 'deleted', 0, 100
                )

            open_table = self.rtenv.modules[self.ttm].\
                issue_teaser_table_tpl(opened)

            closed_table = self.rtenv.modules[self.ttm].issue_teaser_table_tpl(
                closed
                )

            deleted_table = self.rtenv.modules[self.ttm].\
                issue_teaser_table_tpl(
                    deleted
                    )

            repository_page = self.rtenv.modules[self.ttm].repository_page_tpl(
                repository_name=repository_name,
                open_issue_table=open_table,
                closed_issue_table=closed_table,
                deleted_issue_table=deleted_table
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' issues".format(p.title),
                actions=actions,
                body=repository_page
                )

        return ret

    def repository_issues(self, repository_name):
        ret = ''

        rts = self.generate_rts_object()

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        self.repository_view_access_check(rts, p)

        decoded_params = bottle.request.params.decode('utf-8')

        if not 'page' in decoded_params:
            decoded_params['page'] = '0'

        if not 'count' in decoded_params:
            decoded_params['count'] = '100'

        if not 'status' in decoded_params:
            decoded_params['status'] = 'open'

        if (not decoded_params['status']
            in self.rtenv.modules[self.ttm].statuses):
            raise bottle.HTTPError(400, body="invalid status")

        try:
            page = int(decoded_params['page'])
            count = int(decoded_params['count'])
        except:
            raise bottle.HTTPError(400, body="invalid numbers")

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='repository_activities',
                repository_name=repository_name,
                rts_object=rts
                )

            issue_records = self.rtenv.modules[self.ttm].get_repository_issues(
                repository_name,
                decoded_params['status'],
                page * count,
                (page * count) + count
                )

            issue_page = self.rtenv.modules[self.ttm].repository_issues_page_tpl(
                issue_records=issue_records,
                status=decoded_params['status'],
                page=page,
                count=count
                )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' {} issues".format(
                    p.title,
                    decoded_params['status']
                    ),
                actions=actions,
                body=issue_page
                )

        return ret

    def repository_activities(self, repository_name):
        ret = ''

        rts = self.generate_rts_object()

        p = self.rtenv.modules[self.ttm].get_repository(repository_name)

        self.repository_view_access_check(rts, p)

        decoded_params = bottle.request.params.decode('utf-8')

        if not 'page' in decoded_params:
            decoded_params['page'] = '0'

        if not 'count' in decoded_params:
            decoded_params['count'] = '100'

        try:
            page = int(decoded_params['page'])
            count = int(decoded_params['count'])
        except:
            raise bottle.HTTPError(400, body="invalid numbers")

        if not p:
            raise bottle.HTTPError(404, body="Project not found")

        else:

            actions = self.get_page_actions(
                mode='repository_activities',
                repository_name=repository_name,
                rts_object=rts
                )

            repository_updates = self.rtenv.modules[self.ttm].get_repository_updates(
                repository_name, page * count, ((page * count) + count)
                )

            activities_table = self.rtenv.modules[self.ttm].\
                repository_activity_table_tpl(
                    activities=repository_updates, page=page, count=count
                    )

            ret = self.rtenv.modules[self.ttm].html_tpl(
                title="`{}' activities".format(p.title),
                actions=actions,
                body=activities_table
                )

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
