
# -*- coding: utf-8 -*-

import os.path
import pprint

import pygit2
import mako.lookup

import wayround_org.wsgi.server
import wayround_org.carafe.carafe

#MIME_XHTML = 'application/xhtml+xml'
MIME_XHTML = 'text/html;codepage=UTF-8'
MIME_TEXT = 'text/plain;codepage=UTF-8'


class GitPubViewRepoServer:

    def __init__(self, controller):
        self._controller = controller

        self.template_lookup = mako.lookup.TemplateLookup(
            os.path.join(
                os.path.dirname(__file__),
                'repo_view_templates'
                )
            )

        self.router = wayround_org.carafe.carafe.Router(
            self.default_router_target
            )

        self.router.add(
            'GET',
            [],
            self.home_list
            )

        self.router.add(
            'GET',
            [('fm', '*', 'home')],
            self.repo_list
            )

        self.router.add(
            'GET',
            [
                ('fm', '*', 'home'),
                ('fm', '*', 'repo'),
                ('fm', 'branch')
                ],
            self.branch_list
            )

        self.router.add(
            'GET',
            [
                ('fm', '*', 'home'),
                ('fm', '*', 'repo'),
                ('fm', 'tag')
                ],
            self.tag_list
            )

        return

    def default_router_target(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        response_start(404, [('Content-type', MIME_TEXT)])
        return ['Repository Server. 404']

    def determine_guest_jid(self):
        return 'test_guest@wayround.org'

    def get_jid_role(self, path):
        ret = 'guest'
        if self.determine_guest_jid() is None:
            ret = 'guest'
        return ret

    def home_list(self,
                  wsgi_environment,
                  response_start,
                  route_result
                  ):

        messages = []

        res = self._controller.lst(
            self.determine_guest_jid(),
            self.determine_guest_jid(),
            home_level=None,
            messages=messages
            )

        error = False

        for i in messages:
            if i['type'] == 'error':
                error = True

        response_start(200, [('Content-type', MIME_XHTML)])

        html = self.template_lookup.get_template('/html.xhtml')

        site_messages = self.template_lookup.get_template(
            '/site_messages.xhtml'
            )

        home_list = self.template_lookup.get_template('/home_list.xhtml')

        ret = html.render(
            title='Home list',
            body=home_list.render(
                list_items=res
                ),
            site_messages=site_messages.render(
                messages=messages
                )
            )

        return ret

    def repo_list(self,
                  wsgi_environment,
                  response_start,
                  route_result
                  ):

        messages = []

        res = self._controller.lst(
            self.determine_guest_jid(),
            self.determine_guest_jid(),
            home_level=route_result['home'],
            messages=messages
            )

        error = False

        for i in messages:
            if i['type'] == 'error':
                error = True

        response_start(200, [('Content-type', MIME_XHTML)])

        html = self.template_lookup.get_template('/html.xhtml')

        site_messages = self.template_lookup.get_template(
            '/site_messages.xhtml'
            )

        repo_list = self.template_lookup.get_template('/repo_list.xhtml')

        ret = html.render(
            title='Repository list in home: {}'.format(route_result['home']),
            body=repo_list.render(
                list_items=res,
                home=route_result['home']
                ),
            site_messages=site_messages.render(
                messages=messages
                )
            )

        return ret

    def branch_list(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):

        messages = []
        
        # repo = self._controller.get_ssh_git_host().

        res = self._controller.lst(
            self.determine_guest_jid(),
            self.determine_guest_jid(),
            home_level=route_result['home'],
            messages=messages
            )

        error = False

        for i in messages:
            if i['type'] == 'error':
                error = True

        response_start(200, [('Content-type', MIME_XHTML)])

        html = self.template_lookup.get_template('/html.xhtml')

        site_messages = self.template_lookup.get_template(
            '/site_messages.xhtml'
            )

        branch_list = self.template_lookup.get_template('/branch_list.xhtml')

        ret = html.render(
            title='Branch List {}/{}'.format(
                route_result['home'],
                route_result['repo']
                ),
            body=branch_list.render(
                list_items=res,
                home=route_result['home'],
                repo=route_result['repo']
                ),
            site_messages=site_messages.render(
                messages=messages
                )
            )

        return ret

    def tag_list(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        return []


class GitPubBranchServer:

    def __init__(self, controller):
        self._controller = controller

        self.router = wayround_org.carafe.carafe.Router(
            self.default_router_target
            )

        self.router.add('GET', [('path', None, 'path')], self.by_path)

        return

    def default_router_target(
            self,
            wsgi_environment,
            response_start,
            route_result
            ):
        response_start(404, [('Content-type', MIME_TEXT)])
        return ['Branch Server. 404']

    def by_path(self,
                wsgi_environment,
                response_start,
                route_result
                ):
        response_start(200)
        return 'by_path'


class WebServer:

    def __init__(self, controller, main_domain, address):

        self.main_domain = main_domain

        self.main_domain_server = GitPubViewRepoServer(controller)
        self.sub_domain_server = GitPubBranchServer(controller)

        self.carafe_app = \
            wayround_org.carafe.carafe.Carafe(self.router_entry)

        self.wsgi_server = \
            wayround_org.wsgi.server.CompleteServer(
                self.carafe_app.target_for_wsgi_server,
                address
                )

        return

    def start(self):
        self.wsgi_server.start()
        return

    def wait(self):
        self.wsgi_server.wait()
        return

    def stop(self):
        self.wsgi_server.stop()
        return

    def router_entry(self, wsgi_environment, response_start):

        req_domain = wsgi_environment['HTTP_HOST']
        req_port = None
        r = req_domain.split(':')
        if len(r) > 1:
            req_port = int(r[1])
        req_domain = r[0]
        del r

        if req_domain == self.main_domain:
            ret = self.main_domain_server.router.wsgi_server_target(
                wsgi_environment, response_start
                )
        else:
            if req_domain.endswith(self.main_domain):
                ret = self.sub_domain_server.router.wsgi_server_target(
                    wsgi_environment, response_start
                    )
            else:
                response_start(404, [('Content-Type', MIME_TEXT)])
                ret = [
                    'host {} is not served'.format(
                        wsgi_environment['HTTP_HOST']
                        )
                    ]
        return ret
