
# -*- coding: utf-8 -*-

import os.path
import pprint

import mako.lookup

import wsgiref.simple_server

import org.wayround.carafe.carafe

MIME_XHTML = 'application/xhtml+xml'
MIME_TEXT = 'text/plain;codepage=UTF-8'


class GitPubViewRepoServer:

    def __init__(self):
        self._controller = None
        self.server = None
        self._host = None
        self._port = None

        self.template_lookup = mako.lookup.TemplateLookup(
            os.path.join(
                os.path.dirname(__file__),
                'repo_view_templates'
                )
            )

        self.app = org.wayround.carafe.carafe.Carafe(
            self.carafe_router
            )

        return

    def set_controller(self, controller):
        self._controller = controller
        self._controller.set_repo_view_site(self)
        return

    def set_host_port(self, host, port):
        self._host = host
        self._port = port
        return

    def start(self):

        self.server = wsgiref.simple_server.make_server(
            self._host, self._port,
            self.app
            )

        self.server.serve_forever()

        return

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
        self.server = None
        # self.app.close()
        return

    def carafe_router(self, wsgi_environment, response_start):
        response_start(
            '200 OK',
            [('Content-type', 'text/plain; charset=UTF-8')]
            )

        return pprint.pformat(wsgi_environment)

    def determine_guest_jid(self):
        return None

    def get_jid_role(self, path):
        ret = 'guest'
        if self.determine_guest_jid() is None:
            ret = 'guest'
        return ret

    def index(self):
        html_t = self.template_lookup.get_template('html.xhtml')
        text = html_t.render(
            title='<Test title>',
            body='empty'
            )
        resp = bottle.Response(
            text, 200
            )
        resp.set_header('Content-Type', MIME_TEXT)
        return resp

    def home_index(self):
        return 'test'
