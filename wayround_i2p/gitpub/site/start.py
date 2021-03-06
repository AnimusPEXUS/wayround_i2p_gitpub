#!/usr/bin/python3

import os.path
import sys

import wayround_i2p.utils.program
import wayround_i2p.utils.path

import wayround_i2p.gitpub.commands

import wayround_i2p.xmpp.core


wayround_i2p.utils.program.logging_setup('info')

wd = os.path.abspath(os.path.dirname(__file__))

jid = wayround_i2p.xmpp.core.JID(
    user='gitpub',
    domain='wayround.org',
    resource='home'
    )

connection_info = wayround_i2p.xmpp.core.C2SConnectionInfo(
    host='wayround.org',
    port=5222,
    )

auth_info = wayround_i2p.xmpp.core.Authentication(
    service='xmpp',
    hostname='wayround.org',
    authid='gitpub',
    authzid='',
    realm='wayround.org',
    password=''
    )

adds = {}
adds['jid'] = jid
adds['xmpp_connection_info'] = connection_info
adds['xmpp_auth_info'] = auth_info
adds['db_filename'] = wayround_i2p.utils.path.join(wd, 'db', 'database.zodb')
adds['host'] = 'localhost'
adds['port'] = 8084
adds['main_owner'] = 'animus@wayround.org'
adds['ssh_working_root_dir'] = os.path.join(wd, 'ssh_dir')
adds['ssh_host_address'] = 'localhost'
adds['ssh_host_port'] = 2121
adds['host_key_private_rsa_filename'] = \
    os.path.join(wd, 'host_keys', 'host_rsa')
adds['enable_view_repo_server'] = False
adds['web_frontend_host'] = 'localhost'
adds['web_frontend_port'] = 8085
adds['web_frontend_domain'] = 'localhost'


commands = wayround_i2p.gitpub.commands.commands()

command_name = os.path.basename(sys.argv[0])

ret = wayround_i2p.utils.program.program(command_name, commands, adds)

exit(ret)
