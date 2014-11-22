#!/usr/bin/python3

import os.path
import sys

import org.wayround.utils.program
import org.wayround.utils.path

import org.wayround.gitpub.commands

import org.wayround.xmpp.core


org.wayround.utils.program.logging_setup('info')

wd = os.path.abspath(os.path.dirname(__file__))

jid = org.wayround.xmpp.core.JID(
    user='gitpub',
    domain='wayround.org',
    resource='home'
    )

connection_info = org.wayround.xmpp.core.C2SConnectionInfo(
    host='wayround.org',
    port=5222,
    )

auth_info = org.wayround.xmpp.core.Authentication(
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
adds['db_filename'] = org.wayround.utils.path.join(wd, 'db', 'database.zodb')
adds['host'] = 'localhost'
adds['port'] = 8084
adds['main_owner'] = 'animus@wayround.org'
adds['ssh_working_root_dir'] = os.path.join(wd, 'ssh_dir')
adds['ssh_host_address'] = 'localhost'
adds['ssh_host_port'] = 2121
adds['host_key_privat_rsa_filename'] = \
    os.path.join(wd, 'host_keys', 'host_rsa')


commands = org.wayround.gitpub.commands.commands()

command_name = os.path.basename(sys.argv[0])

ret = org.wayround.utils.program.program(command_name, commands, adds)

exit(ret)
