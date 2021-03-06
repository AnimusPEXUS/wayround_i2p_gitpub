
import logging
import threading

import wayround_i2p.xmpp.client_bot

import wayround_i2p.softengine.rtenv

import wayround_i2p.gitpub.jabber_commands
import wayround_i2p.gitpub.modules
import wayround_i2p.gitpub.controller

import wayround_i2p.gitpub.web_server

import wayround_i2p.sshgithost.sshgithost


def commands():
    return dict(
        start=site_start
        )


def site_start(comm, opts, args, adds):

    ret = 0

    db_filename = adds['db_filename']
    host = adds['host']
    port = adds['port']
    main_owner = adds['main_owner']
    ssh_working_root_dir = adds['ssh_working_root_dir']
    ssh_host_address = adds['ssh_host_address']
    ssh_host_port = adds['ssh_host_port']
    host_key_private_rsa_filename = adds['host_key_private_rsa_filename']

    jid = adds['jid']
    xmpp_connection_info = adds['xmpp_connection_info']
    xmpp_auth_info = adds['xmpp_auth_info']

    db = wayround_i2p.softengine.rtenv.DB_ZODB(db_filename)

    rtenv = wayround_i2p.softengine.rtenv.RuntimeEnvironment(db)

    wayround_i2p.gitpub.modules.GitPub(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    commands = wayround_i2p.gitpub.jabber_commands.JabberCommands()

    ssh_git_host = wayround_i2p.sshgithost.sshgithost.SSHGitHost(
        ssh_working_root_dir,
        ssh_host_address,
        ssh_host_port,
        host_key_private_rsa_filename
        )

    bot = wayround_i2p.xmpp.client_bot.Bot()

    # environ = wayround_i2p.gitpub.env.Environment(
    #    rtenv,
    #    host=host,
    #    port=port,
    #    owner_jid=main_owner
    #    )

    controller = wayround_i2p.gitpub.controller.Controller(
        owner_jid=main_owner
        )
    controller.set_bot(bot)
    controller.set_ssh_git_host(ssh_git_host)
    controller.set_rtenv(rtenv)

    # threading.Thread(
    #name="Environ Thread",
    # target=environ.start
    #).start()

    commands.set_controller(controller)
    commands.set_ssh_git_host(ssh_git_host)

    bot.set_commands(commands.commands_dict())
    # environ.set_bot(bot)
    # environ.set_ssh_git_host(ssh_git_host)

    print("web server: {} {}".format(adds['web_frontend_domain'],
        (adds['web_frontend_host'],
         int(adds['web_frontend_port']))))
    web_server = wayround_i2p.gitpub.web_server.WebServer(
        controller,
        adds['web_frontend_domain'],
        (adds['web_frontend_host'],
         int(adds['web_frontend_port']))
        )

    threading.Thread(
        name="Bot Thread",
        target=bot.connect,
        args=(jid, xmpp_connection_info, xmpp_auth_info,),
        ).start()

    print("starting ssh service")
    ssh_git_host.start()
    print("started ssh service")

    print("starting web_server")
    threading.Thread(
        target=web_server.start
        ).start()
    print("started web_server")

    try:
        exit_event.wait()
    except KeyboardInterrupt:
        logging.info("exiting now")
    except:
        logging.exception("Some error while waiting for exit event")

    exit_event.set()

    print("starting ssh stop")
    ssh_git_host.stop()
    print("starting bot stop")

    print("stopping view repo")
    web_server.stop()
    print("stopping view repo")

    bot.disconnect()
    # print("starting environ stop")
    # environ.stop()
    print("all things stopped")

    print("MainThread exiting")

    return ret
