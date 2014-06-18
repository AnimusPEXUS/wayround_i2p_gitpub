
import logging
import threading

import org.wayround.softengine.rtenv
import org.wayround.gitpub.jabber_commands
import org.wayround.gitpub.modules
import org.wayround.xmpp.client_bot
import org.wayround.sshgithost.sshgithost


def commands():
    return dict(
        site=dict(
            start=site_start
            ),
        help=dict(
            )
        )


def site_start(comm, opts, args, adds):

    ret = 0

    db_config = adds['db_config']
    db_echo = adds['db_echo']
    host = adds['host']
    port = adds['port']
    main_admin = adds['main_admin']
    ssh_working_root_dir = adds['ssh_working_root_dir']
    ssh_host_address = adds['ssh_host_address']
    ssh_host_port = adds['ssh_host_port']
    host_key_privat_rsa_filename = adds['host_key_privat_rsa_filename']

    jid = adds['jid']
    xmpp_connection_info = adds['xmpp_connection_info']
    xmpp_auth_info = adds['xmpp_auth_info']

    db = org.wayround.softengine.rtenv.DB(
        db_config,
        echo=db_echo,
        # FIXME: this is unsafe?
        connect_args={'check_same_thread': False}
        )

    rtenv = org.wayround.softengine.rtenv.RuntimeEnvironment(db)

    org.wayround.gitpub.modules.GitPub(rtenv)

    exit_event = threading.Event()

    rtenv.init()

    rtenv.db.create_all()

    commands = org.wayround.gitpub.jabber_commands.JabberCommands()

    ssh_git_host = org.wayround.sshgithost.sshgithost.SSHGitHost(
        ssh_working_root_dir,
        ssh_host_address,
        ssh_host_port,
        host_key_privat_rsa_filename
        )

    bot = org.wayround.xmpp.client_bot.Bot()

    site = org.wayround.gitpub.env.Environment(
        rtenv,
        host=host,
        port=port,
        admin_jid=main_admin
        )

    threading.Thread(
        name="Site Thread",
        target=site.start
        ).start()

    commands.set_site(site)
    commands.set_ssh_git_host(ssh_git_host)

    bot.set_commands(commands.commands_dict())
    site.set_bot(bot)
    site.set_ssh_git_host(ssh_git_host)

    threading.Thread(
        name="Bot Thread",
        target=bot.connect,
        args=(jid, xmpp_connection_info, xmpp_auth_info,),
        ).start()

    print("starting ssh service")
    ssh_git_host.start()
    print("started ssh service")

    try:
        exit_event.wait()
    except KeyboardInterrupt:
        logging.info("exiting now")
    except:
        logging.exception("Some error while waiting for exit event")

    exit_event.set()

    logging.debug("starting ssh stop")
    ssh_git_host.stop()
    logging.debug("starting bot stop")
    bot.disconnect()
    logging.debug("starting site stop")
    site.stop()
    logging.debug("all things stopped")

    logging.debug("MainThread exiting")

    return ret
