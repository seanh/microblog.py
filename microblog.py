#!/usr/bin/env python2.6
"""microblog.py A command-line microblogging client for
identica/twitter/statusnet, see microblog.py --help for usage.

TODO: Add --no-colour option. (To implement this, if NOCOLOUR is True then just set all the
      colour escape codes (BLACK, RED, GREEN, etc.) to empty strings.
TODO: Add --no-bold option. (Same implementation as --no-colour.)
TODO: Add --no-wrap option.
TODO: Implement show <id> command to show specific message(s) by id.
TODO: Short-format printing of messages and users should be
      tab-separated values with empty lines separating rows.
TODO: Long-format printing of messages and users should be JSON.
TODO: Make short-format and long-format help messages. Add fun
      examples to the long help.
TODO: Make it installable with distutils.
TODO: Finish implementing the commands that currently raise NotImplementedError.
TODO: Add more error handling, e.g. of HTTPErrors raised by python_twitter.
TODO: Add an interactive mode, probably using curses
      microblog.py --interactive

"""
from python_twitter import twitter
import os
import ConfigParser
import optparse
import sys
import textwrap
import logging
import readline
import urllib2
import getpass
import shelve
import inspect

IDENTICA_API_ROOT = 'http://identi.ca/api'
TWITTER_API_ROOT = 'http://api.twitter.com/'

UNSEEN = None
USERNAME = None
PASSWORD = None
APIROOT = None
ENCODING = None
API = None
SHELF = None
LONG = None

# Get height and width of user's terminal.
HEIGHT,WIDTH = os.popen('stty size','r').read().split()
HEIGHT = int(HEIGHT)
WIDTH = int(WIDTH)

# ASCII escape sequences
END = '\033[0m'
BRIGHT = '\033[1m'
FAINT = '\033[2m'
NORMAL = '\033[22m'
STRIKETHROUGH = '\033[9m'
BLACK = '\033[30m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
BLACKBG = '\033[40m'
REDBG = '\033[41m'
GREENBG = '\033[42m'
YELLOWBG = '\033[43m'
BLUEBG = '\033[44m'
MAGENTABG = '\033[45m'
CYANBG = '\033[46m'
WHITEBG = '\033[47m'

def whoami():
    """Return the name of the calling function (string).

    """
    return inspect.stack()[1][3]

def whocalledme():
    """Return the name of the caller of the calling function
    (string).

    """
    return inspect.stack()[2][3]

def debug(msg):
    """Print out a debug message.

    """
    logging.getLogger("%s.%s" % (__name__,whocalledme())).debug(' '+str(msg))

def print_status(status):
    """Pretty-print a twitter.Status object.

    """
    name = status.user.screen_name.encode('UTF-8')
    created = status.relative_created_at.encode('UTF-8')
    text = status.text.encode('UTF-8')
    id = str(status.id)
    print '\n'.join(textwrap.wrap("%s %s (%s) [#%s]" % (BRIGHT+BLUE+name+END,text,BLUE+created+END,GREEN+id+END),WIDTH))
    debug(status.id)

def print_statuses(statuses):
    """Pretty-print a sequence of twitter.Status objects.

    """
    for (index,status) in enumerate(reversed(statuses)):
        print_status(status)
        if index < len(statuses)-1: print

def print_statuses(statuses):
    """Pretty-print a sequence of twitter.Status objects.

    """
    for (index,status) in enumerate(reversed(statuses)):
        print_status(status)
        if index < len(statuses)-1: print


def print_message(message):
    """Pretty-print a twitter.DirectMessage object.

    """
    id = str(message.id)
    created = message.created_at
    sender_id = str(message.sender_id)
    sender_name = message.sender_screen_name
    recipient_id = str(message.recipient_id)
    recipient_name = message.recipient_screen_name
    text = message.text
    if LONG:
        print "From: %s" % BRIGHT+BLUE+sender_name+END
        print "To: %s" % BRIGHT+BLUE+recipient_name+END
        print "Date: %s" % BLUE+created+END
        print "Sender ID: %s" % GREEN+sender_id+END
        print "Recipient ID: %s" % GREEN+recipient_id+END
        print "Message ID: %s" % GREEN+id+END
        print
        print text
    else:
        print '\n'.join(textwrap.wrap("%s %s (%s) [#%s]" % (BRIGHT+BLUE+sender_name+END,text,BLUE+created+END,GREEN+id+END),WIDTH))
    debug(id)

def print_messages(messages):
    """Pretty-print a sequence of twitter.DirectMessage objects.

    """
    for (index,message) in enumerate(reversed(messages)):
        print_message(message)
        if index < len(messages)<1: print

def print_user(user):
    """Pretty-print a twitter.User object.

    """
    screen_name = user.GetScreenName().encode('UTF-8')
    long_name = user.GetName().encode('UTF-8')
    statuses = str(user.GetStatusesCount())
    followers = str(user.GetFollowersCount())
    following = str(user.GetFriendsCount())
    if LONG:
        print "%s (%s)" % (BRIGHT+BLUE+screen_name+END,long_name)
        location = user.GetLocation()
        if location:
            print "Location: %s" % YELLOW+location.encode('UTF-8')+END
        description = user.GetDescription()
        if description:
            print "Description: %s" % YELLOW+description.encode('UTF-8')+END
        url = user.GetUrl()
        if url:
            print "Print URL: %s" % BLUE+url.encode('UTF-8')+END
        print "following %s, %s followers" % (GREEN+following+END,GREEN+followers+END)
        status = user.GetStatus()
        if status:
            print "%s messages, latest: %s" % (statuses,YELLOW+status.text.encode('UTF-8')+END)
        else:
            print "%s messages" % statuses
    else:
        print "%s (%s) [%s %s %s]" % (BRIGHT+BLUE+screen_name+END,long_name,GREEN+statuses,followers,following+END)

def print_users(users):
    """Pretty-print a sequence of twitter.User objects.

    """
    for (index,user) in enumerate(users):
        print_user(user)
        if LONG and index < len(users)-1: print

def authenticate():
    """Authenticate with the microblogging service API. Ask the user for her
    username and password if necessary.

    """
    global USERNAME, PASSWORD
    if API._username is not None and API._password is not None:
        # It looks like we've already authenticated.
        return
    if not USERNAME:
        USERNAME = raw_input("Username for %s> " % APIROOT).strip()
    if not PASSWORD:
        PASSWORD = getpass.getpass("Password for %s@%s> " % (USERNAME,APIROOT))
    API.SetCredentials(USERNAME,PASSWORD)
    debug('set credentials for %s@%s' % (USERNAME,APIROOT))

def _read_lastid(args):
    """This is a helper function called by the various ls* functions, it exists
    to avoid code repetition.

    """
    if UNSEEN:
        caller = whocalledme()
        try:
            debug("Reading lastid ['%s']['%s']['%s']['%s']['lastid']." % (APIROOT,USERNAME,caller,str(args)))
            lastid = SHELF[APIROOT][USERNAME][caller][str(args)]['lastid']
        except KeyError:
            lastid = None
        debug("lastid: %s" % lastid)
    else:
        # If UNSEEN is False then reading lastid's is disabled.
        lastid = None
    return lastid

def _save_lastid(lastid,args):
    """This is a helper function called by the various ls* functions, it exists
    to avoid code repetition.

    """
    caller = whocalledme()
    args = str(args)
    debug("Saving lastid ['%s']['%s']['%s']['%s']['%s']." % (APIROOT,USERNAME,caller,str(args),lastid))
    if not SHELF.has_key(APIROOT): SHELF[APIROOT] = {}
    if not SHELF[APIROOT].has_key(USERNAME): SHELF[APIROOT][USERNAME] = {}
    if not SHELF[APIROOT][USERNAME].has_key(caller): SHELF[APIROOT][USERNAME][caller] = {}
    if not SHELF[APIROOT][USERNAME][caller].has_key(args): SHELF[APIROOT][USERNAME][caller][args] = {}
    SHELF[APIROOT][USERNAME][caller][args]['lastid'] = lastid

def lspublic(args):
    lastid = _read_lastid(args)
    if args:
        term = ' '.join(args)
        debug("Filtering public timeline: %s" % term)
        statuses = API.FilterPublicTimeline(term,since_id=lastid)
    else:
        debug("Getting public timeline unfiltered.")
        statuses = API.GetPublicTimeline(since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,args)

def lspersonal(args):
    if len(args) > 1: raise TypeError("lspersonal takes at most one argument.")
    if args:
        user = args[0]
    else:
        user = None
        authenticate()
    lastid = _read_lastid(user)
    statuses = API.GetFriendsTimeline(user=user,since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,user)

def lsprofile(args):
    if len(args) > 1: raise TypeError("lsprofile takes at most one argument.")
    if args:
        user = args[0]
    else:
        user = None
        authenticate()
    lastid = _read_lastid(user)
    statuses = API.GetUserTimeline(id=user,since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,user)

def lsreplies(args):
    if args: raise TypeError("lsreplies doesn't take any arguments.")
    authenticate()
    lastid = _read_lastid(None)
    statuses = API.GetReplies(since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,None)

def send(args):
    authenticate()
    if not args:
        message = raw_input("What's up, %s? > " % USERNAME).strip()
    else:
        message = ' '.join(args).strip()
    try:
        status = API.PostUpdate(message)
    except urllib2.HTTPError, e:
        print "HTTPError: have you verified the email address for your account?"
        raise
    except UnicodeDecodeError:
        print "Your message could not be encoded. Perhaps it contains non-ASCII characters?\nTry explicitly specifying the encoding with the --encoding flag"
        raise
    print "%s just posted: %s" % (status.user.name, status.text)

# TODO: Send the same message to many users, by passing multiple
# args to msg?
def msg(args):
    authenticate()
    try:
        recipient = args[0]
    except IndexError:
        recipient = None
    message = ' '.join(args[1:])
    if not recipient:
        recipient = raw_input("To: ").strip()
    if not message:
        message = raw_input("Message: ").strip()
    try:
        message = API.PostDirectMessage(recipient,message)
    except urllib2.HTTPError, e:
        print "%s. Have you verified the email address for your account? Are you allowed to send direct messages to this recipient?" % e
        raise
    except UnicodeDecodeError:
        print "Your message could not be encoded. Perhaps it contains non-ASCII characters?\nTry explicitly specifying the encoding with the --encoding flag"
        raise
    print "%s@%s just sent the following message to %s@%s: %s" % (USERNAME,APIROOT,message.recipient_screen_name,APIROOT,message.text)

def lsmsgs(args):
    if args: raise TypeError("lsmsgs doesn't take any arguments.")
    authenticate()
    last_id = _read_lastid(None)
    messages = API.GetDirectMessages(since_id=last_id)
    if not messages:
        return
    else:
        print_messages(messages)
        lastid = str(messages[0].id)
        if UNSEEN:
            _save_lastid(lastid,None)

def lsgroup(args):
    raise NotImplementedError()

def lsmembers(args):
    raise NotImplementedError()

def join(args):
    raise NotImplementedError()

def leave(args):
    raise NotImplementedError()

def lsfollowers(args):
    if args: raise TypeError("lsfollowers doesn't take any arguments.")
    authenticate()
    followers = API.GetFollowers()
    print_users(followers)

def lsfollowing(args):
    if len(args) > 1: raise TypeError("lsfollowing takes at most one argument.")
    if args:
        user = args[0]
    else:
        user = None
        authenticate()
    following = API.GetFriends(user=user)
    print_users(following)

def follow(args):
    if not args:
        args = raw_input("User(s) to follow: ").strip().split()
    authenticate()
    for user in args:
        try:
            following = API.CreateFriendship(user=user)
        except urllib2.HTTPError, e:
            print "%s. Did you mistype the username? Usernames should be a space-separated list, no commas" % e
            return
        print "%s@%s is now following:" % (USERNAME,APIROOT)
        print_user(following)

def unfollow(args):
    if not args:
        args = raw_input("User(s) to unfollow: ").strip().split()
    authenticate()
    for user in args:
        try:
            following = API.DestroyFriendship(user=user)
        except urllib2.HTTPError, e:
            print "%s. Did you mistype the username? Usernames should be a space-separated list, no commas" % e
            return
        print "%s@%s is no longer following:" % (USERNAME,APIROOT)
        print_user(following)

def fav(args):
    if not args:
        args = raw_input("ID(s) of the message(s) to fav: ").strip().split()
    authenticate()
    for arg in args:
        id = arg.strip()
        if id.startswith('#'): id = id[1:]
        status = API.GetStatus(id)
        favorite = API.CreateFavorite(status)
        print "%s@%s just favorited message %s: %s" % (USERNAME,APIROOT,favorite.id,favorite.text.encode("UTF-8"))

def unfav(args):
    print "The status.net API doesn't support favorites/destroy yet :("
    raise NotImplementedError()

def lsfavs(args):
    if len(args) > 1: raise TypeError("lsfavs takes at most one argument.")
    if args:
        user = args[0]
    else:
        user = None
        authenticate()
    statuses = API.GetFavorites(user=user)
    print_statuses(statuses)

def lsmentions(args):
    if args: raise TypeError("lsmentions doesn't take any arguments.")
    authenticate()
    lastid = _read_lastid(None)
    statuses = API.GetMentions(since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,None)

def search(args):
    if args:
        term = ' '.join(args)
    else:
        term = raw_input("Search term: ").strip()
    debug("Searching for %s" % term)
    lastid = _read_lastid(term)
    statuses = API.GetSearch(term,since_id=lastid)
    if not statuses:
        return
    else:
        print_statuses(statuses)
        lastid = str(statuses[0].id)
        if UNSEEN:
            _save_lastid(lastid,term)

# FIXME: This always seems to get 401 Unauthorized.
def lsfeatured(args):
    if args: raise TypeError("lsfeatured doesn't take any arguments.")
    authenticate()
    featured = API.GetFeatured()
    print_users(featured)

def lsusers(args):
    if not args:
        args = raw_input("User(s) to list: ").strip().split()
    users = []
    for user in args:
        try:
            if '@' in user[1:-1]:
                users.append(API.GetUserByEmail(user.strip()))
            else:
                users.append(API.GetUser(user))
        except urllib2.HTTPError, e:
            if e.code == 404:
                pass
            else:
                raise
    print_users(users)

# The available commands, their help messages and the functions that
# implement them.
COMMANDS = (
('lscommands',
'List the available commands.',
None),

('lspublic [term]',
"""List the public timeline, or list messages from the public timeline that
match a search term with lspublic <term>.""",
lspublic),

('lspersonal [username]',
"""List recent posts from you and your friends, or list posts for
another user with lspersonal <username>. Equivalent to an identica
user's personal page.""",
lspersonal),

('lsprofile [username]',
"""List your own posts, or list another user's posts with
lspersonal <username>. Equivalent to an identica user's profile
page.""",
lsprofile),

('lsreplies',
"""List replies to you. Equivalent to your identica replies
page.""",
lsreplies),

('send [message]',
"""Post a new item to your microblog. You will be asked to type out
your message, or you can give it in the command:
send "Hello world!" """,
send),

('msg [username] [message]',
"""Send a direct message. If you don't give them in the command
you'll be asked to type out the recipient and the message.""",
msg),

('lsmsgs',
"""List your private messages. Equivalent to your identica Inbox
page.""",
lsmsgs),

('lsgroup <groupname>',
"""List recent posts to a group.""",
lsgroup),

('lsmembers <groupname>',
"""List the members of a group.""",
lsmembers),

('join <groupname>',
"""Join a group.""",
join),

('leave <groupname>',
"""Leave a group.""",
leave),

('lsfollowers',
"""List your followers.""",
lsfollowers),

('lsfollowing [username]',
"""List the people you are following, or list the people another
user is following with lsfollowing <username>.""",
lsfollowing),

('follow <username>',
"""Begin following a user.""",
follow),

('unfollow <username>',
"""Stop following a user.""",
unfollow),

('fav <#id>',
"""Favourite the specified message.""",
fav),

('unfav <#id>',
"""Unfavourite the specified message.""",
unfav),

('lsfavs [username]',
"""List your 20 most recently favorited messages, or list another user's
favorites with lsfavs <username>.""",
lsfavs),

('lsmentions',
"""List the 20 most recent mentions of your username (messages containing
@username).""",
lsmentions),

('search <query>',
"""List recent messages that match the given search query.""",
search),

('lsfeatured',
"""List featured users.""",
lsfeatured),

('lsusers <usernames>',
"""Print the details of some users. For each user you can give their screen
name, used ID or email address (a good way to search for a user name by email
address).""",
lsusers))

def main():
    global UNSEEN, LONG, USERNAME, PASSWORD, APIROOT, ENCODING, API, SHELF

    # Parse the command-line options and arguments.
    usage = """Usage: %prog [options] command [args]

Commands:"""
    for (command,help,func) in COMMANDS:
        usage += ('\n\n' + command + '\n' + help)
    usage += """

You don't have to type a command name in full, you can just type a unique
prefix. For example, 'lsc' for the 'lscommands' command, 'lsr' for the
'lsreplies' command, etc.

If you don't want to keep typing your username and password you can put them in
a ~/.microblogrc file:

    [DEFAULT]
    # Use twitter instead of identica by default.
    apiroot = twitter
    # Specify a default for the --encoding option.
    encoding = UTF-8
    # Always use the --unseen option.
    unseen = True

    [identica]
    username = seanh
    password = **********

    [twitter]
    username = your_username
    password = *****
"""
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-u','--unseen',action='store_true',help="remember which messages have been printed and only print messages that you haven't seen before")
    parser.add_option('-l','--long',action='store_true',help="long form output")
    parser.add_option('-U','--username',action='store',help="specify an alternate username (overrides any username in the config file)")
    parser.add_option('-p','--password',action='store',help="specify an alternate password (overrides any password in the config file)")
    parser.add_option('-a','--apiroot',action='store',help="specify an alternate API root (overrides any apiroot in the config file)")
    parser.add_option('-e','--encoding',action='store',help="specify the character set encoding used in input strings, e.g. utf-8 (overrides any encoding in the config file)")
    parser.add_option('-c','--config',action='store',help="specify an alternate config file")
    parser.add_option('-d','--debug',action='store_true',help='enable verbose output for debugging')
    parser.set_defaults(unseen=False, long=False, username=None, password=None, apiroot=None, encoding=None, config='~/.microblogrc', debug=False)
    (options,args) = parser.parse_args()

    if not args:
        # There has to be at least one argument, the command.
        parser.print_help()
        sys.exit(2)

    # Parse the config file.
    config = ConfigParser.SafeConfigParser()
    configfile = os.path.abspath(os.path.expanduser(options.config))
    config.read(configfile)

    # Initialise various global settings based on the command-line options and
    # the config file.
    if options.debug: logging.basicConfig(level=logging.DEBUG)

    if options.apiroot:
        APIROOT = options.apiroot
    elif config.has_option('DEFAULT','apiroot'):
        APIROOT = config.get('DEFAULT','apiroot')
    else:
        APIROOT = 'identica'

    # The config file and command-line options use 'identica' and 'twitter' as
    # aliases for IDENTICA_API_ROOT and TWITTER_API_ROOT.
    if APIROOT.strip() == 'identica':
        apiroot = IDENTICA_API_ROOT
    elif APIROOT.strip() == 'twitter':
        apiroot = TWITTER_API_ROOT
    else:
        apiroot = APIROOT
    debug("apiroot = %s" % apiroot)

    if options.unseen:
        UNSEEN = options.unseen
    elif config.has_option(APIROOT,"unseen"):
        UNSEEN = config.getboolean(APIROOT,"unseen")
    elif config.has_option("DEFAULT","unseen"):
        UNSEEN = config.getboolean("DEFAULT","unseen")
    else:
        UNSEEN = False
    debug("UNSEEN = %s" % UNSEEN)

    if options.long:
        LONG = options.long
    elif config.has_option(APIROOT,"long"):
        LONG = config.getboolean(APIROOT,"long")
    elif config.has_option("DEFAULT","long"):
        LONG = config.getboolean("DEFAULT","long")
    else:
        LONG = False
    debug("LONG = %s" % LONG)

    if options.encoding:
        ENCODING = options.encoding
    elif config.has_option('DEFAULT','encoding'):
        ENCODING = config.get('DEFAULT','encoding')
    else:
        ENCODING = None
    debug("ENCODING = %s" % ENCODING)

    API = twitter.Api(base_url=apiroot, input_encoding=ENCODING)
    API.SetUserAgent("microblog.py")

    if options.username:
        USERNAME = options.username
    elif config.has_option(APIROOT,"username"):
        USERNAME = config.get(APIROOT,"username")
    elif config.has_option("DEFAULT","username"):
        USERNAME = config.get("DEFAULT","username")
    else:
        USERNAME = None

    if options.password:
        PASSWORD = options.password
    elif config.has_option(APIROOT,"password"):
        PASSWORD = config.get(APIROOT,"password")
    elif config.has_option("DEFAULT","password"):
        PASSWORD = config.get("DEFAULT","password")
    else:
        PASSWORD = None

    if USERNAME and PASSWORD:
        API.SetCredentials(USERNAME,PASSWORD)
        debug('set credentials for %s@%s' % (USERNAME,APIROOT))

    # Parse the command argument and call the appropriate command function.
    matching_commands = [command for command in COMMANDS if command[0].startswith(args[0])]
    if len(matching_commands) == 0:
        parser.print_help()
        sys.exit(2)
    if len(matching_commands) > 1:
        print 'That command was ambiguous:\n%s' % '\n'.join(command[0] for command in matching_commands)
        sys.exit(2)
    else:
        (command,help,func) = matching_commands[0]
        if command == 'lscommands':
            for (command,help,func) in COMMANDS:
                print command
        else:
            SHELF = shelve.open(os.path.abspath(os.path.expanduser('~/.microblog.shelf')), writeback=True)
            try:
                func(args[1:])
            except NotImplementedError:
                print "%s is not implemented yet :(" % command
            except TypeError, e:
                sys.exit(e)
            except urllib2.HTTPError, e:
                print e
            finally:
                SHELF.close()

if __name__ == "__main__":
    main()
