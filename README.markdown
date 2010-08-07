# `microblog.py` A Command-Line Microblogging Client

I wanted a simple command-line client for twitter/identica/statusnet.
`microblog.py`'s commands are quite similar to
[twidge](http://wiki.github.com/jgoerzen/twidge/)'s. It's implemented
using [python-twitter](http://code.google.com/p/python-twitter/).

Usage: `microblog.py [options] command [args]`

## A Few Example Commands

First, setup an alias `mb` for microblog.py. Then:

Spy on the [identica public timeline](http://identi.ca/):

    $ mb lspublic

Print only messages that haven't been printed before:

    $ mb -u lspublic

Spy on the twitter public timeline:

    $ mb -a twitter lspublic

You don't need an identica or twitter account to do this!

List unseen messages from you and your friends:

    $ mb -u lspersonal

List replies to you:

    $ mb lsreplies

Search identica for mentions of 'python':

    $ mb search python

Search for mentions of your username:

    $ mb lsmentions

Post a new message to your microblog:

    $ mb send

You don't have to type a command name in full, you can just type a unique
prefix. For example, 'lsc' for the 'lscommands' command, 'lsr' for the
'lsreplies' command, etc.

To print a short list of the available commands:

    $ mb lscommands

If you don't want to keep typing your username and password you can put them in
a `~/.microblogrc` file:

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

To print the detailed help message:

    $ mb -h

`microblog.py` is suitable for shell scripting. For example, to watch
the public timeline ticking by live:

    $ while (true); do mb -u lspublic; sleep 10; done

...or to watch only message to do with recipes:

    $ while (true); do mb -u search recipes; sleep 10; done

## TODO

I've taken `microblog.py` about as far as I'm likely to. I just wanted a
simple microblogging command, and this fits my needs. But there's much
that could be added:

*  Add `--no-colour` option. (To implement this, if `NOCOLOUR` is `True` then
   just set all the colour escape codes (`BLACK`, `RED`, `GREEN`, etc.) to
   empty strings.
*  Add `--no-bold` option. (Same implementation as `--no-colour`.)
*  Add `--no-wrap` option.
*  Implement `show <id>` command to show specific message(s) by id.
*  Short-format printing of messages and users should be
   tab-separated values with empty lines separating rows. `\n`'s will appear
   in values because the output is hard-wrapped, but an empty line
   (`\n\n`) indicates a new row. Will have to replace any tab characters in values
   with four spaces.
*  Long-format printing of messages and users should be JSON.
*  Make it installable with distutils.
*  Finish implementing the commands that currently raise
   `NotImplementedError`.
*  Add more error handling, e.g. of `HTTPErrors` raised by python_twitter.
*  Add an interactive mode, probably using curses: `microblog.py --interactive`.

If you feel like contributing, fork it!
