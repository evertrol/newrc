"""An object-oriented interface to .netrc files.

An extension to the original Python netrc module.

"""

# Original netrc module and documentation by Eric S. Raymond, 21 Dec 1998


import os
import shlex
import stat
from collections import defaultdict, namedtuple


__all__ = ["netrc", "NetrcParseError", "Attrs"]


Attrs = namedtuple('attrs', ['login', 'account', 'password'])


class NetrcParseError(Exception):
    """Exception raised on syntax errors in the .netrc file."""
    def __init__(self, msg, filename=None, lineno=None):
        self.filename = filename
        self.lineno = lineno
        super(NetrcParseError, self).__init__(self, msg)

    def __str__(self):
        return "{msg} ({filename}, line {lineno})".format(
            msg=self.msg, filename=self.filename, lineno=self.lineno)


class netrc(object):
    def __init__(self, file=None, posix=False):
        self.use_default_netrc = file is None
        self.posix = posix
        if self.use_default_netrc:
            try:
                file = os.path.join(os.environ['HOME'], ".netrc")
            except KeyError:
                raise OSError("Could not find .netrc: $HOME is not set")
        self.hosts = {}
        self.hosts2 = defaultdict(list)
        self.macros = {}
        if hasattr(file, 'read') and hasattr(file, 'readline'):
            self._parse(file.name, file)
        else:
            with open(file) as fp:
                self._parse(file, fp)

        for name, attrs in self.hosts2.items():
            self.hosts[name] = tuple(attrs[0])

    def _parse(self, filename, fp):
        print(filename)
        lexer = shlex.shlex(fp, posix=self.posix)
        lexer.wordchars += r"""!$%&()*+,-./:;<=>?@[\]^_`{|}~"""
        if not self.posix:
            lexer.wordchars += r"""#"'"""
        lexer.commenters = lexer.commenters.replace('#', '')
        while True:
            # Look for a machine, default, or macdef top-level keyword
            saved_lineno = lexer.lineno
            toplevel = tt = lexer.get_token()
            if not tt:
                break
            elif tt[0] == '#':
                if lexer.lineno == saved_lineno and len(tt) == 1:
                    # comment: skip to next line
                    lexer.instream.readline()
                continue
            elif tt == 'machine':
                entryname = lexer.get_token()
            elif tt == 'default':
                entryname = 'default'
            elif tt == 'macdef':
                # Just skip to end of macdefs
                entryname = lexer.get_token()
                if entryname == lexer.eof:
                    raise NetrcParseError("missing macro name",
                                          filename, lexer.lineno)
                self.macros[entryname] = []
                lexer.whitespace = ' \t'
                while True:
                    line = lexer.instream.readline()
                    if not line or line == '\012':
                        lexer.whitespace = ' \t\r\n'
                        break
                    self.macros[entryname].append(line)
                continue
            else:
                raise NetrcParseError(
                    "bad toplevel token {token!s}".format(token=tt),
                    filename, lexer.lineno)

            # We're looking at start of an entry for a named machine
            # or default.
            login = ''
            account = password = None
            while True:
                tt = lexer.get_token()
                print(tt)
                if (tt in {lexer.eof, 'machine', 'default', 'macdef'} or
                    tt.startswith('#')):
                    if password:
                        attrs = Attrs(login=login,
                                      account=account,
                                      password=password)
                        print(attrs)
                        if entryname == 'default':
                            # allow only default one entry
                            self.hosts2['default'] = [attrs]
                        else:
                            self.hosts2[entryname].append(attrs)
                        lexer.push_token(tt)
                        break
                    else:
                        raise NetrcParseError(
                            "malformed {toplevel} entry {entryname} "
                            "terminated by {token}".format(
                                toplevel=toplevel,
                                entryname=entryname,
                                token=repr(tt)),
                            filename, lexer.lineno)
                elif tt == 'login' or tt == 'user':
                    login = lexer.get_token()
                    if login == lexer.eof:
                        raise NetrcParseError("missing login",
                                              filename, lexer.lineno)
                elif tt == 'account':
                    account = lexer.get_token()
                    if account == lexer.eof:
                        raise NetrcParseError("missing account",
                                              filename, lexer.lineno)
                elif tt == 'password':
                    if os.name == 'posix' and self.use_default_netrc:
                        prop = os.fstat(fp.fileno())
                        if prop.st_uid != os.getuid():
                            import pwd
                            try:
                                fowner = pwd.getpwuid(prop.st_uid)[0]
                            except KeyError:
                                fowner = 'uid {uid}'.format(prop.st_uid)
                            try:
                                user = pwd.getpwuid(os.getuid())[0]
                            except KeyError:
                                user = 'uid {uid}'.format(os.getuid())
                            raise NetrcParseError(
                                "~/.netrc file owner ({owner}) does not match"
                                " current user ({user})".format(
                                    owner=fowner, user=user),
                                filename, lexer.lineno)
                        if (prop.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                            raise NetrcParseError(
                               "~/.netrc access too permissive: access"
                               " permissions must restrict access to only"
                               " the owner", filename, lexer.lineno)
                    password = lexer.get_token()
                    if password == lexer.eof:
                        raise NetrcParseError("missing password",
                                              filename, lexer.lineno)

                else:
                    raise NetrcParseError(
                        "bad follower token {token!r}".format(token=tt),
                        filename, lexer.lineno)


    def authenticators(self, host):
        """Return a (user, account, password) tuple for given host."""
        if host in self.hosts:
            return self.hosts[host]
        elif 'default' in self.hosts:
            return self.hosts['default']
        else:
            return None

    def authenticators2(self, host, user=None):
        """Return a (user, account, password) tuple for given host.

        If the user is set, the entry have to match both the host and
        user, otherwise None is returned.

        If host is not found, the default login details are returned,
        as a 1-element list of a 3-tuple.


        When neither the host nor a default section is present in the
        .netrc file, an empty list is returned

        """
        if host in self.hosts2:
            entries = self.hosts2[host]
            if user:
                entries = [entry for entry in self.hosts2[host]
                           if user == entry.login]
                return entries
            return entries
        elif 'default' in self.hosts2:
            entries = self.hosts2['default']
            if user:
                if user == self.hosts2['default'][0][0]:
                    entries = self.host['default']
                return entries
            return entries
        else:
            return []

    def __repr__(self):
        """Dump the class data in the format of a .netrc file."""
        rep = ""
        for host, attrs in self.hosts2.items():
            for attr in attrs:
                rep = (rep + "machine "+ host +
                       "\n\tlogin " + repr(attr.login) + "\n")
                if attr.account:
                    rep = rep + "account " + repr(attr.account)
                rep = rep + "\tpassword " + repr(attr.password) + "\n"
        for macro in self.macros.keys():
            rep = rep + "macdef " + macro + "\n"
            for line in self.macros[macro]:
                rep = rep + line
            rep = rep + "\n"
        return rep


if __name__ == '__main__':
    import sys
    try:
        text = netrc(sys.argv[1], posix=True)
    except IndexError:
        text = netrc()
    print(text)
