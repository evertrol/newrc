import newrc as netrc, os, unittest, sys, textwrap
from test import support

temp_filename = support.TESTFN

class NetrcTestCase(unittest.TestCase):

    def make_nrc(self, test_data):
        test_data = textwrap.dedent(test_data)
        mode = 'w'
        if sys.platform != 'cygwin':
            mode += 't'
        with open(temp_filename, mode) as fp:
            fp.write(test_data)
        self.addCleanup(os.unlink, temp_filename)
        return netrc.netrc(temp_filename)

    def test_default(self):
        nrc = self.make_nrc("""\
            machine host1.domain.com login log1 password pass1 account acct1
            default login log2 password pass2
            """)
        self.assertEqual(nrc.hosts['host1.domain.com'],
                         ('log1', 'acct1', 'pass1'))
        self.assertEqual(nrc.hosts['default'], ('log2', None, 'pass2'))

    def test_macros(self):
        nrc = self.make_nrc("""\
            macdef macro1
            line1
            line2

            macdef macro2
            line3
            line4
            """)
        self.assertEqual(nrc.macros, {'macro1': ['line1\n', 'line2\n'],
                                      'macro2': ['line3\n', 'line4\n']})

    def _test_passwords(self, nrc, passwd):
        nrc = self.make_nrc(nrc)
        self.assertEqual(nrc.hosts['host.domain.com'], ('log', 'acct', passwd))

    def test_password_with_leading_hash(self):
        self._test_passwords("""\
            machine host.domain.com login log password #pass account acct
            """, '#pass')

    def test_password_with_trailing_hash(self):
        self._test_passwords("""\
            machine host.domain.com login log password pass# account acct
            """, 'pass#')

    def test_password_with_internal_hash(self):
        self._test_passwords("""\
            machine host.domain.com login log password pa#ss account acct
            """, 'pa#ss')

    def _test_comment(self, nrc, passwd='pass'):
        nrc = self.make_nrc(nrc)
        self.assertEqual(nrc.hosts['foo.domain.com'], ('bar', None, passwd))
        self.assertEqual(nrc.hosts['bar.domain.com'], ('foo', None, 'pass'))

    def test_comment_before_machine_line(self):
        self._test_comment("""\
            # comment
            machine foo.domain.com login bar password pass
            machine bar.domain.com login foo password pass
            """)

    def test_comment_before_machine_line_no_space(self):
        self._test_comment("""\
            #comment
            machine foo.domain.com login bar password pass
            machine bar.domain.com login foo password pass
            """)

    def test_comment_before_machine_line_hash_only(self):
        self._test_comment("""\
            #
            machine foo.domain.com login bar password pass
            machine bar.domain.com login foo password pass
            """)

    def test_comment_at_end_of_machine_line(self):
        self._test_comment("""\
            machine foo.domain.com login bar password pass # comment
            machine bar.domain.com login foo password pass
            """)

    def test_comment_at_end_of_machine_line_no_space(self):
        self._test_comment("""\
            machine foo.domain.com login bar password pass #comment
            machine bar.domain.com login foo password pass
            """)

    def test_comment_at_end_of_machine_line_pass_has_hash(self):
        self._test_comment("""\
            machine foo.domain.com login bar password #pass #comment
            machine bar.domain.com login foo password pass
            """, '#pass')


    @unittest.skipUnless(os.name == 'posix', 'POSIX only test')
    def test_security(self):
        # This test is incomplete since we are normally not run as root and
        # therefore can't test the file ownership being wrong.
        d = support.TESTFN
        os.mkdir(d)
        self.addCleanup(support.rmtree, d)
        fn = os.path.join(d, '.netrc')
        with open(fn, 'wt') as f:
            f.write("""\
                machine foo.domain.com login bar password pass
                default login foo password pass
                """)
        with support.EnvironmentVarGuard() as environ:
            environ.set('HOME', d)
            os.chmod(fn, 0o600)
            nrc = netrc.netrc()
            self.assertEqual(nrc.hosts['foo.domain.com'],
                             ('bar', None, 'pass'))
            os.chmod(fn, 0o622)
            self.assertRaises(netrc.NetrcParseError, netrc.netrc)

    # New test for newrc
    def test_multiple_logins(self):
        nrc = self.make_nrc("""\
            machine host1.domain.com login log1 password pass1 account acct1
            machine host1.domain.com login log2 password pass2 account acct2
            default login log2 password pass2
            """)
        self.assertEqual(nrc.hosts['host1.domain.com'],
                         ('log1', 'acct1', 'pass1'))
        self.assertEqual(nrc.hosts['default'], ('log2', None, 'pass2'))
        self.assertEqual(len(nrc.hosts2['host1.domain.com']), 2)
        self.assertEqual(nrc.authenticators2('non-existing')[0],
                         netrc.Attrs(login='log2', password='pass2',
                                     account=None))
        attrs = nrc.authenticators2('host1.domain.com')
        self.assertEqual(attrs[0], netrc.Attrs(login='log1', password='pass1',
                                               account='acct1'))
        self.assertEqual(attrs[1], netrc.Attrs(login='log2', password='pass2',
                                               account='acct2'))


class NetrcTestCasePosix(NetrcTestCase):
    def make_nrc(self, test_data):
        test_data = textwrap.dedent(test_data)
        mode = 'w'
        if sys.platform != 'cygwin':
            mode += 't'
        with open(temp_filename, mode) as fp:
            fp.write(test_data)
        self.addCleanup(self.unlink, temp_filename)
        return netrc.netrc(temp_filename, posix=True)

    def unlink(self, filename):
        try:
            os.unlink(filename)
        except FileNotFoundError:
            pass

    def _test_passwords(self, nrc, passwd, account=False):
        nrc = self.make_nrc(nrc)
        acct = 'acct' if account is False else account
        self.assertEqual(nrc.hosts['host.domain.com'], ('log', acct, passwd))


    def test_password_with_leading_hash(self):
        with self.assertRaises(netrc.NetrcParseError):
            self._test_passwords("""\
            machine host.domain.com login log password #pass account acct
            """, '#pass')
        self._test_passwords("""\
            machine host.domain.com login log password '#pass' account acct
            """, '#pass')

    def test_password_with_trailing_hash(self):
        self._test_passwords("""\
            machine host.domain.com login log password pass# account acct
            """, 'pass', account=None)
        self._test_passwords("""\
            machine host.domain.com login log password 'pass#' account acct
            """, 'pass#')

    def test_password_with_internal_hash(self):
        # default style
        self._test_passwords("""\
            machine host.domain.com login log password pa#ss account acct
            """, 'pa', account=None)
        # POSIX style
        self._test_passwords("""\
            machine host.domain.com login log password 'pa#ss' account acct
            """, 'pa#ss')

    def test_comment_at_end_of_machine_line_pass_has_hash(self):
        # default style
        with self.assertRaises(netrc.NetrcParseError):
            self._test_comment("""\
            machine foo.domain.com login bar password #pass #comment
            machine bar.domain.com login foo password pass
            """, '#pass')
        self._test_comment("""\
            machine foo.domain.com login bar password '#pass' #comment
            machine bar.domain.com login foo password pass
            """, '#pass')

    def test_backslash_escape(self):
        self._test_comment("""\
            machine foo.domain.com login bar password \#pass #comment
            machine bar.domain.com login foo password pass
            """, '#pass')

    def test_quoting(self):
        self._test_comment("""\
            machine foo.domain.com login bar password "#pass" #comment
            machine bar.domain.com login foo password pass
            """, '#pass')
        self._test_comment("""\
            machine foo.domain.com login bar password '#p"ass' #comment
            machine bar.domain.com login foo password pass
            """, '#p"ass')
        self._test_comment("""\
            machine foo.domain.com login bar password "#pa'ss" #comment
            machine bar.domain.com login foo password pass
            """, "#pa'ss")
        # Shell-style single quote escape
        self._test_comment("""\
            machine foo.domain.com login bar password '#pas'\\''s' #comment
            machine bar.domain.com login foo password pass
            """, "#pas's")


class NetrcAuthethenticatorTestCase(unittest.TestCase):
    pass



def test_main():
    support.run_unittest(NetrcTestCase)


if __name__ == "__main__":
    test_main()
