
import os, sys, json

from six import StringIO

from twisted.trial import unittest
from twisted.internet import defer
from twisted.application import service

from foolscap.api import Tub, eventually
from foolscap.appserver import cli, server, client
from foolscap.test.common import ShouldFailMixin, StallMixin
from foolscap.util import allocate_tcp_port

orig_service_data = {"version": 1,
                     "services": {
                         "swiss1": {"relative_basedir": "1",
                                    "type": "type1",
                                    "args": ["args1a", "args1b"],
                                    "comment": None,
                                    },
                         "swiss2": {"relative_basedir": "2",
                                    "type": "type2",
                                    "args": ["args2a", "args2b"],
                                    "comment": "comment2",
                                    },
                         }}

# copied+trimmed from the old-format appserver/cli.py
def old_add_service(basedir, service_type, service_args, comment, swissnum):
    service_basedir = os.path.join(basedir, 'services', swissnum)
    os.makedirs(service_basedir)

    with open(os.path.join(service_basedir, 'service_type'), 'w') as f:
        f.write(service_type + '\n')

    with open(os.path.join(service_basedir, 'service_args'), 'w') as f:
        f.write(repr(service_args) + '\n')

    if comment:
        with open(os.path.join(service_basedir, 'comment'), 'w') as f:
            f.write(comment + '\n')

    with open(os.path.join(basedir, 'furl_prefix')) as f:
        furl_prefix = f.read().strip()

    furl = furl_prefix + swissnum

    return furl, service_basedir


class ServiceData(unittest.TestCase):
    def test_parse_json(self):
        basedir = "appserver/ServiceData/parse_json"
        os.makedirs(basedir)

        with open(os.path.join(basedir, "services.json"), "w") as f:
            json.dump(orig_service_data, f)

        data = server.load_service_data(basedir)
        self.assertEqual(orig_service_data, data)

    def test_parse_files_and_upgrade(self):
        # create a structure with individual files, and make sure we parse it
        # correctly. Test the git-foolscap case with slashes in the swissnum.
        basedir = "appserver/ServiceData/parse_files"
        os.makedirs(basedir)
        J = os.path.join

        with open(os.path.join(basedir, "furl_prefix"), "wb") as f:
            f.write(b"prefix")

        old_add_service(basedir, "type1", ("args1a", "args1b"), None, "swiss1")
        old_add_service(basedir, "type2", ("args2a", "args2b"), "comment2", "swiss2")
        old_add_service(basedir, "type3", ("args3a", "args3b"), "comment3", "swiss3/3")

        data = server.load_service_data(basedir)
        expected = {"version": 1,
                    "services": {
                        "swiss1": {"relative_basedir": J("services","swiss1"),
                                   "type": "type1",
                                   "args": ["args1a", "args1b"],
                                   "comment": None,
                                   },
                        "swiss2": {"relative_basedir": J("services","swiss2"),
                                   "type": "type2",
                                   "args": ["args2a", "args2b"],
                                   "comment": "comment2",
                                   },
                        J("swiss3","3"): {"relative_basedir":
                                        J("services","swiss3","3"),
                                        "type": "type3",
                                        "args": ["args3a", "args3b"],
                                        "comment": "comment3",
                                        },
                        }}
        self.assertEqual(data, expected)

        s4 = {"relative_basedir": J("services","4"),
              "type": "type4",
              "args": ["args4a", "args4b"],
              "comment": "comment4",
              }
        data["services"]["swiss4"] = s4
        server.save_service_data(basedir, data) # this upgrades to JSON
        data2 = server.load_service_data(basedir) # reads JSON, not files
        expected["services"]["swiss4"] = s4
        self.assertEqual(data2, expected)

    def test_bad_version(self):
        basedir = "appserver/ServiceData/bad_version"
        os.makedirs(basedir)
        orig = {"version": 99}

        with open(os.path.join(basedir, "services.json"), "w") as f:
            json.dump(orig, f)

        e = self.assertRaises(server.UnknownVersion, server.load_service_data, basedir)

        self.assertIn("unable to handle version 99", str(e))

    def test_save(self):
        basedir = "appserver/ServiceData/save"
        os.makedirs(basedir)
        server.save_service_data(basedir, orig_service_data)

        data = server.load_service_data(basedir)
        self.assertEqual(orig_service_data, data)


class CLI(unittest.TestCase):
    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_create(self):
        basedir = "appserver/CLI/create"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        d = self.run_cli("create", "--location", "localhost:1234", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))
            # check that the directory is group/world-inaccessible, even on
            # windows where those concepts are pretty fuzzy. Do this by
            # making sure the mode doesn't change when we chmod it again.
            mode1 = os.stat(serverdir).st_mode
            os.chmod(serverdir, 0o700)
            mode2 = os.stat(serverdir).st_mode
            self.assertEqual("%o" % mode1, "%o" % mode2)

        return d.addCallback(_check)

    def test_create_no_clobber_dir(self):
        basedir = "appserver/CLI/create_no_clobber_dir"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        os.mkdir(serverdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 1)
            self.assertIn("Refusing to touch pre-existing directory", err)
            self.assertFalse(os.path.exists(os.path.join(serverdir, "port")))
            self.assertFalse(os.path.exists(os.path.join(serverdir, "services")))

        return d.addCallback(_check)

    def test_create2(self):
        basedir = "appserver/CLI/create2"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        portnum = allocate_tcp_port()
        d = self.run_cli("create",
                         "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         "--umask", "022", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))
            got_port = open(os.path.join(serverdir, "port"), "r").read().strip()
            self.assertEqual(got_port, "tcp:%d" % portnum)
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.assertTrue(prefix.endswith(":%d/" % portnum), prefix)
            umask = open(os.path.join(serverdir, "umask")).read().strip()
            self.assertEqual(umask, "0022")

        return d.addCallback(_check)

    def test_create3(self):
        basedir = "appserver/CLI/create3"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")

        d = self.run_cli("create", "--location", "proxy.example.com:12345", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))
            # pick an arbitrary port, but FURLs should reference the proxy
            prefix = open(os.path.join(serverdir, "furl_prefix"), "r").read().strip()
            self.assertTrue(prefix.endswith("@proxy.example.com:12345/"), prefix)

        return d.addCallback(_check)

    def test_add(self):
        basedir = "appserver/CLI/add"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)

        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir, "upload-file", incomingdir))

        def _check_add(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            lines = out.splitlines()
            self.assertTrue(lines[0].startswith("Service added in "))
            servicedir = lines[0].split()[-1]
            self.assertTrue(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            swiss = furl[furl.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir2 = os.path.join(serverdir, data["services"][swiss]["relative_basedir"])
            self.assertEqual(os.path.abspath(servicedir), os.path.abspath(servicedir2))
            self.assertEqual(data["services"][swiss]["comment"], None)

        return d.addCallback(_check_add)

    def test_add_service(self):
        basedir = "appserver/CLI/add_service"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))
        d.addCallback(_check)

        def _check_add(ign):
            furl1,servicedir1a = cli.add_service(serverdir,
                                                 "upload-file", (incomingdir,),
                                                 None)
            self.assertTrue(os.path.isdir(servicedir1a))
            asd1 = os.path.abspath(servicedir1a)
            self.assertTrue(asd1.startswith(os.path.abspath(basedir)))
            swiss1 = furl1[furl1.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir1b = os.path.join(serverdir,
                                        data["services"][swiss1]["relative_basedir"])
            self.assertEqual(os.path.abspath(servicedir1a),
                             os.path.abspath(servicedir1b))

            # add a second service, to make sure the "find the next-highest
            # available servicedir" logic works from both empty and non-empty
            # starting points
            furl2,servicedir2a = cli.add_service(serverdir,
                                                 "run-command", ("dummy",),
                                                 None)
            self.assertTrue(os.path.isdir(servicedir2a))
            asd2 = os.path.abspath(servicedir2a)
            self.assertTrue(asd2.startswith(os.path.abspath(basedir)))
            swiss2 = furl2[furl2.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir2b = os.path.join(serverdir,
                                        data["services"][swiss2]["relative_basedir"])
            self.assertEqual(os.path.abspath(servicedir2a),
                             os.path.abspath(servicedir2b))

        return d.addCallback(_check_add)

    def test_add_comment(self):
        basedir = "appserver/CLI/add_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)

        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               "--comment", "commentary here",
                                               serverdir,
                                               "upload-file", incomingdir))
        def _check_add(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            lines = out.splitlines()
            self.assertTrue(lines[0].startswith("Service added in "))
            servicedir = lines[0].split()[-1]
            self.assertTrue(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            swiss = furl[furl.rfind("/")+1:]
            data = server.load_service_data(serverdir)
            servicedir2 = os.path.join(serverdir,
                                       data["services"][swiss]["relative_basedir"])
            self.assertEqual(os.path.abspath(servicedir),
                             os.path.abspath(servicedir2))
            self.assertEqual(data["services"][swiss]["comment"],
                             "commentary here")

        d.addCallback(_check_add)
        return d

    def test_add_badargs(self):
        basedir = "appserver/CLI/add_badargs"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        servicesdir = os.path.join(serverdir, "services")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               serverdir,
                                               "upload-file",
                                               # missing targetdir
                                               ))
        def _check_add(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertIn("Error", err)
            self.assertIn("Wrong number of arguments", err)
            self.assertEqual(os.listdir(servicesdir), [])

        d.addCallback(_check_add)
        d.addCallback(lambda ign: self.run_cli("add",
                                               serverdir,
                                               "upload-file",
                                               "nonexistent-targetdir",
                                               ))

        def _check_add2(rc_out_err):
            rc, out, err = rc_out_err

            self.assertNotEqual(rc, 0)
            self.assertIn("Error", err)
            self.assertIn("targetdir ", err)
            self.assertIn(" must already exist", err)
            self.assertEqual(os.listdir(servicesdir), [])

        d.addCallback(_check_add2)
        return d

    def test_list(self):
        basedir = "appserver/CLI/list"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "upload-file", incomingdir))

        def _check_add(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)

        d.addCallback(_check_add)

        def _check_list_services(ign):
            services = cli.list_services(serverdir)
            self.assertEqual(len(services), 1)
            s = services[0]
            self.assertEqual(s.service_type, "upload-file")
            self.assertEqual(s.service_args, [incomingdir] )
        d.addCallback(_check_list_services)

        d.addCallback(lambda ign: self.run_cli("list", serverdir))

        def _check_list(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            s = cli.list_services(serverdir)[0]
            lines = out.splitlines()
            self.assertEqual(lines[0], "")
            self.assertEqual(lines[1], s.swissnum+":")
            self.assertEqual(lines[2], " upload-file %s" % incomingdir)
            self.assertEqual(lines[3], " " + s.furl)
            self.assertEqual(lines[4], " " + s.service_basedir)

        d.addCallback(_check_list)
        return d

    def test_list_comment(self):
        basedir = "appserver/CLI/list_comment"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        d = self.run_cli("create", "--location", "localhost:3116", serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add",
                                               "--comment", "commentary here",
                                               serverdir,
                                               "upload-file", incomingdir))
        def _check_add(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)

        d.addCallback(_check_add)
        d.addCallback(lambda ign: self.run_cli("list", serverdir))

        def _check_list(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            s = cli.list_services(serverdir)[0]
            lines = out.splitlines()
            self.assertEqual(lines[0], "")
            self.assertEqual(lines[1], s.swissnum+":")
            self.assertEqual(lines[2], " upload-file %s" % incomingdir)
            self.assertEqual(lines[3], " # commentary here")
            self.assertEqual(lines[4], " " + s.furl)
            self.assertEqual(lines[5], " " + s.service_basedir)

        d.addCallback(_check_list)
        return d


class Server(unittest.TestCase, ShouldFailMixin):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_run(self):
        basedir = "appserver/Server/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)

        self.tub = Tub()
        self.tub.setServiceParent(self.s)
        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "upload-file", incomingdir))
        def _check_add(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            lines = out.splitlines()
            self.assertTrue(lines[1].startswith("FURL is pb://"))
            self.furl = lines[1].split()[-1]

        d.addCallback(_check_add)
        stdout = StringIO()

        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)

        d.addCallback(_start_server)
        # make sure the server can actually instantiate a service
        d.addCallback(lambda _ign: self.tub.getReference(self.furl))

        def _got_rref(rref):
            # great!
            pass

        d.addCallback(_got_rref)
        d.addCallback(lambda ign:
                      self.shouldFail(KeyError, "getReference(bogus)",
                                      "unable to find reference for name ",
                                      self.tub.getReference,
                                      self.furl+".bogus"))

        return d


class Upload(unittest.TestCase, ShouldFailMixin):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(client.run_flappclient, argv=argv, run_by_human=False)
        return d  # fires with (rc,out,err)

    def test_run(self):
        basedir = "appserver/Upload/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        furlfile = os.path.join(basedir, "furlfile")

        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)

        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        d.addCallback(_check)
        d.addCallback(lambda ign: self.run_cli("add", serverdir,
                                               "upload-file", incomingdir))
        def _check_add(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            lines = out.splitlines()
            self.assertTrue(lines[1].startswith("FURL is pb://"))
            self.furl = lines[1].split()[-1]
            f = open(furlfile,"w")
            f.write("\n") # it should ignore blank lines
            f.write("# it should ignore comments like this\n")
            f.write(self.furl+"\n")
            f.write("# and it should only pay attention to the first FURL\n")
            f.write(self.furl+".bogus\n")
            f.close()

        d.addCallback(_check_add)
        stdout = StringIO()

        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)

        d.addCallback(_start_server)

        DATA = b"This is some source text.\n"

        sourcefile = os.path.join(basedir, "foo.txt")
        with open(sourcefile, "wb") as f:
            f.write(DATA)

        d.addCallback(lambda _ign: self.run_client("--furl", self.furl, "upload-file", sourcefile))

        def _check_client(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), "foo.txt: uploaded")
            self.assertEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "foo.txt")
            self.assertTrue(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.assertEqual(contents, DATA)

        d.addCallback(_check_client)

        DATA2 = b"This is also some source text.\n"

        sourcefile2 = os.path.join(basedir, "bar.txt")
        with open(sourcefile2, "wb") as f:
            f.write(DATA2)

        d.addCallback(lambda _ign: self.run_client("--furlfile", furlfile,
                                                   "upload-file",
                                                   sourcefile2))

        def _check_client2(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), "bar.txt: uploaded")
            self.assertEqual(err.strip(), "")
            fn = os.path.join(incomingdir, "bar.txt")
            self.assertTrue(os.path.exists(fn))
            contents = open(fn,"rb").read()
            self.assertEqual(contents, DATA2)

        d.addCallback(_check_client2)

        empty_furlfile = furlfile + ".empty"
        open(empty_furlfile, "wb").close()

        d.addCallback(lambda _ign: self.run_client("--furlfile", empty_furlfile,
                                                   "upload-file",
                                                   sourcefile2))

        def _check_client3(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertIn("must provide --furl or --furlfile", err.strip())

        d.addCallback(_check_client3)

        DATA3 = b"file number 3\n"
        DATA4 = b"file number 4\n"
        DATA5 = b"file number 5\n"

        sourcefile3 = os.path.join(basedir, "file3.txt")
        with open(sourcefile3, "wb") as f:
            f.write(DATA3)

        sourcefile4 = os.path.join(basedir, "file4.txt")
        with open(sourcefile4, "wb") as f:
            f.write(DATA4)

        sourcefile5 = os.path.join(basedir, "file5.txt")
        with open(sourcefile5, "wb") as f:
            f.write(DATA5)

        d.addCallback(lambda _ign: self\
            .run_client("--furl", self.furl, "upload-file", sourcefile3, sourcefile4, sourcefile5))

        def _check_client4(rc_out_err):
            rc, out, err = rc_out_err

            self.assertEqual(rc, 0)
            self.assertIn("file3.txt: uploaded", out)
            self.assertIn("file4.txt: uploaded", out)
            self.assertIn("file5.txt: uploaded", out)
            self.assertEqual(err.strip(), "")

            fn = os.path.join(incomingdir, "file3.txt")
            self.assertTrue(os.path.exists(fn))
            contents = open(fn, "rb").read()
            self.assertEqual(contents, DATA3)

            fn = os.path.join(incomingdir, "file4.txt")
            self.assertTrue(os.path.exists(fn))
            contents = open(fn, "rb").read()
            self.assertEqual(contents, DATA4)

            fn = os.path.join(incomingdir, "file5.txt")
            self.assertTrue(os.path.exists(fn))
            contents = open(fn, "rb").read()
            self.assertEqual(contents, DATA5)

        return d.addCallback(_check_client4)


class Client(unittest.TestCase):
    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(client.run_flappclient, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def test_no_command(self):
        d = self.run_client()

        def _check_client1(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertIn("must provide --furl or --furlfile", err)

        d.addCallback(_check_client1)
        d.addCallback(lambda _ign: self.run_client("--furl", "foo"))

        def _check_client2(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertIn("must specify a command", err)

        return d.addCallback(_check_client2)

    def test_help(self):
        d = self.run_client("--help")

        def _check_client(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertIn("Usage: flappclient [--furl=|--furlfile=] ", out)
            self.assertEqual("", err.strip())

        return d.addCallback(_check_client)

    def test_version(self):
        d = self.run_client("--version")

        def _check_client(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertIn("Foolscap version:", out)
            self.assertEqual("", err.strip())

        return d.addCallback(_check_client)


class RunCommand(unittest.TestCase, StallMixin):
    def setUp(self):
        self.s = service.MultiService()
        self.s.startService()

    def tearDown(self):
        return self.s.stopService()

    def run_cli(self, *args):
        argv = ["flappserver"] + list(args)
        d = defer.maybeDeferred(cli.run_flappserver, argv=argv, run_by_human=False)
        return d # fires with (rc,out,err)

    def run_client(self, *args):
        argv = ["flappclient"] + list(args)
        d = defer.maybeDeferred(client.run_flappclient, argv=argv, run_by_human=False, stdio=None)
        return d # fires with (rc,out,err)

    def run_client_with_stdin(self, stdin, *args):
        argv = ["flappclient"] + list(args)

        def my_stdio(proto):
            eventually(proto.connectionMade)
            eventually(proto.dataReceived, stdin)
            eventually(proto.connectionLost, None)

        d = defer.maybeDeferred(client.run_flappclient,
                                argv=argv, run_by_human=False,
                                stdio=my_stdio)

        return d  # fires with (rc,out,err)

    def add(self, serverdir, *args):
        d = self.run_cli("add", serverdir, *args)

        def _get_furl(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            lines = out.splitlines()
            self.assertTrue(lines[1].startswith("FURL is pb://"))
            furl = lines[1].split()[-1]
            return furl

        return d.addCallback(_get_furl)

    def stash_furl(self, furl, which):
        self.furls[which] = furl

    def test_run(self):
        basedir = "appserver/RunCommand/run"
        os.makedirs(basedir)
        serverdir = os.path.join(basedir, "fl")
        incomingdir = os.path.join(basedir, "incoming")
        os.mkdir(incomingdir)
        self.furls = {}

        portnum = allocate_tcp_port()
        d = self.run_cli("create", "--location", "localhost:%d" % portnum,
                         "--port", "tcp:%d" % portnum,
                         serverdir)

        @d.addCallback
        def _check(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isdir(serverdir))

        targetfile = os.path.join(incomingdir, 'foo.txt')
        DATA = 'Contents of foo.txt.\n'

        def _populate_foo(ign):
            with open(targetfile, 'w') as f:
                f.write(DATA)

        d.addCallback(_populate_foo)

        helper = os.path.join(os.path.dirname(__file__), 'apphelper.py')
        d.addCallback(lambda ign:
                      self.add(serverdir,
                               'run-command',
                               '--no-log-stdin', '--log-stdout', '--no-log-stderr',
                               incomingdir,
                               sys.executable, helper, 'cat', 'foo.txt'))
        d.addCallback(self.stash_furl, 0)

        stdout = StringIO()

        @d.addCallback
        def _start_server(ign):
            ap = server.AppServer(serverdir, stdout)
            ap.setServiceParent(self.s)

        d.addCallback(lambda _ign: self.run_client('--furl', self.furls[0], 'run-command'))

        @d.addCallback
        def _check_client(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), DATA.strip())
            self.assertEqual(err.strip(), '')

        def _delete_foo(ign):
            os.unlink(targetfile)

        d.addCallback(_delete_foo)
        d.addCallback(lambda _ign: self.run_client('--furl', self.furls[0], 'run-command'))

        @d.addCallback
        def _check_client2(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertEqual(out, '')
            self.assertEqual(err.strip(), 'cat: foo.txt: No such file or directory')

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command", "--accept-stdin",
                               "--log-stdin", "--no-log-stdout", "--log-stderr",
                               incomingdir,
                               sys.executable, helper, "dd", "of=bar.txt"))
        d.addCallback(self.stash_furl, 1)

        barfile = os.path.join(incomingdir, 'bar.txt')
        DATA2 = 'Pass this\ninto stdin\n'

        d.addCallback(lambda _ign: self\
            .run_client_with_stdin(DATA2.encode(), "--furl", self.furls[1], "run-command"))

        @d.addCallback
        def _check_client3(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)

            with open(barfile, 'r') as f:
                bardata = f.read()

            self.assertEqual(bardata, DATA2)
            # we use a script instead of the real dd; we know how it behaves
            self.assertEqual(out, '')
            self.assertIn('records in', err.strip())

        # exercise some more options

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--send-stdout", "--no-stderr",
                               incomingdir,
                               sys.executable, helper, "cat", "foo.txt"))
        d.addCallback(self.stash_furl, 2)

        d.addCallback(lambda ign:
                      self.add(serverdir,
                               "run-command",
                               "--no-stdin", "--no-stdout", "--send-stderr",
                               incomingdir,
                               sys.executable, helper, "cat", "foo.txt"))

        d.addCallback(self.stash_furl, 3)
        d.addCallback(_populate_foo)
        d.addCallback(lambda _ign: self.run_client("--furl", self.furls[2], "run-command"))

        @d.addCallback
        def _check_client4(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertEqual(out.strip(), DATA.strip())
            self.assertEqual(err, '')

        d.addCallback(lambda _ign: self.run_client("--furl", self.furls[3], "run-command"))

        @d.addCallback
        def _check_client5(rc_out_err):
            rc, out, err = rc_out_err
            self.assertEqual(rc, 0)
            self.assertEqual(out, '') # --no-stdout
            self.assertEqual(err, '')

        d.addCallback(_delete_foo)
        d.addCallback(lambda _ign: self.run_client("--furl", self.furls[2], "run-command"))

        @d.addCallback
        def _check_client6(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertEqual(out, '')
            self.assertEqual(err, '') # --no-stderr

        d.addCallback(lambda _ign: self.run_client("--furl", self.furls[3], "run-command"))

        def _check_client7(rc_out_err):
            rc, out, err = rc_out_err
            self.assertNotEqual(rc, 0)
            self.assertEqual(out, '') # --no-stdout
            self.assertEqual(err.strip(), 'cat: foo.txt: No such file or directory')

        return d.addCallback(_check_client7)
