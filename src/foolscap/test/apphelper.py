
"""
I am the command executed by test_appserver.py when it exercises the
'run-command' server. On a unix box, we'd use /bin/cat and /bin/dd ; this
script lets the test work on windows too.
"""

import sys, os.path


if sys.argv[1] == 'cat':
    if not os.path.exists(sys.argv[2]):
        sys.stderr.write('cat: %s: No such file or directory\n' % sys.argv[2])
        sys.exit(1)

    with open(sys.argv[2]) as f:
        data = f.read()

    sys.stdout.write(data)
    sys.exit(0)


if sys.argv[1] == 'dd':
    assert sys.argv[2].startswith('of=')

    fn   = sys.argv[2][3:]
    data = sys.stdin.read()

    with open(fn, 'w') as f:
        f.write(data)

    sys.stderr.write('0+1 records in\n')
    sys.stderr.write('0+1 records out\n')
    sys.stderr.write('%d bytes transferred in 42 seconds\n' % len(data))
    sys.exit(0)
