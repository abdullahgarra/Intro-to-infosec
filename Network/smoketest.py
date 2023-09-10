import contextlib
import os
import traceback

import infosec.core as utils
from infosec import core


@core.smoke.smoke_check
def check_q1():
    try:
        result = utils.execute(['python3', 'q1.py', 'q1.pcap'])
        if result.exit_code:
            core.smoke.error('ERROR: `python3 q1.py q1.pcap` exitted with non-zero code {}'
                        .format(result.exit_code))

        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if not len(lines) == 1:
            core.smoke.error(("ERROR: `python3 q1.py q1.pcap` should return exactly one "
                         + "line of ('user', 'password'), (as the .pcap should have one "
                         + "login attempt), but it returned {} lines:")
                        .format(len(lines)))
            print(result.stdout)
        else:
            core.smoke.success("q1.py looks good")

    except Exception as e:
        core.smoke.error('ERROR: Failed running/analyzing `python3 q1.py q1.pcap`')
        traceback.print_exc()

@contextlib.contextmanager
def question_context(name):
    try:
        core.smoke.highlight(name)
        yield
    except Exception as e:
        core.smoke.error(e)
    finally:
        # Add a new-line after each question
        print()

def smoketest():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    with question_context("Question 1"):
        core.smoke.check_if_nonempty('q1.py')
        core.smoke.check_if_nonempty('q1.txt')
        core.smoke.check_if_nonempty('q1.pcap')
        check_q1()
    with question_context("Question 2"):
        core.smoke.check_if_nonempty('q2.py')
        core.smoke.check_if_nonempty('q2.txt')
    with question_context("Question 3"):
        core.smoke.check_if_nonempty('q3.py')
        core.smoke.check_if_nonempty('q3.txt')


if __name__ == '__main__':
    smoketest()
