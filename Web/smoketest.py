import contextlib
import os

from infosec import core


@core.smoke.smoke_check
def check_msg(path):
    with open(path, 'r') as f:
        header = f.readline()
        if not header.startswith('#'):
            core.smoke.error(f'First line of {path} should be a channel name and '
                        f'begin with a #')
            return
        if not f.read().strip():
            core.smoke.error(f'No content provided (after the channel) in {path}')
            return
    core.smoke.success(f'{path} seems cool')


@core.smoke.smoke_check
def make_check(prefix):
    console_path = prefix + '.console'
    msg_path = prefix + '.msg'
    txt_path = prefix + '.txt'
    if os.path.exists(console_path) and os.path.exists(msg_path):
        core.smoke.error(f'Provided both {console_path} and {msg_path}')
    elif os.path.exists(console_path):
        core.smoke.check_if_nonempty(console_path)
    elif os.path.exists(msg_path):
        check_msg(msg_path)
    else:
        core.smoke.error(f"Couldn't find {console_path} or {msg_path}")


@core.smoke.smoke_check
def check_q5():
    if not os.path.exists('q5.html'):
        core.smoke.error('Missing q5.html')
        return
    with open('q5.html', 'r') as f:
        text = f.read()
    ok = True
    for pattern in '#announcements', 'Give Edward a Raise!':
        if not pattern in text:
            ok = False
            core.smoke.warning(f"Couldn't find {pattern!r} in q5.html - do you have a typo?")
    if ok:
        core.smoke.success('q5.html exists and has the right strings')
    else:
        print("If you have this string exactly but it's encoded, feel free to ignore this warning")


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

    with question_context('Question 1'):
        core.smoke.check_if_nonempty('q1.console')
        core.smoke.check_if_nonempty('q1.txt')

    with question_context('Question 2'):
        make_check('q2')
        core.smoke.check_if_nonempty('q2.txt')

    with question_context('Question 3'):
        make_check('q3')
        core.smoke.check_if_nonempty('q3.txt')

    with question_context('Question 4'):
        make_check('q4')
        core.smoke.check_if_nonempty('q4.txt')

    with question_context('Question 5'):
        check_q5()
        core.smoke.check_if_nonempty('q5.txt')


if __name__ == '__main__':
    smoketest()
