#!/usr/bin/env python3
# coding: utf-8
'''
Use this script to solve the collision challenge on http://pwnable.kr/play.php.

Due to nature of challenge, your solved hash collision will likely be different.
'''
import angr #the main framework
import claripy #the solver engine
import signal
import logging
import os
import codecs
import hexdump

script_directory = os.path.dirname(os.path.realpath(__file__))

logging.getLogger('angr.manager').setLevel(logging.DEBUG)

def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()

signal.signal(signal.SIGINT, sigint_handler)

# col-dyn-32 is a locally compiled version of the binary on the server.
proj = angr.Project(script_directory + "/col-dyn", auto_load_libs=False)

argv = [proj.filename]   #argv[0]
sym_arg_size = 20   #max number of bytes we'll try to solve for
sym_arg = claripy.BVS('sym_arg', 8*sym_arg_size)
argv.append(sym_arg)    #argv[1]

'''
At this point rdi will contain user input that satifies SMT
'''
find_addr = 0x401234

'''
These avoid addresses were obtained after disassembling binary in binja
'''
avoid_addr = [0x40124c, 0x4011c4, 0x4011ff]

main=0x4011af # entry point

state = proj.factory.blank_state(addr=main,add_options={angr.options.LAZY_SOLVES})
simgr = proj.factory.simulation_manager(state)

simgr.explore(find=find_addr,avoid=avoid_addr)

'''
found will contain a successful simulation object that will contain a user input
that satisfies the check_password function.
'''
found = simgr.found[0]


'''
When observing the binary running in gdb, it becomes apparent that the user input
can be obtained through a pointer in rdi register.
'''
mem_pointer1 = found.mem[found.regs.rdi]

'''eval allows us to derefence and save value into python variable.'''
hash_chunk_1 = found.solver.eval( mem_pointer1.uint64_t.resolved, cast_to=bytes)
'''Reverse order the bytes'''
passcode = codecs.encode(hash_chunk_1[::-1],'hex')

mem_pointer2 = found.mem[found.regs.rdi+8]
hash_chunk_2 = found.solver.eval( mem_pointer2.uint64_t.resolved, cast_to=bytes)
passcode += codecs.encode(hash_chunk_2[::-1],'hex')

mem_pointer3 = found.mem[found.regs.rdi+8+8]
hash_chunk_3 = found.solver.eval( mem_pointer3.uint64_t.resolved, cast_to=bytes)
passcode += codecs.encode(hash_chunk_3[:3:-1],'hex')

passcode_bytes = bytes.fromhex(passcode.decode())

hexdump.hexdump(passcode_bytes)

print('Passcode is {}.'.format(passcode))

'''
Now we submit the challenge to obtain the flag.

$ ssh col@pwnable.kr -p2222
The authenticity of host '[pwnable.kr]:2222 ([143.248.249.64]:2222)' can't be established.
ECDSA key fingerprint is SHA256:kWTx0QCL5U5VbUkQa1x5/dw8hJ6DS5CR0KilMRJnUYY.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '[pwnable.kr]:2222,[143.248.249.64]:2222' (ECDSA) to the list of known hosts.
col@pwnable.kr's password:
 ____  __    __  ____    ____  ____   _        ___      __  _  ____
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    /
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|

- Site admin : daehee87.kr@gmail.com
- IRC : irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
Last login: Thu Oct 11 20:45:35 2018 from 207.148.113.134
col@ubuntu:~$ arg1=$(perl -e 'printf "\xc9\xc9\x6d\x2c\x80\xef\x39\x95\xa0\xae\xaf\x28\x40\x22\x90\x59\xc3\x7f\xf5\xdd"')
col@ubuntu:~$ ./col "arg1"
daddy! I just managed to create a hash collision :)
'''
