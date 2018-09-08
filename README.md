# Writeup for exp200_defcamp2015_da61746febd7112be5b04437f6f17f5f0c37c384

Disclaimer: This update to @jvoisin code allows to target any libc, and also provides a database for important offsets of all libc versions

## Identify libc

Okay first we need to identify the libc, the only requirement is the file path.

What we will do is compute the sha1 hash of the libc

Import Section:

```python
import r2pipe
```

Code Section:

```python
r = r2pipe.open(libc_path)
hash_value=r.cmd("e file.sha1")
print('[+] libc sha1 %s' % hash_value)
```

When we got the sha1 of the libc we will query the DB:

```python
from tinydb import TinyDB, Query
```

Code Section:

```python
db = TinyDB('fingerprints/db.json')
table = db.table('hashes')
Hash = Query()
result = table.search(Hash.hash == hash_value)
libc_id = result[0]['lib']
print('[+] libc fingerprint found -> id %s' % libc_id)
```

And we have the id of our libc

## Get the offsets

Now that we have the offsets we just have to query the db for the offsets and extract them from the result:

``python
from tinydb import TinyDB, Query
```

Code Section:

```python
table = db.table('offsets')
Offsets = Query()
result = table.search(Offsets.lib == libc_id)
print('[+] libc start %s' % result[0]['__libc_start_main_ret'])
print('[+] libc system %s' % result[0]['system'])
print('[+] libc read %s' % result[0]['read'])
print('[+] libc write %s' % result[0]['write'])
print('[+] libc bin sh offsets %s' % result[0]['str_bin_sh'])
```


And voila, profit!