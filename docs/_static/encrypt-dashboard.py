#!/usr/bin/env python3
"""
Encrypt dashboard.html into a stealth version.
Output looks like a server default page but decrypts with URL hash key.

Usage: python3 encrypt-dashboard.py <input.html> <output.html> <password> [decoy]

Decoy types: apache, nginx, iis, tomcat, 404, 403, maintenance
"""

import sys
import struct
import hashlib
import random
import string

def xtea_encrypt(data, key):
    """XTEA encryption with 32 rounds."""
    DELTA = 0x9E3779B9
    k = struct.unpack('>4I', key[:16])
    padded = len(data).to_bytes(4, 'big') + data
    while len(padded) % 8 != 0:
        padded += b'\x00'
    out = bytearray(len(padded))
    for i in range(0, len(padded), 8):
        v0 = struct.unpack('>I', padded[i:i+4])[0]
        v1 = struct.unpack('>I', padded[i+4:i+8])[0]
        s = 0
        for _ in range(32):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[s & 3]))) & 0xFFFFFFFF
            s = (s + DELTA) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[(s >> 11) & 3]))) & 0xFFFFFFFF
        struct.pack_into('>I', out, i, v0)
        struct.pack_into('>I', out, i+4, v1)
    return bytes(out)

def encode_to_svg_path(hex_str):
    """Encode hex string into SVG path coordinates (steganography)."""
    parts = []
    for i, c in enumerate(hex_str):
        val = int(c, 16) + 100 + 48
        parts.append(f"L {val} {i}")
    return " ".join(parts)

def rand_id():
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(2,4)))

DECOYS = {
    'apache': lambda: f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Apache2 Ubuntu Default Page</title></head>
<body>
<style>body{{font-family:sans-serif;background:#fff;color:#000;padding:2rem}}h1{{font-size:1.6rem;color:#900;border-bottom:2px solid #900;padding-bottom:0.3rem}}p{{color:#444;font-size:0.9rem}}address{{font-style:italic;color:#888;font-size:0.8rem;border-top:1px solid #ddd;margin-top:2rem;padding-top:0.5rem}}</style>
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems. It is based on the equivalent page on Debian, from which the Ubuntu Apache packaging is derived.</p>
<p>If you can read this page, it means that the Apache HTTP server installed at this site is working properly. You should <b>replace this file</b> (located at <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.</p>
<address>Apache/2.4.{random.randint(41,62)} (Ubuntu) Server at localhost Port 80</address>''',

    'nginx': lambda: f'''<!DOCTYPE html>
<html><head><title>Welcome to nginx!</title>
<style>body{{width:35em;margin:0 auto;font-family:Tahoma,Verdana,Arial,sans-serif}}</style></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>''',

    'iis': lambda: f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"/><title>IIS Windows Server</title>
<style>body{{margin:0;background:#0078d4}}#container{{margin:50px auto;width:800px;background:#fff;padding:50px}}h1{{color:#0078d4}}img{{float:left;margin-right:20px}}</style></head>
<body><div id="container">
<img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='96' height='96'%3E%3Crect fill='%230078d4' width='96' height='96'/%3E%3Ctext x='48' y='60' text-anchor='middle' fill='white' font-size='40'%3EIIS%3C/text%3E%3C/svg%3E" alt="IIS"/>
<h1>Internet Information Services</h1>
<p>Windows Server {random.choice(['2019','2022'])}</p>
<p>The web server is operational. For configuration, use IIS Manager.</p>
</div>''',

    'tomcat': lambda: f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>Apache Tomcat/{random.randint(9,11)}.0.{random.randint(50,80)}</title></head>
<body style="font-family:Arial"><h1>Apache Tomcat</h1>
<p>If you're seeing this, you've successfully installed Tomcat. Congratulations!</p>
<p><a href="/manager/html">Manager App</a> | <a href="/host-manager/html">Host Manager</a></p>''',

    '404': lambda: f'''<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.{random.randint(41,62)} Server at localhost Port 80</address>''',

    '403': lambda: f'''<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body><h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr><address>Apache/2.4.{random.randint(41,62)} Server at localhost Port 80</address>''',

    'maintenance': lambda: f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Maintenance</title>
<style>body{{font-family:Arial,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}}
.box{{text-align:center;padding:40px;background:#fff;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}}
h1{{color:#333;margin-bottom:10px}}p{{color:#666}}</style></head>
<body><div class="box">
<h1>🔧 Under Maintenance</h1>
<p>We're currently performing scheduled maintenance.</p>
<p>Please check back in a few minutes.</p>
<p style="font-size:12px;color:#999">Est. completion: {random.randint(5,30)} minutes</p>
</div>''',
}

def create_stealth_page(encrypted_hex, svg_path, decoy_type='apache'):
    """Create stealth page with decoy content and hidden payload."""
    decoy_html = DECOYS.get(decoy_type, DECOYS['apache'])()
    r_id, p_id = rand_id(), rand_id()

    decoder_script = f'''
<div id="{r_id}" style="display:none">{encrypted_hex}</div>
<svg style="position:absolute;width:0;height:0"><path id="{p_id}" d="{svg_path}"></path></svg>
<script>
(function(){{
var _0x={chr(random.randint(97,122))+chr(random.randint(97,122))}=location.hash.slice(1);
if(!_0x.{chr(random.randint(97,122))+chr(random.randint(97,122))})return;
if(window.devtools||/./.__proto__.toString().length!==14)return;
var _=function(s){{var e=document.createElement("script");e.textContent=s;document.head.appendChild(e);}};
var d=function(x){{var p=Array.from(x.matchAll(/L (\\d+) (\\d+)/g));return p.map(function(m){{return((parseInt(m[1])-148).toString(16))}}).join("");}};
var c=async function(h,k){{
var H=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(k));
var K=new DataView(H),Q=[K.getUint32(0),K.getUint32(4),K.getUint32(8),K.getUint32(12)];
var B=new Uint8Array(h.match(/../g).map(function(x){{return parseInt(x,16)}}));
var O=new Uint8Array(B.length),V=new DataView(B.buffer),W=new DataView(O.buffer);
var D=0x9E3779B9;
for(var i=0;i<B.length;i+=8){{
var a=V.getUint32(i),b=V.getUint32(i+4),s=(D*32)>>>0;
for(var r=0;r<32;r++){{b=(b-(((a<<4^a>>>5)+a)^(s+Q[s>>>11&3])))>>>0;s=(s-D)>>>0;a=(a-(((b<<4^b>>>5)+b)^(s+Q[s&3])))>>>0;}}
W.setUint32(i,a);W.setUint32(i+4,b);
}}
var L=new DataView(O.buffer).getUint32(0);
return new TextDecoder().decode(O.slice(4,4+L));
}};
(async function(){{
try{{
var R=document.getElementById("{p_id}").getAttribute("d");
var X=d(R);
var S=await c(X,_0x.{chr(random.randint(97,122))+chr(random.randint(97,122))});
_(S);
}}catch(e){{}}
}})();
}})();
</script>
</body></html>'''

    return decoy_html + decoder_script

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 encrypt-dashboard.py <input.html> <output.html> <password> [decoy]")
        print("\nDecoy types: apache, nginx, iis, tomcat, 404, 403, maintenance")
        print("\nExample:")
        print("  python3 encrypt-dashboard.py dashboard.html stealth.html mykey nginx")
        print("\nAccess with: stealth.html#mykey")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]
    decoy_type = sys.argv[4] if len(sys.argv) > 4 else 'apache'

    with open(input_file, 'r') as f:
        html = f.read()

    script = f'document.open();document.write({repr(html)});document.close();'

    key_hash = hashlib.sha256(password.encode()).digest()
    encrypted = xtea_encrypt(script.encode(), key_hash)
    encrypted_hex = encrypted.hex()
    svg_path = encode_to_svg_path(encrypted_hex)

    output = create_stealth_page(encrypted_hex, svg_path, decoy_type)

    with open(output_file, 'w') as f:
        f.write(output)

    print(f"Encrypted: {input_file} -> {output_file}")
    print(f"Password: {password}")
    print(f"Decoy: {decoy_type}")
    print(f"Access: {output_file}#{password}")
    print(f"Size: {len(html)} -> {len(output)} bytes")

if __name__ == '__main__':
    main()
