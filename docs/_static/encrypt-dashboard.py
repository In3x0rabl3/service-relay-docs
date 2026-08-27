#!/usr/bin/env python3
"""
Encrypt dashboard.html into a stealth version.
Output looks like an Apache default page but decrypts with URL hash key.

Usage: python3 encrypt-dashboard.py <input.html> <output.html> <password>
"""

import sys
import struct
import hashlib
import os

def xtea_encrypt(data, key):
    """XTEA encryption with 32 rounds."""
    DELTA = 0x9E3779B9
    k = struct.unpack('>4I', key[:16])

    # Pad to 8-byte boundary
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
        val = int(c, 16) + 100 + 48  # offset to make valid coords
        parts.append(f"L {val} {i}")
    return " ".join(parts)

def create_decoy_page(encrypted_hex, svg_path):
    """Create Apache-looking decoy page with hidden payload."""
    return f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>Apache2 Ubuntu Default Page</title>
</head>
<body>
<style>body{{font-family:sans-serif;background:#fff;color:#000;padding:2rem}}h1{{font-size:1.6rem;color:#900;border-bottom:2px solid #900;padding-bottom:0.3rem}}p{{color:#444;font-size:0.9rem}}address{{font-style:italic;color:#888;font-size:0.8rem;border-top:1px solid #ddd;margin-top:2rem;padding-top:0.5rem}}</style>
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
<address>Apache/2.4.57 (Ubuntu) Server at localhost Port 80</address>
<div id="__r" style="display:none">{encrypted_hex}</div>
<svg style="display:none"><path id="__p" d="{svg_path}"></path></svg>
<script>
(async function(){{
var key=location.hash.slice(1);
if(!key)return;
function _exec(s){{var e=document.createElement("script");e.textContent=s;document.head.appendChild(e);}}
function decode(d){{var pts=Array.from(d.matchAll(/L (\\d+) (\\d+)/g));return pts.map(m=>((parseInt(m[1])-148).toString(16))).join("");}}
async function decrypt(h,k){{
var hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(k));
var kv=new DataView(hash),keys=[kv.getUint32(0),kv.getUint32(4),kv.getUint32(8),kv.getUint32(12)];
var b=new Uint8Array(h.match(/../g).map(x=>parseInt(x,16)));
var out=new Uint8Array(b.length),dv=new DataView(b.buffer),ov=new DataView(out.buffer);
var D=0x9E3779B9;
for(var i=0;i<b.length;i+=8){{
var v0=dv.getUint32(i),v1=dv.getUint32(i+4),s=(D*32)>>>0;
for(var r=0;r<32;r++){{v1=(v1-(((v0<<4^v0>>>5)+v0)^(s+keys[s>>>11&3])))>>>0;s=(s-D)>>>0;v0=(v0-(((v1<<4^v1>>>5)+v1)^(s+keys[s&3])))>>>0;}}
ov.setUint32(i,v0);ov.setUint32(i+4,v1);
}}
var len=new DataView(out.buffer).getUint32(0);
return new TextDecoder().decode(out.slice(4,4+len));
}}
var raw=document.getElementById("__p").getAttribute("d");
var hex=decode(raw);
var src=await decrypt(hex,key);
_exec(src);
}})();
</script>
</body></html>'''

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 encrypt-dashboard.py <input.html> <output.html> <password>")
        print("\nExample:")
        print("  python3 encrypt-dashboard.py dashboard.html stealth.html mysecretkey")
        print("\nAccess with: stealth.html#mysecretkey")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]

    # Read input
    with open(input_file, 'r') as f:
        html = f.read()

    # Extract just the script content (or wrap entire HTML)
    # For simplicity, we'll encrypt the entire HTML and inject it
    script = f'document.open();document.write({repr(html)});document.close();'

    # Encrypt
    key_hash = hashlib.sha256(password.encode()).digest()
    encrypted = xtea_encrypt(script.encode(), key_hash)
    encrypted_hex = encrypted.hex()

    # Encode to SVG path
    svg_path = encode_to_svg_path(encrypted_hex)

    # Create output
    output = create_decoy_page(encrypted_hex, svg_path)

    with open(output_file, 'w') as f:
        f.write(output)

    print(f"Encrypted: {input_file} -> {output_file}")
    print(f"Password: {password}")
    print(f"Access URL: {output_file}#{password}")
    print(f"Original size: {len(html)} bytes")
    print(f"Encrypted size: {len(output)} bytes")

if __name__ == '__main__':
    main()
