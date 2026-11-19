import r2pipe as r2p
import json
from pwn import ELF

p = r2p.open()

# Enter the library ur binary's using here
lib_name = "your_library_here.so"

lib = ELF(lib_name)

symbol_list = lib.symbols

# start dbg mode by stopping at main

p.cmd("dcu main")

symbols = p.cmdj(f"dmij {lib_name}") or []

functions = {}
objects = {}

for tgt_func in symbol_list:
    target = next(
        ((sym["vaddr"], sym["type"]) for sym in symbols if tgt_func in sym.get("name", "")),
        None
    )
    if target:
        target_addr = target[0]
        if target[1] == "FUNC":
            print(f"[+] Found function {tgt_func} at {hex(target_addr)}")
            p.cmd(f"af twil.{tgt_func} @ {target_addr}")
            functions[f"twil.{tgt_func}"] = hex(target_addr)
        elif target[1] == "OBJ":
            print(f"[+] Found object {tgt_func} at {hex(target_addr)}")
            p.cmd(f"f twil.{tgt_func} @ {target_addr}")
            objects[f"twil.{tgt_func}"] = hex(target_addr)
        else:
            print(f"[=] Found symbol {tgt_func} of type {target[1]}, ignoring...")
    else:
        print(f"[-] Couldn't find {tgt_func} in the library {lib_name}")

print("Functions\n", json.dumps(functions, indent=4))
print("Objects\n", json.dumps(objects, indent=4))
