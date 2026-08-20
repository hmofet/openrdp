#!/usr/bin/env python3
"""termsrv.dll RDP-host autopatcher - symbol-free, structural, self-verifying.

Enables the RDP *host* role on Windows client SKUs (Home/single-session Pro) by
forcing, inside CSLQuery::Initialize in termsrv.dll:
  A) IsServerSku        = 1   (the wProductType path)
  B) bRemoteConnAllowed = 1   (the Software-Licensing policy result)

bRemoteConnAllowed==0 is what makes the connection manager skip creating the
WinStations listeners, so port 3389 never binds. Forcing it (and IsServerSku)
to 1 makes the listeners bind. Same idea as RDP Wrapper, but the patch is
re-derived from the binary each run instead of read from an offset table.

Supported architectures (auto-detected from the PE machine field):
  * ARM64  (0xAA64) - an ARM64X hybrid image. Only the NATIVE ARM64 stream runs
    in a native process, so the sites are located strictly inside the CHPE
    native code range (patching the ARM64EC twin verifies but never executes).
    Pure-Python: pefile + a tiny built-in A64 decoder, no capstone.
  * x64    (0x8664) - a plain PE with one code stream. Uses capstone's x86-64
    decoder (pip install capstone; wheels ship for x64).

Why it survives a Windows Update that ships a NEW termsrv.dll: no hardcoded
offsets. Every run it re-derives both sites from stable anchors - the
GetVersionExW import, the wProductType compare, the SL policy's 0xC004F012
status, and the two CSLQuery cache-global stores. Each site's encoding is
re-checked before any byte is written, and the tool REFUSES (exit 3) rather
than guess if an anchor is ambiguous: a mis-patch of a system DLL is worse
than an unbound port.

Usage:
  termsrv_autopatch.py locate <in.dll>
  termsrv_autopatch.py patch  <in.dll> <out.dll>
Exit: 0 ok, 3 refused (ambiguous/unrecognized/unsupported).
"""
from __future__ import annotations
import sys, struct, hashlib
import pefile

MOV_W8_0 = 0x52800008      # A64: mov w8, #0
MOV_W8_1 = 0x52800028      # A64: mov w8, #1

class Refuse(Exception): ...

def u32(b, o): return int.from_bytes(b[o:o+4], "little")

# =================== shared PE helper ===================
class T:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG']])
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.machine = self.pe.FILE_HEADER.Machine
        self.data = bytearray(open(path, "rb").read())

    def roff(self, rva):
        for s in self.pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s.PointerToRawData + (rva - s.VirtualAddress)
        raise Refuse(f"rva 0x{rva:x} not mapped")

    def text_sections(self):
        for s in self.pe.sections:
            if b".text" in s.Name:
                yield s

    def import_iat_va(self, want):
        for mod in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in mod.imports:
                if imp.name and imp.name.decode("ascii", "ignore").lower() == want.lower():
                    return imp.address
        raise Refuse(f"import {want} not found")

# =================== ARM64 (A64) minimal decoder ===================
def _sxt(v, bits):
    return v - (1 << bits) if v & (1 << (bits-1)) else v

def a64(va, w):
    if (w & 0x9F000000) == 0x90000000:  # ADRP
        immlo = (w >> 29) & 3; immhi = (w >> 5) & 0x7FFFF
        return {"m":"adrp","rd":w & 0x1F,"page":(va & ~0xFFF) + (_sxt((immhi<<2)|immlo,21)<<12)}
    if ((w >> 24) & 0x3F) == 0x39:      # LDR/STR/LDRB unsigned-offset imm
        size=(w>>30)&3; opc=(w>>22)&3; imm12=(w>>10)&0xFFF
        mn={0:"str",1:"ldr"}.get(opc,"?ls")
        if size==0 and opc==1: mn="ldrb"
        return {"m":mn,"rt":w&0x1F,"rn":(w>>5)&0x1F,"disp":imm12<<size,"size":size}
    if (w & 0x7F800000) == 0x52800000:  # MOVZ (no shift)
        return {"m":"movz","rd":w&0x1F,"imm":(w>>5)&0xFFFF}
    if (w & 0xFF000010) == 0x54000000:  # B.cond
        return {"m":"bcond","cond":w&0xF}
    if (w & 0xFFFFFC1F) == 0xD61F0000:  # BR
        return {"m":"br","rn":(w>>5)&0x1F}
    if (w >> 26) in (0x25, 0x05):       # BL / B
        return {"m":"bl" if (w>>26)==0x25 else "b","target":va + _sxt(w&0x03FFFFFF,26)*4}
    return {"m":"?","w":w}

def _arm64_native_range(t: T):
    lc = t.pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
    chpe = getattr(lc, "CHPEMetadataPointer", 0)
    if not chpe:
        raise Refuse("ARM64 image without CHPE metadata - not the ARM64X termsrv.dll expected")
    off = t.roff(chpe - t.base)
    ver, cm_rva, cnt = struct.unpack_from("<III", t.data, off)
    cmoff = t.roff(cm_rva); best = None
    for i in range(cnt):
        entry, length = struct.unpack_from("<II", t.data, cmoff + i*8)
        if entry & 3 == 0:  # ARM64 native
            start = entry & ~3
            if best is None or length > best[1]-best[0]:
                best = (start, start+length)
    if not best:
        raise Refuse("no native ARM64 code range in CHPE map")
    return t.base+best[0], t.base+best[1]

def _arm64_iter(t, s):
    soff=s.PointerToRawData; srva=s.VirtualAddress
    n=max(s.Misc_VirtualSize,s.SizeOfRawData)&~3
    for i in range(0,n,4):
        yield t.base+srva+i, u32(t.data, soff+i)

def _arm64_getversion_thunks(t):
    iat=t.import_iat_va("GetVersionExW"); out=[]
    for s in t.text_sections():
        win=[]
        for va,w in _arm64_iter(t,s):
            d=a64(va,w); d["_va"]=va; win.append(d)
            if len(win)>3: win.pop(0)
            if len(win)==3:
                a,l,b=win
                if (a["m"]=="adrp" and l["m"]=="ldr" and b["m"]=="br"
                    and l["rn"]==a["rd"] and l["rt"]==a["rd"] and b["rn"]==a["rd"]
                    and a["page"]+l["disp"]==iat):
                    out.append(a["_va"])
    return sorted(set(out))

def _arm64_decode_from(t, va, count):
    off=t.roff(va-t.base); out=[]
    for i in range(count):
        w=u32(t.data, off+i*4); d=a64(va+i*4,w); d["_va"]=va+i*4; d["_w"]=w; out.append(d)
    return out

def _arm64_try_match(t, call_va):
    ins=_arm64_decode_from(t, call_va, 0x100); base=t.base
    site_a=None
    for i,d in enumerate(ins):
        if d["m"]=="ldrb" and d.get("rn")==31:               # ldrb w?,[sp,#wProductType]
            for j in range(i+1, min(i+10,len(ins))):
                if ins[j]["m"]=="bcond" and ins[j]["cond"]==1:   # b.ne
                    for k in range(j+1, min(j+4,len(ins))):
                        if ins[k]["_w"]==MOV_W8_0: site_a=ins[k]["_va"]; break
                    break
            if site_a: break
    if site_a is None: return None
    pages={}; iss=None
    for d in ins:
        if d["m"]=="adrp": pages[d["rd"]]=d["page"]
        elif d["m"]=="str" and d["_va"]>site_a and d.get("rn") in pages:
            iss=pages[d["rn"]]+d["disp"]; break
    if iss is None: return None
    rca=iss-0x14
    pages={}; last=None; site_b=None
    for d in ins:
        if d["m"]=="adrp": pages[d["rd"]]=d["page"]
        elif d["m"]=="ldr" and d.get("rn")==31 and d.get("rt")==8: last=d
        elif d["m"]=="str" and d.get("rn") in pages and pages[d["rn"]]+d["disp"]==rca:
            if last is not None: site_b=last["_va"]
            break
    return dict(func=call_va, site_a=site_a, site_b=site_b, iss=iss, rca=rca)

def find_arm64(t: T):
    nlo, nhi = _arm64_native_range(t)
    thunks = _arm64_getversion_thunks(t)
    if not thunks: raise Refuse("could not resolve GetVersionExW thunk")
    callers=[va for s in t.text_sections() for va,w in _arm64_iter(t,s)
             if (w>>26)==0x25 and a64(va,w)["target"] in set(thunks) and nlo<=va<nhi]
    if not callers: raise Refuse("no native ARM64 caller of GetVersionExW")
    matches=[m for c in callers if (m:=_arm64_try_match(t,c))]
    full=[m for m in matches if m["site_b"] is not None]
    if len(full)!=1: raise Refuse(f"ambiguous/none: {len(full)} full ARM64 matches")
    m=full[0]
    # shape verify
    if u32(t.data, t.roff(m["site_a"]-t.base)) != MOV_W8_0:
        raise Refuse("ARM64 site A not mov w8,#0")
    wb=u32(t.data, t.roff(m["site_b"]-t.base)); db=a64(m["site_b"], wb)
    if not (db["m"]=="ldr" and db.get("rn")==31 and db.get("rt")==8):
        raise Refuse("ARM64 site B not ldr w8,[sp]")
    patches=[
        {"rva":m["site_a"]-t.base, "orig":struct.pack("<I",MOV_W8_0), "new":struct.pack("<I",MOV_W8_1),
         "desc":"IsServerSku: mov w8,#0 -> mov w8,#1"},
        {"rva":m["site_b"]-t.base, "orig":struct.pack("<I",wb),        "new":struct.pack("<I",MOV_W8_1),
         "desc":"bRemoteConnAllowed: ldr w8,[sp] -> mov w8,#1"},
    ]
    return dict(arch="arm64", func_rva=m["func"]-t.base, iss=m["iss"], rca=m["rca"], patches=patches)

# =================== x64 (via capstone) ===================
def find_x64(t: T):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        from capstone import x86 as X
    except ImportError:
        raise Refuse("x64 target needs capstone (pip install capstone)")
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True; md.skipdata = True
    MEM, IMM, REG = X.X86_OP_MEM, X.X86_OP_IMM, X.X86_OP_REG
    RIP, RSP = X.X86_REG_RIP, X.X86_REG_RSP
    iat = t.import_iat_va("GetVersionExW")

    def window(va, n):
        off = t.roff(va - t.base)
        return [i for i in md.disasm(bytes(t.data[off:off+n]), va) if i.id != 0]

    callers = []
    for s in t.text_sections():
        code = bytes(t.data[s.PointerToRawData: s.PointerToRawData + max(s.Misc_VirtualSize, s.SizeOfRawData)])
        for ins in md.disasm(code, t.base + s.VirtualAddress):
            if ins.id == 0:
                continue
            if ins.mnemonic == "call" and len(ins.operands) == 1 and ins.operands[0].type == MEM:
                m = ins.operands[0].mem
                if m.base == RIP and ins.address + ins.size + m.disp == iat:
                    callers.append(ins.address)
    if not callers:
        raise Refuse("no x64 caller of GetVersionExW")

    def is_movimm0_rsp(o):
        return (o.mnemonic == "mov" and o.bytes and o.bytes[0] == 0xC7 and len(o.operands) == 2
                and o.operands[0].type == MEM and o.operands[0].mem.base == RSP
                and o.operands[1].type == IMM and o.operands[1].imm == 0)

    def try_match(call_va):
        ins = window(call_va, 0x900)
        # PATCH A: movzx r,byte[rsp] -> cmp r,1 -> jne -> mov dword[rsp+A],0
        site_a = None
        for i, d in enumerate(ins):
            if d.mnemonic == "movzx" and len(d.operands) == 2 and d.operands[1].type == MEM and d.operands[1].mem.base == RSP:
                for j in range(i+1, min(i+8, len(ins))):
                    if ins[j].mnemonic == "cmp" and any(op.type == IMM and op.imm == 1 for op in ins[j].operands):
                        for k in range(j+1, min(j+4, len(ins))):
                            if ins[k].mnemonic in ("jne", "jnz"):
                                for l in range(k+1, min(k+5, len(ins))):
                                    if is_movimm0_rsp(ins[l]): site_a = ins[l]; break
                                break
                        break
                if site_a: break
        if site_a is None: return None
        # IsServerSku store: first mov [rip+G], reg after site_a
        iss = None
        for d in ins:
            if d.address > site_a.address and d.mnemonic == "mov" and len(d.operands) == 2 \
               and d.operands[0].type == MEM and d.operands[0].mem.base == RIP and d.operands[1].type == REG:
                iss = d.address + d.size + d.operands[0].mem.disp; break
        # PATCH B: first cmp ...,0xC004F012 -> first mov[rip+RCA],reg -> feeder mov reg,[rsp+B] -> mov dword[rsp+B],0
        magic = next((i for i, d in enumerate(ins)
                      if d.mnemonic == "cmp" and any(op.type == IMM and (op.imm & 0xFFFFFFFF) == 0xC004F012 for op in d.operands)), None)
        if magic is None: return None
        rca_i = rca = srcreg = None
        for i in range(magic, len(ins)):
            d = ins[i]
            if d.mnemonic == "mov" and len(d.operands) == 2 and d.operands[0].type == MEM \
               and d.operands[0].mem.base == RIP and d.operands[1].type == REG:
                rca_i = i; rca = d.address + d.size + d.operands[0].mem.disp; srcreg = d.operands[1].reg; break
        if rca_i is None: return None
        slotB = None
        for i in range(rca_i-1, max(rca_i-5, -1), -1):
            d = ins[i]
            if d.mnemonic == "mov" and len(d.operands) == 2 and d.operands[0].type == REG and d.operands[0].reg == srcreg \
               and d.operands[1].type == MEM and d.operands[1].mem.base == RSP:
                slotB = d.operands[1].mem.disp; break
        if slotB is None: return None
        site_b = None
        for i in range(rca_i-1, max(rca_i-9, -1), -1):
            d = ins[i]
            if is_movimm0_rsp(d) and d.operands[0].mem.disp == slotB: site_b = d; break
        if site_b is None: return None
        return dict(func=call_va, site_a=site_a, site_b=site_b, iss=iss, rca=rca)

    matches = [m for c in callers if (m := try_match(c))]
    full = [m for m in matches if m["site_b"] is not None]
    if len(full) != 1:
        raise Refuse(f"ambiguous/none: {len(full)} full x64 matches")
    m = full[0]
    patches = []
    for ins, desc in ((m["site_a"], "IsServerSku: mov dword[rsp],0 -> 1"),
                      (m["site_b"], "bRemoteConnAllowed: mov dword[rsp],0 -> 1")):
        imm_rva = ins.address - t.base + ins.size - 4     # imm32 is the last 4 bytes of C7 /0 id
        if u32(t.data, t.roff(imm_rva)) != 0:
            raise Refuse(f"x64 site @0x{ins.address-t.base:x} imm32 not 0 - shape changed")
        patches.append({"rva": imm_rva, "orig": b"\x00\x00\x00\x00", "new": b"\x01\x00\x00\x00", "desc": desc})
    return dict(arch="x64", func_rva=m["func"]-t.base, iss=m["iss"], rca=m["rca"], patches=patches)

# =================== driver ===================
def analyze(t: T):
    if t.machine == 0xAA64:
        return find_arm64(t)
    if t.machine == 0x8664:
        return find_x64(t)
    raise Refuse(f"unsupported machine 0x{t.machine:x} (need ARM64 0xAA64 or x64 0x8664)")

def report(s):
    print(f"arch={s['arch']}  CSLQuery::Initialize @ RVA 0x{s['func_rva']:x}")
    print(f"  IsServerSku global        @ 0x{s['iss']:x}")
    print(f"  bRemoteConnAllowed global @ 0x{s['rca']:x}")
    for i, p in enumerate(s["patches"]):
        print(f"  PATCH {'AB'[i]} @ RVA 0x{p['rva']:x}  ({p['desc']})")

def apply(t: T, s):
    for p in s["patches"]:
        off = t.roff(p["rva"]); cur = bytes(t.data[off:off+len(p["orig"])])
        if cur != p["orig"]:
            raise Refuse(f"pre-write mismatch @0x{p['rva']:x}: {cur.hex()} != {p['orig'].hex()}")
        t.data[off:off+len(p["new"])] = p["new"]
    for p in s["patches"]:
        off = t.roff(p["rva"])
        if bytes(t.data[off:off+len(p["new"])]) != p["new"]:
            raise Refuse(f"post-write verify failed @0x{p['rva']:x}")

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    cmd = sys.argv[1]; t = T(sys.argv[2]); s = analyze(t); report(s)
    if cmd == "locate":
        print("OK (located, nothing written)"); return 0
    if cmd != "patch":
        raise Refuse(f"unknown command {cmd}")
    apply(t, s)
    out = sys.argv[3]; open(out, "wb").write(t.data)
    print(f"wrote {out}  sha256={hashlib.sha256(t.data).hexdigest().upper()}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refuse as e:
        print(f"REFUSE: {e}", file=sys.stderr); sys.exit(3)
