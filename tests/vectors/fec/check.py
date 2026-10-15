import subprocess, sys

POLY = 285  # from nanors deps/obl/gf2_8_tables.h: "generated with polynomial: 285"

# Build GF(2^8) log/exp from scratch -- no tables copied from nanors.
exp = [0]*512; log = [0]*256
x = 1
for i in range(255):
    exp[i] = x
    log[x] = i
    x <<= 1
    if x & 0x100: x ^= POLY
for i in range(255, 512): exp[i] = exp[i-255]

def mul(a, b):
    if a == 0 or b == 0: return 0
    return exp[log[a] + log[b]]
def inv(a):
    return exp[255 - log[a]]

def matrix(ds, ps):
    # nanors rs.c: row[i] = GF2_8_INV[(ps + i) ^ j]   -- a Cauchy matrix
    return [[inv((ps + i) ^ j) for i in range(ds)] for j in range(ps)]

def encode(ds, ps, bs):
    P = matrix(ds, ps)
    data = [[(k*31 + b*7 + 11) & 0xFF for b in range(bs)] for k in range(ds)]
    parity = []
    for j in range(ps):
        row = [0]*bs
        for i in range(ds):
            c = P[j][i]
            if c:
                di = data[i]
                for b in range(bs): row[b] ^= mul(c, di[b])
        parity.append(row)
    return P, parity

def run_c(ds, ps, bs):
    out = subprocess.run(["/tmp/fec-dump", str(ds), str(ps), str(bs)],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    i = out.index(f"MATRIX {ds} {ps}")
    M = [[int(v) for v in out[i+1+j].split()] for j in range(ps)]
    i = out.index(f"PARITY {ds} {ps} {bs}")
    Pa = [[int(v) for v in out[i+1+j].split()] for j in range(ps)]
    return M, Pa

cases = [(6,3,8), (1,2,32), (5,2,64), (212,42,96), (255-20,20,128), (100,20,1392+16)]
ok = True
for ds, ps, bs in cases:
    cM, cP = run_c(ds, ps, bs)
    pM, pP = encode(ds, ps, bs)
    m_ok, p_ok = (cM == pM), (cP == pP)
    ok &= m_ok and p_ok
    print(f"ds={ds:<4} ps={ps:<3} bs={bs:<5} matrix={'MATCH' if m_ok else 'DIFFER'}  parity={'MATCH' if p_ok else 'DIFFER'}")
print("\nALL MATCH" if ok else "\nMISMATCH")
