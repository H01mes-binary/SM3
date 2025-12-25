import struct
import os
import random
import time
import argparse
import subprocess
import tempfile
import tracemalloc

# ======================================================
# SM3 算法实现（纯标准库）
# ======================================================

IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
]

def rotl(x, n):
    x &= 0xffffffff
    n &= 31
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def P0(x): return x ^ rotl(x, 9) ^ rotl(x, 17)
def P1(x): return x ^ rotl(x, 15) ^ rotl(x, 23)

def FF(x, y, z, j):
    return x ^ y ^ z if j <= 15 else (x & y) | (x & z) | (y & z)

def GG(x, y, z, j):
    return x ^ y ^ z if j <= 15 else (x & y) | (~x & z)

def padding(data: bytes):
    bit_len = len(data) * 8
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    data += struct.pack(">Q", bit_len)
    return data

def sm3_hash(data: bytes) -> str:
    data = padding(data)
    V = IV[:]

    for i in range(0, len(data), 64):
        B = data[i:i + 64]
        W = [0] * 68
        W1 = [0] * 64

        for j in range(16):
            W[j] = struct.unpack(">I", B[j*4:(j+1)*4])[0]
        for j in range(16, 68):
            W[j] = (P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15))
                    ^ rotl(W[j-13], 7) ^ W[j-6]) & 0xffffffff
        for j in range(64):
            W1[j] = W[j] ^ W[j+4]

        A, B_, C, D, E, F, G, H = V

        for j in range(64):
            T = 0x79CC4519 if j <= 15 else 0x7A879D8A
            SS1 = rotl((rotl(A, 12) + E + rotl(T, j)) & 0xffffffff, 7)
            SS2 = SS1 ^ rotl(A, 12)
            TT1 = (FF(A, B_, C, j) + D + SS2 + W1[j]) & 0xffffffff
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
            D, C, B_, A = C, rotl(B_, 9), A, TT1
            H, G, F, E = G, rotl(F, 19), E, P0(TT2)

        V = [(V[k] ^ x) & 0xffffffff for k, x in enumerate([A,B_,C,D,E,F,G,H])]

    return ''.join(f'{x:08x}' for x in V)

# ======================================================
# OpenSSL 调用
# ======================================================

def openssl_sm3(data: bytes) -> str:
    """
    真实调用 OpenSSL 计算 SM3
    """
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        fname = f.name

    try:
        result = subprocess.check_output(
            ["openssl", "dgst", "-sm3", fname],
            stderr=subprocess.STDOUT
        ).decode()
        return result.strip().split("= ")[-1]
    finally:
        os.remove(fname)

# ======================================================
# 输出工具
# ======================================================

def log(msg):
    print(msg, flush=True)

def line():
    print("-" * 80)

# ======================================================
# 自动化测试
# ======================================================

def correctness_tests():
    line()
    log("【正确性验证（OpenSSL 对比）】")

    cases = [
        ("空字符串", b""),
        ("abc", b"abc"),
        ("超长字符串", b"abcd" * 16)
    ]

    for name, data in cases:
        my = sm3_hash(data)
        ref = openssl_sm3(data)
        log(f"[{name}]")
        log(f"  自研 SM3 : {my}")
        log(f"  OpenSSL  : {ref}")
        log(f"  是否一致: {my == ref}")
        line()

def boundary_tests():
    line()
    log("【边界用例验证】")

    # 空文件
    open("empty.txt", "wb").close()
    data = open("empty.txt", "rb").read()
    log("空文件:")
    log(f"  自研   : {sm3_hash(data)}")
    log(f"  OpenSSL: {openssl_sm3(data)}")

    # 1 字节
    data = b"a"
    log("1 字节输入:")
    log(f"  自研   : {sm3_hash(data)}")

    # 448bit
    data = b"a" * 56
    log("448bit 输入:")
    log(f"  自研   : {sm3_hash(data)}")

    # 多分组
    data = os.urandom(1024)
    log("1024 字节随机输入:")
    log(f"  自研   : {sm3_hash(data)[:64]}...")

def collision_test(n=10000):
    line()
    log(f"【抗碰撞测试】样本数={n}")
    table = {}
    for i in range(n):
        data = os.urandom(random.randint(16, 256))
        h = sm3_hash(data)
        if h in table and table[h] != data:
            log("❌ 发现碰撞")
            return
        table[h] = data
    log("✅ 未发现碰撞")

def avalanche_test():
    line()
    log("【雪崩效应测试】")
    base = b"sm3_avalanche_test_2024"
    H0 = sm3_hash(base)
    total = 0

    for i in range(5):
        m = bytearray(base)
        m[i] ^= 1 << (i % 8)
        H1 = sm3_hash(bytes(m))
        diff = sum(a != b for a, b in zip(
            bin(int(H0,16))[2:].zfill(256),
            bin(int(H1,16))[2:].zfill(256)
        ))
        total += diff
        log(f"第{i+1}次：差异比特数 = {diff}")

    log(f"平均差异比特数 = {total / 5:.2f}")

def performance_test():
    line()
    log("【性能测试】")
    sizes = [16, 1024, 10*1024, 100*1024, 1024*1024]

    for size in sizes:
        data = os.urandom(size)
        times = []
        tracemalloc.start()

        for _ in range(5):
            t0 = time.perf_counter()
            sm3_hash(data)
            times.append((time.perf_counter() - t0) * 1000)

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        avg = sum(times) / len(times)
        tp = (size / 1024 / 1024) / (avg / 1000)
        log(f"{size}B | 平均耗时 {avg:.2f} ms | 吞吐量 {tp:.2f} MB/s | 内存 {peak/1024:.1f} KB")

# ======================================================
# CLI
# ======================================================

def main():
    parser = argparse.ArgumentParser(description="SM3 哈希算法命令行工具（含 OpenSSL 验证）")
    parser.add_argument("-s", "--string", help="计算字符串 SM3")
    parser.add_argument("-f", "--file", help="计算文件 SM3")
    parser.add_argument("--auto-test", action="store_true", help="执行全部自动化测试")
    args = parser.parse_args()

    if args.string is not None:
        log(sm3_hash(args.string.encode()))
    elif args.file:
        log(sm3_hash(open(args.file, "rb").read()))
    elif args.auto_test:
        correctness_tests()
        boundary_tests()
        collision_test()
        avalanche_test()
        performance_test()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
