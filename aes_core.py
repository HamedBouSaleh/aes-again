SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
])

RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def bytes_to_state(block: bytes) -> list[list[int]]:
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes")
    state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = block[c * 4 + r]
    return state


def state_to_bytes(state: list[list[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))


def state_copy(state: list[list[int]]) -> list[list[int]]:
    return [row[:] for row in state]


def sub_bytes(state: list[list[int]], inverse: bool = False) -> None:
    box = INV_SBOX if inverse else SBOX
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def shift_rows(state: list[list[int]], inverse: bool = False) -> None:
    if inverse:
        state[1] = [state[1][3], state[1][0], state[1][1], state[1][2]]
        state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
        state[3] = [state[3][1], state[3][2], state[3][3], state[3][0]]
    else:
        state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
        state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
        state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]


def _gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def mix_columns(state: list[list[int]], inverse: bool = False) -> None:
    if inverse:
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = _gf_mul(0x0e, s0) ^ _gf_mul(0x0b, s1) ^ _gf_mul(0x0d, s2) ^ _gf_mul(0x09, s3)
            state[1][c] = _gf_mul(0x09, s0) ^ _gf_mul(0x0e, s1) ^ _gf_mul(0x0b, s2) ^ _gf_mul(0x0d, s3)
            state[2][c] = _gf_mul(0x0d, s0) ^ _gf_mul(0x09, s1) ^ _gf_mul(0x0e, s2) ^ _gf_mul(0x0b, s3)
            state[3][c] = _gf_mul(0x0b, s0) ^ _gf_mul(0x0d, s1) ^ _gf_mul(0x09, s2) ^ _gf_mul(0x0e, s3)
    else:
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = _gf_mul(2, s0) ^ _gf_mul(3, s1) ^ s2 ^ s3
            state[1][c] = s0 ^ _gf_mul(2, s1) ^ _gf_mul(3, s2) ^ s3
            state[2][c] = s0 ^ s1 ^ _gf_mul(2, s2) ^ _gf_mul(3, s3)
            state[3][c] = _gf_mul(3, s0) ^ s1 ^ s2 ^ _gf_mul(2, s3)


def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def key_expansion(key: bytes) -> list[list[list[int]]]:
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes (128 bits)")
    w = [0] * 44
    for i in range(4):
        w[i] = int.from_bytes(key[i * 4:(i + 1) * 4], 'big')
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((t << 8) | (t >> 24)) & 0xffffffff
            t = (SBOX[(t >> 24) & 0xff] << 24 |
                 SBOX[(t >> 16) & 0xff] << 16 |
                 SBOX[(t >> 8) & 0xff] << 8 |
                 SBOX[t & 0xff])
            t ^= (RCON[i // 4] << 24)
        w[i] = w[i - 4] ^ t
    round_keys = []
    for rnd in range(11):
        rk = [[0] * 4 for _ in range(4)]
        for col in range(4):
            word = w[rnd * 4 + col]
            for row in range(4):
                rk[row][col] = (word >> (24 - row * 8)) & 0xff
        round_keys.append(rk)
    return round_keys


def words_to_hex_words(round_keys: list[list[list[int]]]) -> list[list[str]]:
    result = []
    for rk in round_keys:
        group = []
        for c in range(4):
            word = (rk[0][c] << 24) | (rk[1][c] << 16) | (rk[2][c] << 8) | rk[3][c]
            group.append(f"{word:08x}")
        result.append(group)
    return result


def encrypt_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: list[list[list[int]]]) -> bytes:
    state = bytes_to_state(block)
    add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        shift_rows(state, inverse=True)
        sub_bytes(state, inverse=True)
        add_round_key(state, round_keys[rnd])
        mix_columns(state, inverse=True)
    shift_rows(state, inverse=True)
    sub_bytes(state, inverse=True)
    add_round_key(state, round_keys[0])
    return state_to_bytes(state)


def encrypt_block_with_rounds(block: bytes, round_keys: list[list[list[int]]]) -> list[list[list[int]]]:
    states = []
    state = bytes_to_state(block)
    add_round_key(state, round_keys[0])
    states.append(state_copy(state))
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])
        states.append(state_copy(state))
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    states.append(state_copy(state))
    return states


def decrypt_block_with_rounds(block: bytes, round_keys: list[list[list[int]]]) -> list[list[list[int]]]:
    states = []
    state = bytes_to_state(block)
    add_round_key(state, round_keys[10])
    states.append(state_copy(state))
    for rnd in range(9, 0, -1):
        shift_rows(state, inverse=True)
        sub_bytes(state, inverse=True)
        add_round_key(state, round_keys[rnd])
        mix_columns(state, inverse=True)
        states.append(state_copy(state))
    shift_rows(state, inverse=True)
    sub_bytes(state, inverse=True)
    add_round_key(state, round_keys[0])
    states.append(state_copy(state))
    return states


def one_round_steps(block: bytes, round_keys: list[list[list[int]]], round_index: int) -> list[tuple[str, list[list[int]]]]:
    state = bytes_to_state(block)
    steps = []
    if round_index == 0:
        add_round_key(state, round_keys[0])
        steps.append(("AddRoundKey (Round 0)", state_copy(state)))
        return steps

    add_round_key(state, round_keys[0])
    for rnd in range(1, round_index):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[rnd])

    steps.append((f"Initial state (after Round {round_index - 1})", state_copy(state)))
    sub_bytes(state)
    steps.append(("SubBytes", state_copy(state)))
    shift_rows(state)
    steps.append(("ShiftRows", state_copy(state)))
    if round_index < 10:
        mix_columns(state)
        steps.append(("MixColumns", state_copy(state)))
    add_round_key(state, round_keys[round_index])
    steps.append(("AddRoundKey", state_copy(state)))
    return steps


def bit_mismatch(a: list[list[int]], b: list[list[int]]) -> int:
    count = 0
    for r in range(4):
        for c in range(4):
            x = a[r][c] ^ b[r][c]
            while x:
                count += x & 1
                x >>= 1
    return count


def state_to_hex_grid(state: list[list[int]]) -> str:
    lines = []
    for r in range(4):
        line = " ".join(f"{state[r][c]:02x}" for c in range(4))
        lines.append(line)
    return "\n".join(lines)


def parse_hex_block(s: str) -> bytes:
    s = s.replace(" ", "").replace("\n", "").strip().lower()
    if len(s) != 32 or not all(c in "0123456789abcdef" for c in s):
        raise ValueError("Block must be 32 hexadecimal characters (128 bits)")
    return bytes.fromhex(s)


def parse_hex_key(s: str) -> bytes:
    return parse_hex_block(s)
