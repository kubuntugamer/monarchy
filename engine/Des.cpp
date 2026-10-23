// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Des.h"

// DES (FIPS 46-3): the straight specification, not an optimised variant, so the
// tables below are the published ones and every step can be checked against the
// standard's test vectors. AD uses DES only for the LM/NT one-way functions and
// for the SAMR password-hash encoding, both of which handle a single block at a
// time, so there is no chaining mode here.
namespace {

constexpr quint32 kRoundMask = 0x0fffffffu; // 28 bits of C or D

// Initial and final permutations.
const int kIp[64] = {
    58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

const int kFp[64] = {
    40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

// Round function: expansion, permutation, and the key schedule permutations.
const int kE[48] = {
    32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

const int kP[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

const int kPc1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18, 10,  2,
    59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15,  7, 62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37,
    29, 21, 13,  5, 28, 20, 12,  4
};

const int kPc2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10, 23, 19, 12,  4,
    26,  8, 16,  7, 27, 20, 13,  2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const quint8 kSBox[8][64] = {
    {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    },
    {
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    },
    {
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    },
    {
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    },
    {
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    },
    {
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    },
    {
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    },
    {
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    },
};


const int kShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// `table` holds 1-based bit positions counted from the most significant bit of
// an `inBits`-wide value, which is how FIPS 46-3 prints them.
quint64 permute(quint64 in, int inBits, const int *table, int outBits)
{
    quint64 out = 0;
    for (int i = 0; i < outBits; ++i)
        out = (out << 1) | ((in >> (inBits - table[i])) & 1u);
    return out;
}

quint64 loadBlock(const QByteArray &block)
{
    quint64 value = 0;
    for (int i = 0; i < 8; ++i)
        value = (value << 8) | quint8(block.at(i));
    return value;
}

QByteArray storeBlock(quint64 value)
{
    QByteArray block(8, '\0');
    for (int i = 7; i >= 0; --i) {
        block[i] = char(value & 0xff);
        value >>= 8;
    }
    return block;
}

quint32 feistel(quint32 right, quint64 subkey)
{
    const quint64 expanded = permute(right, 32, kE, 48) ^ subkey;
    quint32 substituted = 0;
    for (int box = 0; box < 8; ++box) {
        const int six = int((expanded >> (42 - 6 * box)) & 0x3fu);
        // The outer bits of each six select the row, the middle four the column.
        const int row = ((six & 0x20) >> 4) | (six & 0x01);
        const int column = (six >> 1) & 0x0f;
        substituted = (substituted << 4) | kSBox[box][row * 16 + column];
    }
    return quint32(permute(substituted, 32, kP, 32));
}

QByteArray crypt(const QByteArray &key, const QByteArray &block, bool encrypting)
{
    if (key.size() != 8 || block.size() != 8)
        return {};
    const quint64 pc1 = permute(loadBlock(key), 64, kPc1, 56);
    quint32 c = quint32((pc1 >> 28) & kRoundMask);
    quint32 d = quint32(pc1 & kRoundMask);
    quint64 subkeys[16];
    for (int round = 0; round < 16; ++round) {
        for (int i = 0; i < kShifts[round]; ++i) {
            c = ((c << 1) | (c >> 27)) & kRoundMask;
            d = ((d << 1) | (d >> 27)) & kRoundMask;
        }
        subkeys[round] = permute((quint64(c) << 28) | d, 56, kPc2, 48);
    }

    const quint64 initial = permute(loadBlock(block), 64, kIp, 64);
    quint32 left = quint32(initial >> 32);
    quint32 right = quint32(initial);
    for (int round = 0; round < 16; ++round) {
        const quint64 subkey = subkeys[encrypting ? round : 15 - round];
        const quint32 previousRight = right;
        right = left ^ feistel(right, subkey);
        left = previousRight;
    }
    // The halves swap once more before the final permutation.
    return storeBlock(permute((quint64(right) << 32) | left, 64, kFp, 64));
}

} // namespace

namespace Des {

QByteArray encryptBlock(const QByteArray &key, const QByteArray &block)
{
    return crypt(key, block, true);
}

QByteArray decryptBlock(const QByteArray &key, const QByteArray &block)
{
    return crypt(key, block, false);
}

QByteArray keyFromPassword(const QByteArray &sevenBytes)
{
    if (sevenBytes.size() < 7)
        return {};
    const quint8 b0 = quint8(sevenBytes.at(0));
    const quint8 b1 = quint8(sevenBytes.at(1));
    const quint8 b2 = quint8(sevenBytes.at(2));
    const quint8 b3 = quint8(sevenBytes.at(3));
    const quint8 b4 = quint8(sevenBytes.at(4));
    const quint8 b5 = quint8(sevenBytes.at(5));
    const quint8 b6 = quint8(sevenBytes.at(6));
    QByteArray key(8, '\0');
    // Seven bytes carry 56 bits; each output byte holds seven of them in its top
    // seven places and leaves the parity bit clear.
    key[0] = char(b0 & 0xfe);
    key[1] = char(((b0 << 7) | (b1 >> 1)) & 0xfe);
    key[2] = char(((b1 << 6) | (b2 >> 2)) & 0xfe);
    key[3] = char(((b2 << 5) | (b3 >> 3)) & 0xfe);
    key[4] = char(((b3 << 4) | (b4 >> 4)) & 0xfe);
    key[5] = char(((b4 << 3) | (b5 >> 5)) & 0xfe);
    key[6] = char(((b5 << 2) | (b6 >> 6)) & 0xfe);
    key[7] = char((b6 << 1) & 0xfe);
    return key;
}

QByteArray encryptOwfHash(const QByteArray &hash, const QByteArray &sessionKey)
{
    if (hash.size() != 16 || sessionKey.size() < 14)
        return {};
    const QByteArray first = keyFromPassword(sessionKey.left(7));
    const QByteArray second = keyFromPassword(sessionKey.mid(7, 7));
    if (first.size() != 8 || second.size() != 8)
        return {};
    return encryptBlock(first, hash.left(8)) + encryptBlock(second, hash.mid(8, 8));
}

QByteArray decryptOwfHash(const QByteArray &hash, const QByteArray &sessionKey)
{
    if (hash.size() != 16 || sessionKey.size() < 14)
        return {};
    const QByteArray first = keyFromPassword(sessionKey.left(7));
    const QByteArray second = keyFromPassword(sessionKey.mid(7, 7));
    if (first.size() != 8 || second.size() != 8)
        return {};
    return decryptBlock(first, hash.left(8)) + decryptBlock(second, hash.mid(8, 8));
}

} // namespace Des
