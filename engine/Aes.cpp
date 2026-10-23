// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "Aes.h"

#include <QList>
#include <QMessageAuthenticationCode>

namespace {

const quint8 kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

const quint8 kInvSbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

quint8 xtime(quint8 value)
{
    return quint8((value << 1) ^ ((value & 0x80) ? 0x1b : 0x00));
}

quint8 multiply(quint8 a, quint8 b)
{
    quint8 result = 0;
    while (b) {
        if (b & 0x01)
            result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

int roundCount(const QByteArray &key)
{
    return key.size() == 32 ? 14 : (key.size() == 24 ? 12 : 10);
}

// FIPS-197 §5.2 key expansion, kept as one 16-byte round key per round.
QList<QByteArray> expandKey(const QByteArray &key)
{
    const int rounds = roundCount(key);
    const int words = 4 * (rounds + 1);
    const int nk = key.size() / 4;
    QList<quint8> w(words * 4);
    for (int i = 0; i < key.size(); ++i)
        w[i] = quint8(key.at(i));

    quint8 rcon = 0x01;
    for (int i = nk; i < words; ++i) {
        quint8 temp[4] = {w[(i - 1) * 4], w[(i - 1) * 4 + 1], w[(i - 1) * 4 + 2],
                          w[(i - 1) * 4 + 3]};
        if (i % nk == 0) {
            const quint8 first = temp[0];
            temp[0] = kSbox[temp[1]] ^ rcon;
            temp[1] = kSbox[temp[2]];
            temp[2] = kSbox[temp[3]];
            temp[3] = kSbox[first];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (int j = 0; j < 4; ++j)
                temp[j] = kSbox[temp[j]];
        }
        for (int j = 0; j < 4; ++j)
            w[i * 4 + j] = w[(i - nk) * 4 + j] ^ temp[j];
    }

    QList<QByteArray> roundKeys;
    for (int r = 0; r <= rounds; ++r)
        roundKeys.append(QByteArray(reinterpret_cast<const char *>(w.constData() + r * 16), 16));
    return roundKeys;
}

void addRoundKey(quint8 *state, const QByteArray &roundKey)
{
    for (int i = 0; i < 16; ++i)
        state[i] ^= quint8(roundKey.at(i));
}

void subBytes(quint8 *state)
{
    for (int i = 0; i < 16; ++i)
        state[i] = kSbox[state[i]];
}

void invSubBytes(quint8 *state)
{
    for (int i = 0; i < 16; ++i)
        state[i] = kInvSbox[state[i]];
}

// State is column-major: state[4 * column + row].
void shiftRows(quint8 *state)
{
    for (int row = 1; row < 4; ++row) {
        const quint8 saved[4] = {state[row], state[4 + row], state[8 + row], state[12 + row]};
        for (int column = 0; column < 4; ++column)
            state[4 * column + row] = saved[(column + row) % 4];
    }
}

void invShiftRows(quint8 *state)
{
    for (int row = 1; row < 4; ++row) {
        const quint8 saved[4] = {state[row], state[4 + row], state[8 + row], state[12 + row]};
        for (int column = 0; column < 4; ++column)
            state[4 * column + row] = saved[(column + 4 - row) % 4];
    }
}

void mixColumns(quint8 *state)
{
    for (int column = 0; column < 4; ++column) {
        quint8 *c = state + 4 * column;
        const quint8 a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        c[0] = quint8(multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3);
        c[1] = quint8(a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3);
        c[2] = quint8(a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3));
        c[3] = quint8(multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2));
    }
}

void invMixColumns(quint8 *state)
{
    for (int column = 0; column < 4; ++column) {
        quint8 *c = state + 4 * column;
        const quint8 a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        c[0] = quint8(multiply(a0, 0x0e) ^ multiply(a1, 0x0b) ^ multiply(a2, 0x0d)
                      ^ multiply(a3, 0x09));
        c[1] = quint8(multiply(a0, 0x09) ^ multiply(a1, 0x0e) ^ multiply(a2, 0x0b)
                      ^ multiply(a3, 0x0d));
        c[2] = quint8(multiply(a0, 0x0d) ^ multiply(a1, 0x09) ^ multiply(a2, 0x0e)
                      ^ multiply(a3, 0x0b));
        c[3] = quint8(multiply(a0, 0x0b) ^ multiply(a1, 0x0d) ^ multiply(a2, 0x09)
                      ^ multiply(a3, 0x0e));
    }
}

void blockEncrypt(const QByteArray &key, const quint8 *in, quint8 *out)
{
    const QList<QByteArray> roundKeys = expandKey(key);
    quint8 state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = in[i];
    addRoundKey(state, roundKeys.at(0));
    const int rounds = roundKeys.size() - 1;
    for (int round = 1; round < rounds; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys.at(round));
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys.at(rounds));
    for (int i = 0; i < 16; ++i)
        out[i] = state[i];
}

void blockDecrypt(const QByteArray &key, const quint8 *in, quint8 *out)
{
    const QList<QByteArray> roundKeys = expandKey(key);
    quint8 state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = in[i];
    const int rounds = roundKeys.size() - 1;
    addRoundKey(state, roundKeys.at(rounds));
    for (int round = rounds - 1; round >= 1; --round) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys.at(round));
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, roundKeys.at(0));
    for (int i = 0; i < 16; ++i)
        out[i] = state[i];
}

} // namespace

namespace Aes {

QByteArray encryptBlock(const QByteArray &key, const QByteArray &block)
{
    if ((key.size() != 16 && key.size() != 24 && key.size() != 32) || block.size() != 16)
        return {};
    quint8 out[16];
    blockEncrypt(key, reinterpret_cast<const quint8 *>(block.constData()), out);
    return QByteArray(reinterpret_cast<const char *>(out), 16);
}

QByteArray decryptBlock(const QByteArray &key, const QByteArray &block)
{
    if ((key.size() != 16 && key.size() != 24 && key.size() != 32) || block.size() != 16)
        return {};
    quint8 out[16];
    blockDecrypt(key, reinterpret_cast<const quint8 *>(block.constData()), out);
    return QByteArray(reinterpret_cast<const char *>(out), 16);
}

QByteArray ctsEncrypt(const QByteArray &key, const QByteArray &data)
{
    if (data.isEmpty() || (key.size() != 16 && key.size() != 32))
        return {};
    if (data.size() <= 16) {
        QByteArray block = data;
        block.append(QByteArray(16 - block.size(), '\0'));
        return encryptBlock(key, block);
    }

    const int full = data.size() / 16;   // complete blocks, >= 1
    const int rest = data.size() % 16;   // bytes in the final partial block
    QList<QByteArray> blocks;
    QByteArray chain(16, '\0');
    for (int i = 0; i < full; ++i) {
        QByteArray block = data.mid(i * 16, 16);
        for (int j = 0; j < 16; ++j)
            block[j] = char(quint8(block.at(j)) ^ quint8(chain.at(j)));
        chain = encryptBlock(key, block);
        blocks.append(chain);
    }

    QByteArray out;
    if (rest == 0) {
        for (int i = 0; i < full; ++i)
            out.append(blocks.at(i));
        if (full >= 2) {
            const QByteArray last = out.mid((full - 1) * 16, 16);
            const QByteArray previous = out.mid((full - 2) * 16, 16);
            out.replace((full - 2) * 16, 16, last);
            out.replace((full - 1) * 16, 16, previous);
        }
        return out;
    }

    for (int i = 0; i < full - 1; ++i)
        out.append(blocks.at(i));
    // The final partial block is zero padded and XORed with the last complete
    // ciphertext block; the leading bytes of that block are then sent in place
    // of the last 16 bytes, which is the ciphertext-stealing step (RFC 3962 §5).
    QByteArray tail = data.mid(full * 16);
    tail.append(QByteArray(16 - rest, '\0'));
    const QByteArray previous = blocks.at(full - 1);
    for (int j = 0; j < 16; ++j)
        tail[j] = char(quint8(tail.at(j)) ^ quint8(previous.at(j)));
    out.append(encryptBlock(key, tail));
    out.append(previous.left(rest));
    return out;
}

QByteArray ctsDecrypt(const QByteArray &key, const QByteArray &data)
{
    if (data.isEmpty() || (key.size() != 16 && key.size() != 32))
        return {};
    if (data.size() <= 16) {
        const QByteArray block = decryptBlock(key, data.leftJustified(16, '\0'));
        return block.left(data.size());
    }

    const int full = data.size() / 16;
    const int rest = data.size() % 16;
    QByteArray out;

    if (rest == 0) {
        // The last two ciphertext blocks were swapped on the way out.
        QByteArray swapped = data;
        if (full >= 2) {
            const QByteArray last = swapped.mid((full - 1) * 16, 16);
            const QByteArray previous = swapped.mid((full - 2) * 16, 16);
            swapped.replace((full - 2) * 16, 16, last);
            swapped.replace((full - 1) * 16, 16, previous);
        }
        QByteArray chain(16, '\0');
        for (int i = 0; i < full; ++i) {
            const QByteArray cipher = swapped.mid(i * 16, 16);
            QByteArray block = decryptBlock(key, cipher);
            for (int j = 0; j < 16; ++j)
                block[j] = char(quint8(block.at(j)) ^ quint8(chain.at(j)));
            out.append(block);
            chain = cipher;
        }
        return out;
    }

    // Chain up to the second-to-last block.
    QByteArray chain(16, '\0');
    for (int i = 0; i < full - 1; ++i) {
        const QByteArray cipher = data.mid(i * 16, 16);
        QByteArray block = decryptBlock(key, cipher);
        for (int j = 0; j < 16; ++j)
            block[j] = char(quint8(block.at(j)) ^ quint8(chain.at(j)));
        out.append(block);
        chain = cipher;
    }
    const QByteArray stolen = data.mid(full * 16, rest); // leading bytes of the last full block
    const QByteArray finalBlock = data.mid((full - 1) * 16, 16);
    const QByteArray plain = decryptBlock(key, finalBlock);
    // plain = (partial || 0...) XOR lastFull; the missing tail of lastFull is
    // exactly the tail of `plain`.
    QByteArray lastFull = stolen;
    lastFull.append(plain.mid(rest));                  // recover the rest
    QByteArray partial = plain.left(rest);
    for (int j = 0; j < rest; ++j)
        partial[j] = char(quint8(partial.at(j)) ^ quint8(stolen.at(j)));
    QByteArray previousBlock = decryptBlock(key, lastFull);
    for (int j = 0; j < 16; ++j)
        previousBlock[j] = char(quint8(previousBlock.at(j)) ^ quint8(chain.at(j)));
    out.append(previousBlock);
    out.append(partial);
    return out;
}

QByteArray hmacSha1(const QByteArray &key, const QByteArray &data)
{
    QMessageAuthenticationCode mac(QCryptographicHash::Sha1, key);
    mac.addData(data);
    return mac.result();
}

QByteArray pbkdf2Sha1(const QByteArray &password, const QByteArray &salt, int iterations,
                      int keyLength)
{
    QByteArray out;
    for (quint32 block = 1; out.size() < keyLength; ++block) {
        QByteArray counter;
        counter.append(char((block >> 24) & 0xff));
        counter.append(char((block >> 16) & 0xff));
        counter.append(char((block >> 8) & 0xff));
        counter.append(char(block & 0xff));
        QByteArray u = hmacSha1(password, salt + counter);
        QByteArray accumulator = u;
        for (int i = 1; i < iterations; ++i) {
            u = hmacSha1(password, u);
            for (int j = 0; j < accumulator.size(); ++j)
                accumulator[j] = char(quint8(accumulator.at(j)) ^ quint8(u.at(j)));
        }
        out.append(accumulator);
    }
    return out.left(keyLength);
}

QByteArray nfold(const QByteArray &input, int outLength)
{
    if (input.isEmpty() || outLength <= 0)
        return {};
    const int inBits = input.size() * 8;
    const int outBits = outLength * 8;

    QList<int> bits;
    bits.reserve(inBits);
    for (const char byte : input) {
        for (int i = 7; i >= 0; --i)
            bits.append((quint8(byte) >> i) & 0x01);
    }

    int lcm = inBits;
    while (lcm % outBits != 0)
        lcm += inBits;

    // The input is repeated until it fills the lcm length, rotated right by 13
    // bits more before every repetition.
    QList<int> stream;
    stream.reserve(lcm);
    for (int repetition = 0; repetition < lcm / inBits; ++repetition) {
        const int rotation = (13 * repetition) % inBits;
        for (int i = 0; i < inBits; ++i)
            stream.append(bits.at((i - rotation + inBits) % inBits));
    }

    QList<int> accumulator(outBits, 0);
    for (int start = 0; start < lcm; start += outBits) {
        int carry = 0;
        for (int i = outBits - 1; i >= 0; --i) {
            const int sum = accumulator.at(i) + stream.at(start + i) + carry;
            accumulator[i] = sum & 0x01;
            carry = sum >> 1;
        }
        // One's-complement addition: an overflowing carry wraps to the end.
        for (int i = outBits - 1; i >= 0 && carry; --i) {
            const int sum = accumulator.at(i) + 1;
            accumulator[i] = sum & 0x01;
            carry = sum >> 1;
        }
    }

    QByteArray out(outLength, '\0');
    for (int byte = 0; byte < outLength; ++byte) {
        quint8 value = 0;
        for (int bit = 0; bit < 8; ++bit)
            value = quint8((value << 1) | accumulator.at(byte * 8 + bit));
        out[byte] = char(value);
    }
    return out;
}

} // namespace Aes
