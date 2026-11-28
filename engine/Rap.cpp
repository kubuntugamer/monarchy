#include "Rap.h"

#include <QPair>

namespace {

void putLe16(QByteArray &out, quint16 value)
{
    out.append(char(value & 0xff));
    out.append(char((value >> 8) & 0xff));
}

quint16 readLe16(const QByteArray &data, int pos)
{
    if (pos + 1 >= data.size())
        return 0;
    return quint16(quint8(data.at(pos)) | (quint16(quint8(data.at(pos + 1))) << 8));
}

// The fixed-size record a NetGroupEnum answer carries, copied from what both
// NT4 and Windows 2000 put on the wire (Samba's api_RNetGroupEnum writes the
// same): a 21-byte NUL-padded group name and five pad bytes behind it.
const int kGroupRecordSize = 26;
const int kGroupNameSize = 21;

// One descriptor string: NUL-terminated ASCII starting at `at`, which advances
// past the terminator. False when the request ends before the terminator.
bool takeDescriptor(const QByteArray &request, int *at, QByteArray *out)
{
    const int start = *at;
    while (*at < request.size() && request.at(*at) != '\0')
        ++*at;
    if (*at >= request.size())
        return false;
    *out = request.mid(start, *at - start);
    ++*at;
    return true;
}

Rap::Reply unsupported()
{
    Rap::Reply reply;
    reply.status = Rap::ErrorNotSupported;
    putLe16(reply.params, reply.status);
    putLe16(reply.params, 0); // converter word
    return reply;
}

// `net group /domain` asks for the domain's global groups: level 0, the group
// name alone, described as "WrLeh" -> "B21". The two words behind the
// descriptors are the resume context (how many entries the client already has)
// and the size of the buffer it will read.
Rap::Reply netGroupEnum(const QByteArray &request, int at, const QStringList &groups,
                        QString *operation)
{
    if (at + 4 > request.size())
        return unsupported();
    const quint16 resume = readLe16(request, at);
    const quint16 bufferSize = readLe16(request, at + 2);

    QByteArray data;
    int entries = 0;
    Rap::Reply reply;
    reply.status = Rap::ErrorSuccess;
    const int from = qMin(int(resume), int(groups.size()));
    for (int i = from; i < groups.size(); ++i) {
        if (data.size() + kGroupRecordSize > int(bufferSize)) {
            // The client's buffer cannot take the next record; what is here is
            // the page it reads, and 234 tells it there is more.
            reply.status = Rap::ErrorMoreData;
            break;
        }
        QByteArray name;
        name.reserve(kGroupRecordSize);
        name.append(groups.at(i).toLatin1().left(kGroupNameSize - 1));
        name.append(QByteArray(kGroupNameSize - name.size(), '\0'));
        name.append(QByteArray(kGroupRecordSize - kGroupNameSize, '\0'));
        data.append(name);
        ++entries;
    }

    putLe16(reply.params, reply.status);
    putLe16(reply.params, 0); // converter word: the offsets are relative to the data
    putLe16(reply.params, quint16(entries));
    putLe16(reply.params, quint16(from + entries)); // available, as the DC reports it
    reply.data = data;
    if (operation) {
        *operation = QStringLiteral("RAP NetGroupEnum(%1 of %2 from %3)")
                         .arg(entries)
                         .arg(groups.size())
                         .arg(from);
    }
    return reply;
}

} // namespace

namespace Rap {

Reply handle(const QByteArray &request, const QStringList &globalGroups, QString *operation)
{
    if (request.size() < 2)
        return unsupported();
    const quint16 opcode = readLe16(request, 0);
    int at = 2;
    QByteArray paramDesc;
    QByteArray dataDesc;
    if (!takeDescriptor(request, &at, &paramDesc) || !takeDescriptor(request, &at, &dataDesc))
        return unsupported();

    // A server validates the descriptors the client names against the opcode's
    // own, and answers an opcode or a descriptor it does not serve with
    // NERR_notsupported rather than a guess (MS-RAP 2.5.1, 3.2.5.x).
    if (opcode == OpNetGroupEnum && paramDesc == QByteArrayLiteral("WrLeh")
        && dataDesc == QByteArrayLiteral("B21")) {
        return netGroupEnum(request, at, globalGroups, operation);
    }
    return unsupported();
}

} // namespace Rap
