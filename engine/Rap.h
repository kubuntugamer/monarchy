#ifndef RAP_H
#define RAP_H

#include <QByteArray>
#include <QString>
#include <QStringList>

// RAP, the downlevel Remote Administration Protocol (MS-RAP) a Windows 2000
// client still speaks over \\PIPE\LANMAN. `net group /domain` on a 2000 guest
// reads the domain's global groups with NetGroupEnum, not with SAMR: measured
// on the reference DC, the guest takes the SamrQueryDisplayInfo2 answer and
// then asks \PIPE\LANMAN for the same list over RAP, and prints the error from
// that request.
//
// The reply shapes here are copied from the RAP server Samba 4.24.7 serves in
// source3/smbd/smb1_lanman.c (api_RNetGroupEnum), except where the guest was
// measured to read differently: the records are the descriptor's 21 bytes and
// carry no pad, because Windows 2000's net.exe steps by the descriptor size.
namespace Rap {

// MS-RAP 2.5.4, the RAPOpcode word the request starts with.
enum Opcode : quint16 {
    OpNetGroupEnum = 47,
};

// The Win32ErrorCode word the response parameters start with. 50 is
// NERR_notsupported and 234 NERR_MoreData, the values a Windows server sends.
enum Error : quint16 {
    ErrorSuccess = 0,
    ErrorNotSupported = 50,
    ErrorMoreData = 234,
};

struct Reply {
    quint16 status = ErrorNotSupported;
    QByteArray params; // the response parameters after the Win32ErrorCode
    QByteArray data;   // the response data
};

// Handles one RAP request, which is what the client puts in
// Trans_Parameters: the RAPOpcode word, the request descriptor, the response
// descriptor, then the request's own parameters, all NUL-terminated strings
// being ASCII. `operation` receives a line for the log when the request was
// one this server hands to a handler.
Reply handle(const QByteArray &request, const QStringList &globalGroups, QString *operation);

} // namespace Rap

#endif // RAP_H
