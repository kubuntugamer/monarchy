// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryDir>
#include <QThread>

#include "Kdc.h"
#include "Kpasswd.h"
#include "Krb5.h"
#include "LdapServer.h"
#include "Ntlm.h"
#include "Provisioner.h"

#ifdef MONARCHY_WITH_KRB5
#include <krb5.h>

#include <cstring>
#endif

// The kpasswd service (RFC 3244) is exercised by MIT's own client, not by a
// second copy of this code: krb5_change_password and krb5_set_password are what
// a user's `kpasswd` runs, and they check the reply's AP-REP, the KRB-PRIV key
// and the result codes for us.
namespace {

#ifdef MONARCHY_WITH_KRB5

QString krb5Error(krb5_context context, krb5_error_code code)
{
    const char *message = krb5_get_error_message(context, code);
    const QString text = QString::fromUtf8(message);
    krb5_free_error_message(context, message);
    return text;
}

QString dataString(const krb5_data &data)
{
    return data.data ? QString::fromUtf8(data.data, qsizetype(data.length)) : QString();
}

// What the MIT client observed. A test asserts on both halves: whether the
// call itself failed (krb5_error) and what the service answered.
struct ClientOutcome {
    bool kinitOk = false;
    bool callOk = false;
    int resultCode = -1;
    QString resultCodeString;
    QString resultString;
    QString error;
};

// The MIT client blocks, so it runs on its own thread while the test's event
// loop keeps the KDC and kpasswd answering.
class PasswordClient : public QThread
{
public:
    enum Mode { KinitOnly, ChangeOwn, SetForOther };

    Mode mode = KinitOnly;
    QString principal;
    QString password;
    QString newPassword;
    QString target;
    // Ask the KDC for an initial ticket for kadmin/changepw rather than a TGT,
    // which is what the `kpasswd` command does (and needs a reply whose
    // lifetime respects the request's end time).
    bool initialServiceTicket = false;
    ClientOutcome outcome;

protected:
    void run() override
    {
        krb5_context context = nullptr;
        if (krb5_init_context(&context) != 0) {
            outcome.error = QStringLiteral("krb5_init_context failed");
            return;
        }
        krb5_principal name = nullptr;
        krb5_creds creds;
        std::memset(&creds, 0, sizeof(creds));
        krb5_ccache ccache = nullptr;

        // The name of the service whose ticket the AS-REQ should ask for; NULL
        // means a TGT, "kadmin/changepw" is what the kpasswd command asks for.
        const char *inTktService = initialServiceTicket ? "kadmin/changepw" : nullptr;
        krb5_error_code code =
            krb5_parse_name(context, principal.toUtf8().constData(), &name);
        if (code == 0)
            code = krb5_get_init_creds_password(context, &creds, name,
                                                password.toUtf8().constData(), nullptr, nullptr,
                                                0, inTktService, nullptr);
        if (code != 0) {
            outcome.error = krb5Error(context, code);
        } else {
            outcome.kinitOk = true;
        }

        // krb5_change_password builds its AP-REQ from whatever credentials it
        // is handed, so those must be the kadmin/changepw ticket: either the
        // AS-REP asked for it directly, or it is fetched from the cached TGT.
        if (outcome.kinitOk && initialServiceTicket) {
            krb5_creds *serviceCreds = &creds;
            int resultCode = -1;
            krb5_data codeString;
            krb5_data resultString;
            std::memset(&codeString, 0, sizeof(codeString));
            std::memset(&resultString, 0, sizeof(resultString));
            code = krb5_change_password(context, serviceCreds,
                                        newPassword.toUtf8().constData(), &resultCode,
                                        &codeString, &resultString);
            if (code != 0) {
                outcome.error = krb5Error(context, code);
            } else {
                outcome.callOk = true;
                outcome.resultCode = resultCode;
                outcome.resultCodeString = dataString(codeString);
                outcome.resultString = dataString(resultString);
            }
            krb5_free_data_contents(context, &codeString);
            krb5_free_data_contents(context, &resultString);
        } else if (outcome.kinitOk && krb5_cc_default(context, &ccache) == 0
            && krb5_cc_initialize(context, ccache, name) == 0
            && krb5_cc_store_cred(context, ccache, &creds) == 0) {
            krb5_creds wanted;
            std::memset(&wanted, 0, sizeof(wanted));
            krb5_creds *serviceCreds = nullptr;
            code = krb5_cc_get_principal(context, ccache, &wanted.client);
            if (code == 0) {
                code = krb5_build_principal(context, &wanted.server,
                                            int(std::strlen("CORP.EXAMPLE.COM")),
                                            "CORP.EXAMPLE.COM", "kadmin", "changepw",
                                            nullptr);
            }
            if (code == 0)
                code = krb5_get_credentials(context, 0, ccache, &wanted, &serviceCreds);
            krb5_free_cred_contents(context, &wanted);
            if (code != 0) {
                outcome.error = krb5Error(context, code);
                krb5_free_principal(context, name);
                krb5_free_cred_contents(context, &creds);
                krb5_cc_close(context, ccache);
                krb5_free_context(context);
                return;
            }

            int resultCode = -1;
            krb5_data codeString;
            krb5_data resultString;
            std::memset(&codeString, 0, sizeof(codeString));
            std::memset(&resultString, 0, sizeof(resultString));

            if (mode == ChangeOwn) {
                code = krb5_change_password(context, serviceCreds,
                                            newPassword.toUtf8().constData(), &resultCode,
                                            &codeString, &resultString);
            } else if (mode == SetForOther) {
                krb5_principal targetName = nullptr;
                code = krb5_parse_name(context, target.toUtf8().constData(), &targetName);
                if (code == 0) {
                    code = krb5_set_password(context, serviceCreds,
                                             newPassword.toUtf8().constData(), targetName,
                                             &resultCode, &codeString, &resultString);
                }
                krb5_free_principal(context, targetName);
            }
            krb5_free_creds(context, serviceCreds);

            if (code != 0) {
                outcome.error = krb5Error(context, code);
            } else {
                outcome.callOk = true;
                outcome.resultCode = resultCode;
                outcome.resultCodeString = dataString(codeString);
                outcome.resultString = dataString(resultString);
            }
            krb5_free_data_contents(context, &codeString);
            krb5_free_data_contents(context, &resultString);
        } else if (outcome.kinitOk) {
            outcome.error = QStringLiteral("cannot store the TGT in the credential cache");
        }

        if (ccache)
            krb5_cc_close(context, ccache);
        krb5_free_principal(context, name);
        krb5_free_cred_contents(context, &creds);
        krb5_free_context(context);
    }
};

#endif // MONARCHY_WITH_KRB5

struct Fixture {
    QTemporaryDir dir;
    ProvisionResult provisioned;
    LdapServer *server = nullptr;
    Kdc *kdc = nullptr;
    KpasswdServer *kpasswd = nullptr;
    QString guestDn;

    ~Fixture()
    {
        delete kpasswd;
        delete kdc;
        delete server;
    }

    bool start()
    {
        if (!dir.isValid())
            return false;
        ProvisionConfig config;
        config.realm = QStringLiteral("CORP.EXAMPLE.COM");
        config.netbiosDomain = QStringLiteral("CORP");
        config.adminPassword = QStringLiteral("Str0ng-Pass!");
        config.targetDir = dir.path();
        provisioned = provisionDomain(config);
        if (!provisioned.ok)
            return false;
        guestDn = QStringLiteral("CN=Guest,CN=Users,") + provisioned.baseDn;

        server = new LdapServer;
        if (!server->loadFromFile(provisioned.storePath))
            return false;

        KerberosRealmConfig realm;
        realm.realm = QStringLiteral("CORP.EXAMPLE.COM");
        realm.netbios = QStringLiteral("CORP");
        realm.domainSid = provisioned.domainSid;
        realm.dcHost = provisioned.dcHost;

        kdc = new Kdc;
        kdc->setRealm(realm);
        kdc->setObjectProvider([this]() { return server->objects(); });
        server->setKdc(kdc);
        if (!kdc->listen(0))
            return false;

        kpasswd = new KpasswdServer;
        kpasswd->setKdc(kdc);
        kpasswd->setObjectProvider([this]() { return server->objects(); });
        kpasswd->setPasswordWriter([this](const QString &dn, const QString &password,
                                          QString *error) {
            LdapServer::ModifyChange change;
            change.operation = 2; // replace
            change.type = QStringLiteral("unicodePwd");
            change.values = QStringList{password};
            const int result = server->applyModify(dn, {change});
            if (result != 0 && error) {
                *error = result == 19 ? QStringLiteral("rejected by the domain password policy")
                                      : QStringLiteral("account not found (%1)").arg(result);
            }
            return result == 0;
        });
        if (!kpasswd->listen(0))
            return false;

        const QString confPath = dir.path() + QStringLiteral("/krb5-test.conf");
        QFile conf(confPath);
        if (!conf.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return false;
        const QString contents =
            QStringLiteral("[libdefaults]\n"
                           "    default_realm = CORP.EXAMPLE.COM\n"
                           "    dns_lookup_kdc = false\n"
                           "    dns_lookup_realm = false\n"
                           "    allow_weak_crypto = true\n"
                           "    default_tkt_enctypes = rc4-hmac\n"
                           "    default_tgs_enctypes = rc4-hmac\n"
                           "    permitted_enctypes = rc4-hmac\n"
                           "\n"
                           "[realms]\n"
                           "    CORP.EXAMPLE.COM = {\n"
                           "        kdc = 127.0.0.1:%1\n"
                           "        kpasswd_server = 127.0.0.1:%2\n"
                           "    }\n"
                           "\n"
                           "[domain_realm]\n"
                           "    .corp.example.com = CORP.EXAMPLE.COM\n"
                           "    corp.example.com = CORP.EXAMPLE.COM\n")
                .arg(kdc->serverPort())
                .arg(kpasswd->serverPort());
        conf.write(contents.toUtf8());
        conf.close();

        qputenv("KRB5_CONFIG", confPath.toUtf8());
        qputenv("KRB5CCNAME",
                QStringLiteral("FILE:").append(dir.path()).append(QStringLiteral("/ccache"))
                    .toUtf8());
        return true;
    }

    // A second account with a known password, so setting someone else's
    // password has a real target.
    bool giveGuestPassword(const QString &password)
    {
        // Guest is provisioned disabled, the way AD ships it; a disabled
        // account cannot log on, so enable it before it has to.
        LdapServer::ModifyChange enable;
        enable.operation = 2;
        enable.type = QStringLiteral("userAccountControl");
        enable.values = QStringList{QStringLiteral("512")}; // NORMAL_ACCOUNT
        LdapServer::ModifyChange change;
        change.operation = 2;
        change.type = QStringLiteral("unicodePwd");
        change.values = QStringList{password};
        return server->applyModify(guestDn, {enable}) == 0
               && server->applyModify(guestDn, {change}) == 0;
    }

    // Runs the MIT client to completion while the event loop serves the realm.
    static bool run(PasswordClient &client)
    {
        client.start();
        QElapsedTimer timer;
        timer.start();
        while (!client.isFinished() && timer.elapsed() < 10000) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(1);
        }
        client.wait(1000);
        return client.isFinished();
    }
};

} // namespace

class KpasswdTest : public QObject
{
    Q_OBJECT

private slots:
#ifdef MONARCHY_WITH_KRB5
    void changesOwnPassword();
    void changesOwnPasswordWithInitialServiceTicket();
    void refusesWeakPassword();
    void setsAnotherAccountsPassword();
    void refusesUnauthorizedSet();
#else
    void skippedWithoutMitClient() { QSKIP("MIT krb5 is not installed"); }

#endif
};

#ifdef MONARCHY_WITH_KRB5

void KpasswdTest::changesOwnPassword()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    PasswordClient client;
    client.mode = PasswordClient::ChangeOwn;
    client.principal = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    client.password = QStringLiteral("Str0ng-Pass!");
    client.newPassword = QStringLiteral("N3w-Pass!word");
    QVERIFY(Fixture::run(client));
    QVERIFY2(client.outcome.kinitOk, qPrintable(client.outcome.error));
    QVERIFY2(client.outcome.callOk, qPrintable(client.outcome.error));
    QCOMPARE(client.outcome.resultCode, 0);
    QVERIFY(client.outcome.resultString.isEmpty());

    // The new password is the credential of record: Kerberos accepts it and
    // the old one no longer opens a TGT.
    PasswordClient again;
    again.principal = client.principal;
    again.password = client.newPassword;
    QVERIFY(Fixture::run(again));
    QVERIFY2(again.outcome.kinitOk, qPrintable(again.outcome.error));

    PasswordClient stale;
    stale.principal = client.principal;
    stale.password = QStringLiteral("Str0ng-Pass!");
    QVERIFY(Fixture::run(stale));
    QVERIFY(!stale.outcome.kinitOk);

    // ...and it is the same store LDAP serves, so NTLM and simple bind moved
    // with it: the stored NT hash is the new password's.
    bool foundHash = false;
    for (const DirectoryObject &object : fixture.server->objects()) {
        if (object.attributes.value(QStringLiteral("sAMAccountName"))
            != QLatin1String("Administrator"))
            continue;
        const QByteArray hash =
            QByteArray::fromHex(object.attributes.value(QStringLiteral("ntHash")).toLatin1());
        QCOMPARE(hash, Ntlm::ntowfV1(client.newPassword));
        foundHash = true;
    }
    QVERIFY(foundHash);
}

void KpasswdTest::changesOwnPasswordWithInitialServiceTicket()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    // The `kpasswd` command's own path: an AS-REQ that names kadmin/changepw,
    // which the KDC answers with a service ticket instead of a TGT.
    PasswordClient client;
    client.mode = PasswordClient::ChangeOwn;
    client.initialServiceTicket = true;
    client.principal = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    client.password = QStringLiteral("Str0ng-Pass!");
    client.newPassword = QStringLiteral("N3w-Pass!agaiN");
    QVERIFY(Fixture::run(client));
    QVERIFY2(client.outcome.kinitOk, qPrintable(client.outcome.error));
    QVERIFY2(client.outcome.callOk, qPrintable(client.outcome.error));
    QCOMPARE(client.outcome.resultCode, 0);

    PasswordClient again;
    again.principal = client.principal;
    again.password = client.newPassword;
    QVERIFY(Fixture::run(again));
    QVERIFY2(again.outcome.kinitOk, qPrintable(again.outcome.error));
}

void KpasswdTest::refusesWeakPassword()
{
    Fixture fixture;
    QVERIFY(fixture.start());

    PasswordClient client;
    client.mode = PasswordClient::ChangeOwn;
    client.principal = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    client.password = QStringLiteral("Str0ng-Pass!");
    client.newPassword = QStringLiteral("short");
    QVERIFY(Fixture::run(client));
    QVERIFY2(client.outcome.callOk, qPrintable(client.outcome.error));
    QCOMPARE(client.outcome.resultCode, 4); // KRB5_KPASSWD_SOFTERROR
    QVERIFY(!client.outcome.resultString.isEmpty());

    // A refused change leaves the old password in place.
    PasswordClient again;
    again.principal = client.principal;
    again.password = client.password;
    QVERIFY(Fixture::run(again));
    QVERIFY2(again.outcome.kinitOk, qPrintable(again.outcome.error));
}

void KpasswdTest::setsAnotherAccountsPassword()
{
    Fixture fixture;
    QVERIFY(fixture.start());
    QVERIFY(fixture.giveGuestPassword(QStringLiteral("Gu3st-Pass!")));

    PasswordClient client;
    client.mode = PasswordClient::SetForOther;
    client.principal = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    client.password = QStringLiteral("Str0ng-Pass!");
    client.target = QStringLiteral("Guest@CORP.EXAMPLE.COM");
    client.newPassword = QStringLiteral("Gu3st-Pass!2");
    QVERIFY(Fixture::run(client));
    QVERIFY2(client.outcome.callOk, qPrintable(client.outcome.error));
    QCOMPARE(client.outcome.resultCode, 0);

    PasswordClient guest;
    guest.principal = QStringLiteral("Guest@CORP.EXAMPLE.COM");
    guest.password = client.newPassword;
    QVERIFY(Fixture::run(guest));
    QVERIFY2(guest.outcome.kinitOk, qPrintable(guest.outcome.error));
}

void KpasswdTest::refusesUnauthorizedSet()
{
    Fixture fixture;
    QVERIFY(fixture.start());
    QVERIFY(fixture.giveGuestPassword(QStringLiteral("Gu3st-Pass!")));

    // Guest may change its own password but not the administrator's.
    PasswordClient client;
    client.mode = PasswordClient::SetForOther;
    client.principal = QStringLiteral("Guest@CORP.EXAMPLE.COM");
    client.password = QStringLiteral("Gu3st-Pass!");
    client.target = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    client.newPassword = QStringLiteral("Hij4ck-Pass!");
    QVERIFY(Fixture::run(client));
    QVERIFY2(client.outcome.callOk, qPrintable(client.outcome.error));
    QCOMPARE(client.outcome.resultCode, 5); // KRB5_KPASSWD_ACCESSDENIED

    PasswordClient admin;
    admin.principal = QStringLiteral("Administrator@CORP.EXAMPLE.COM");
    admin.password = QStringLiteral("Str0ng-Pass!");
    QVERIFY(Fixture::run(admin));
    QVERIFY2(admin.outcome.kinitOk, qPrintable(admin.outcome.error));
}

#endif // MONARCHY_WITH_KRB5

QTEST_GUILESS_MAIN(KpasswdTest)
#include "test_kpasswd.moc"
