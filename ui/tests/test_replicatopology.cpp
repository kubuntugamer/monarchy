// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The replication link an administrator registers is kept in the directory as
// an nTDSConnection object, which is what makes a partner outlive the process
// that registered it. These cases drive that round trip through LdapServer, so
// what is asserted is what a directory search would find: the object, its
// parent, and the address, options and schedule it reads back as.

#include <QtTest>

#include "LdapServer.h"
#include "ReplicaTopology.h"
#include "resultsmodel.h"

namespace {

const QString kNtdsDn = QStringLiteral(
    "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,"
    "CN=Configuration,DC=corp,DC=example,DC=com");
const QString kConfigNc = QStringLiteral("CN=Configuration,DC=corp,DC=example,DC=com");
const QString kBaseDn = QStringLiteral("DC=corp,DC=example,DC=com");

DirectoryObject object(const QString &dn, const QString &objectClass)
{
    DirectoryObject o;
    o.id = dn;
    o.name = dn.section(QLatin1Char('='), 1).section(QLatin1Char(','), 0, 0);
    o.attributes.insert(QStringLiteral("objectClass"), objectClass);
    return o;
}

// A store with the configuration NC a provisioned domain carries: a root DSE
// naming the partitions, the Servers container, and this DSA's NTDS Settings.
void buildStore(LdapServer *ldap)
{
    DirectoryObject rootDse;
    rootDse.attributes.insert(QStringLiteral("configurationNamingContext"), kConfigNc);
    rootDse.attributes.insert(QStringLiteral("defaultNamingContext"), kBaseDn);

    DirectoryObject ntds = object(kNtdsDn, QStringLiteral("top;nTDSDSA"));
    ntds.attributes.insert(QStringLiteral("cn"), QStringLiteral("NTDS Settings"));

    ldap->setObjects({rootDse, object(kBaseDn, QStringLiteral("top;domain")), ntds});
}

} // namespace

class ReplicaTopologyTest : public QObject
{
    Q_OBJECT

private slots:
    void readsThePhysicalAddressForms()
    {
        QString host;
        quint16 port = 0;
        ReplicaTopology::splitAddress(QStringLiteral("192.168.1.17"), &host, &port);
        QCOMPARE(host, QStringLiteral("192.168.1.17"));
        QCOMPARE(port, quint16(0));

        ReplicaTopology::splitAddress(QStringLiteral("192.168.1.17:1038"), &host, &port);
        QCOMPARE(host, QStringLiteral("192.168.1.17"));
        QCOMPARE(port, quint16(1038));

        ReplicaTopology::splitAddress(QStringLiteral("ncacn_ip_tcp:minerva[1038]"), &host, &port);
        QCOMPARE(host, QStringLiteral("minerva"));
        QCOMPARE(port, quint16(1038));
    }

    void keepsALinkAsAConnectionObject()
    {
        LdapServer ldap;
        buildStore(&ldap);

        ReplicaSource link;
        link.ncDn = kBaseDn;
        link.address = QStringLiteral("192.168.1.17:1038");
        link.options = 16; // DRS_WRIT_REP
        link.schedule = QByteArray(84, char(0x11));
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error), qPrintable(error));

        const QString expectedDn =
            QStringLiteral("CN=192.168.1.17_1038,") + kNtdsDn;
        bool found = false;
        for (const DirectoryObject &o : ldap.objects()) {
            if (o.id.compare(expectedDn, Qt::CaseInsensitive) != 0)
                continue;
            found = true;
            QCOMPARE(o.attributes.value(QStringLiteral("objectClass")),
                     QStringLiteral("top;nTDSConnection"));
            QCOMPARE(o.attributes.value(QStringLiteral("cn")),
                     QStringLiteral("192.168.1.17_1038"));
            QVERIFY(o.attributes.value(QStringLiteral("transportType"))
                        .startsWith(QStringLiteral("22b70c67")));
            QCOMPARE(o.attributes.value(QStringLiteral("options")), QStringLiteral("16"));
            // A level-1 add carries no source DSA, so the source server is named
            // from the address and parented at the forest's first site.
            QCOMPARE(o.attributes.value(QStringLiteral("fromServer")),
                     QStringLiteral("CN=NTDS Settings,CN=192.168.1.17,CN=Servers,"
                                    "CN=Default-First-Site-Name,CN=Sites,%1")
                         .arg(kConfigNc));
        }
        QVERIFY(found);
    }

    void readsTheLinkBackForEveryNamingContext()
    {
        LdapServer ldap;
        buildStore(&ldap);

        ReplicaSource link;
        link.ncDn = kBaseDn;
        link.address = QStringLiteral("192.168.1.17");
        link.options = 1;
        link.schedule = QByteArray(84, char(0x22));
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error), qPrintable(error));

        // A connection object covers every NC the source DSA holds, so the same
        // object is one link per naming context this DC replicates.
        const QList<ReplicaSource> restored = ReplicaTopology::links(
            ldap.objects(), {kBaseDn, kConfigNc});
        QCOMPARE(restored.size(), 2);
        QCOMPARE(restored.at(0).ncDn, kBaseDn);
        QCOMPARE(restored.at(1).ncDn, kConfigNc);
        for (const ReplicaSource &r : restored) {
            QCOMPARE(r.address, QStringLiteral("192.168.1.17"));
            QCOMPARE(r.options, quint32(1));
            QCOMPARE(r.schedule, QByteArray(84, char(0x22)));
            // The synthesised source is not a level-2 source DSA being claimed.
            QVERIFY(r.sourceDsaDn.startsWith(QStringLiteral("CN=NTDS Settings,")));
        }
    }

    void restoringTheSameLinkTwiceChangesNothing()
    {
        LdapServer ldap;
        buildStore(&ldap);
        ReplicaSource link;
        link.ncDn = kBaseDn;
        link.address = QStringLiteral("192.168.1.17");
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error), qPrintable(error));
        const int after = ldap.objects().size();
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error), qPrintable(error));
        QCOMPARE(ldap.objects().size(), after);
    }

    void retiringALinkRemovesItsObject()
    {
        LdapServer ldap;
        buildStore(&ldap);
        ReplicaSource link;
        link.ncDn = kBaseDn;
        link.address = QStringLiteral("192.168.1.17:1038");
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error), qPrintable(error));
        QVERIFY(ReplicaTopology::links(ldap.objects(), {kBaseDn}).size() == 1);

        QVERIFY2(ReplicaTopology::remove(&ldap, link.address, &error), qPrintable(error));
        QVERIFY(ReplicaTopology::links(ldap.objects(), {kBaseDn}).isEmpty());
        // Retiring a link that is not there is not an error: DsReplicaDel
        // deletes an absent link rather than failing the call.
        QVERIFY2(ReplicaTopology::remove(&ldap, link.address, &error), qPrintable(error));
    }

    void refusesToKeepALinkWithNowhereToPutIt()
    {
        LdapServer ldap;
        ldap.setObjects({object(kBaseDn, QStringLiteral("top;domain"))});
        ReplicaSource link;
        link.ncDn = kBaseDn;
        link.address = QStringLiteral("192.168.1.17");
        QString error;
        QVERIFY(!ReplicaTopology::store(&ldap, link, &error));
        QVERIFY(error.contains(QStringLiteral("NTDS Settings")));
        QVERIFY(ReplicaTopology::links(ldap.objects(), {kBaseDn}).isEmpty());
    }
};

#include "test_replicatopology.moc"
QTEST_GUILESS_MAIN(ReplicaTopologyTest)
