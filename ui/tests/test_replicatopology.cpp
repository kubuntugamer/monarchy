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

QString serverDn(const QString &label)
{
    return QStringLiteral("CN=%1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,%2")
        .arg(label, kConfigNc);
}

QString dsaDn(const QString &label)
{
    return QStringLiteral("CN=NTDS Settings,%1").arg(serverDn(label));
}

// The two objects a DC publishes in the configuration NC: its Server object,
// which carries the address a partner pulls from, and its NTDS Settings.
void publishDc(LdapServer *ldap, const QString &label, const QString &host)
{
    DirectoryObject server = object(serverDn(label), QStringLiteral("top;server"));
    server.attributes.insert(QStringLiteral("dNSHostName"), host);
    DirectoryObject ntds = object(dsaDn(label), QStringLiteral("top;nTDSDSA"));
    ntds.attributes.insert(QStringLiteral("cn"), QStringLiteral("NTDS Settings"));

    QList<DirectoryObject> objects = ldap->objects();
    objects.append(server);
    objects.append(ntds);
    ldap->setObjects(objects);
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

    // Two DCs in one site pull from each other: that is the whole intrasite
    // topology a site that small has, and neither needs an administrator to
    // name the other.
    void kccGivesTwoDcsInASiteEachOther()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        publishDc(&ldap, QStringLiteral("DC2"), QStringLiteral("dc2.corp.example.com"));

        const QList<ReplicaSource> created = ReplicaTopology::synchronize(&ldap, kNtdsDn);
        QCOMPARE(created.size(), 1);
        QCOMPARE(created.at(0).address, QStringLiteral("dc2.corp.example.com"));
        QCOMPARE(created.at(0).sourceDsaDn, dsaDn(QStringLiteral("DC2")));

        const QString expectedDn =
            QStringLiteral("CN=dc2.corp.example.com,%1").arg(kNtdsDn);
        bool found = false;
        for (const DirectoryObject &o : ldap.objects()) {
            if (o.id.compare(expectedDn, Qt::CaseInsensitive) != 0)
                continue;
            found = true;
            QCOMPARE(o.attributes.value(QStringLiteral("fromServer")), dsaDn(QStringLiteral("DC2")));
            // NTDSCONN_OPT_IS_GENERATED says the KCC owns this object.
            QCOMPARE(o.attributes.value(QStringLiteral("options")), QStringLiteral("1"));
            QCOMPARE(o.attributes.value(QStringLiteral("enabledConnection")),
                     QStringLiteral("TRUE"));
            // FLAG_CONFIG_ALLOW_RENAME | FLAG_CONFIG_ALLOW_MOVE.
            QCOMPARE(o.attributes.value(QStringLiteral("systemFlags")),
                     QStringLiteral("1610612736"));
        }
        QVERIFY(found);

        // The KCC runs again after every cycle; it must not add a second path to
        // a source this DSA already has.
        QVERIFY(ReplicaTopology::synchronize(&ldap, kNtdsDn).isEmpty());
    }

    // Three DCs form a ring, which for three is also the full mesh: each one's
    // predecessor is the same choice in every store, because the order is the
    // fixed NTDS Settings DN order and nothing process-local.
    void kccFormsARingOfThree()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        publishDc(&ldap, QStringLiteral("DC2"), QStringLiteral("dc2.corp.example.com"));
        publishDc(&ldap, QStringLiteral("DC3"), QStringLiteral("dc3.corp.example.com"));

        const QList<ReplicaTopology::PublishedDsa> dsas =
            ReplicaTopology::intrasiteDsas(ldap.objects(), kNtdsDn);
        QCOMPARE(dsas.size(), 3);
        QCOMPARE(dsas.at(0).ntdsDn, dsaDn(QStringLiteral("DC1")));
        QCOMPARE(dsas.at(2).ntdsDn, dsaDn(QStringLiteral("DC3")));

        // DC1 pulls from DC3, DC3 from DC2, DC2 from DC1: a closed ring.
        QList<ReplicaSource> from = ReplicaTopology::intrasiteTopology(ldap.objects(), kNtdsDn);
        QCOMPARE(from.size(), 1);
        QCOMPARE(from.at(0).sourceDsaDn, dsaDn(QStringLiteral("DC3")));
        from = ReplicaTopology::intrasiteTopology(ldap.objects(), dsaDn(QStringLiteral("DC2")));
        QCOMPARE(from.size(), 1);
        QCOMPARE(from.at(0).sourceDsaDn, dsaDn(QStringLiteral("DC1")));
        from = ReplicaTopology::intrasiteTopology(ldap.objects(), dsaDn(QStringLiteral("DC3")));
        QCOMPARE(from.size(), 1);
        QCOMPARE(from.at(0).sourceDsaDn, dsaDn(QStringLiteral("DC2")));
    }

    // A connection an administrator made is a path the KCC uses and does not
    // touch: MS-ADTS 6.2 says it creates repsFrom from those objects, not that
    // it replaces them with its own.
    void kccLeavesAnAdministratorsConnectionAlone()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        publishDc(&ldap, QStringLiteral("DC2"), QStringLiteral("dc2.corp.example.com"));

        ReplicaSource adminLink;
        adminLink.ncDn = kBaseDn;
        adminLink.address = QStringLiteral("dc2.corp.example.com");
        adminLink.options = 16; // DRS_WRIT_REP
        adminLink.sourceDsaDn = dsaDn(QStringLiteral("DC2"));
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, adminLink, &error), qPrintable(error));

        QVERIFY(ReplicaTopology::synchronize(&ldap, kNtdsDn).isEmpty());
        for (const DirectoryObject &o : ldap.objects()) {
            if (o.id.compare(QStringLiteral("CN=dc2.corp.example.com,%1").arg(kNtdsDn),
                             Qt::CaseInsensitive)
                == 0) {
                QCOMPARE(o.attributes.value(QStringLiteral("options")), QStringLiteral("16"));
                QVERIFY(!o.attributes.contains(QStringLiteral("enabledConnection")));
            }
        }
    }

    // A store with two DSAs — a promoted second controller — has its partner's
    // connection objects replicated into it as well. Those are the partner's
    // links, not this DSA's: written back under the partner and pulled from
    // here, they would have each DC pulling whatever the other holds a link
    // for, and this DC's own link would sit under the wrong NTDS Settings.
    void linksBelongToTheDsaThatOwnsThem()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        publishDc(&ldap, QStringLiteral("DC2"), QStringLiteral("dc2.corp.example.com"));

        ReplicaSource link;
        link.address = QStringLiteral("dc1.corp.example.com:1038");
        link.ncDn = kBaseDn;
        QString error;
        QVERIFY2(ReplicaTopology::store(&ldap, link, &error, dsaDn(QStringLiteral("DC2"))),
                 qPrintable(error));

        // The object is under DC2's own settings, not under DC1's.
        QString stored;
        for (const DirectoryObject &object : ldap.objects()) {
            if (object.attributes.value(QStringLiteral("objectClass"))
                    .contains(QStringLiteral("nTDSConnection"), Qt::CaseInsensitive))
                stored = object.id;
        }
        QCOMPARE(stored,
                 ReplicaTopology::linkDn(dsaDn(QStringLiteral("DC2")), link.address));

        // DC2 reads its own link back, and does not adopt DC1's.
        ReplicaSource dc1Link = link;
        dc1Link.address = QStringLiteral("dc2.corp.example.com:1038");
        QVERIFY(ReplicaTopology::store(&ldap, dc1Link, &error, dsaDn(QStringLiteral("DC1"))));
        const QList<ReplicaSource> mine = ReplicaTopology::links(
            ldap.objects(), {kBaseDn}, dsaDn(QStringLiteral("DC2")));
        QCOMPARE(mine.size(), 1);
        QCOMPARE(mine.first().address, link.address);
    }

    // A destination that announced itself with DsReplicaUpdateRefs is kept as
    // this DSA's repsTo, so the announcement survives a restart, and a list
    // that names fewer destinations is how one is forgotten.
    void keepsDestinationsAsRepsTo()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        const QString selfDn = dsaDn(QStringLiteral("DC1"));
        QVERIFY(ReplicaTopology::destinations(ldap.objects(), selfDn).isEmpty());

        ReplicaDestination first;
        first.ncDn = kBaseDn;
        first.destDsa = QUuid::fromString(QStringLiteral("00112233-4455-6677-8899-aabbccddeeff"));
        first.destDsaName = QStringLiteral(
            "00112233-4455-6677-8899-aabbccddeeff._msdcs.corp.example.com");
        first.options = 0x1cu;

        const ReplicaDestination second = [&first]() {
            ReplicaDestination other = first;
            other.ncDn = kConfigNc;
            return other;
        }();

        QString error;
        QVERIFY(ReplicaTopology::storeDestinations(&ldap, {first, second}, &error, selfDn));
        const QList<ReplicaDestination> restored =
            ReplicaTopology::destinations(ldap.objects(), selfDn);
        QCOMPARE(restored.size(), 2);
        QCOMPARE(restored.at(0).ncDn, kBaseDn);
        QCOMPARE(restored.at(0).destDsa, first.destDsa);
        QCOMPARE(restored.at(0).destDsaName, first.destDsaName);
        QCOMPARE(restored.at(0).options, quint32(0x1c));
        QCOMPARE(restored.at(1).ncDn, kConfigNc);

        // The value is packed rather than a destination written out in plain
        // sight, the same way the other binary-shaped attributes are kept.
        for (const DirectoryObject &object : ldap.objects())
            QVERIFY(!object.attributes.value(QStringLiteral("repsTo")).contains(first.destDsaName));

        // Fewer destinations is how one leaves: the attribute follows the list.
        QVERIFY(ReplicaTopology::storeDestinations(&ldap, {first}, &error, selfDn));
        const QList<ReplicaDestination> kept =
            ReplicaTopology::destinations(ldap.objects(), selfDn);
        QCOMPARE(kept.size(), 1);
        QCOMPARE(kept.first().ncDn, kBaseDn);

        // An empty list takes the attribute off rather than leaving it empty.
        QVERIFY(ReplicaTopology::storeDestinations(&ldap, {}, &error, selfDn));
        QVERIFY(ReplicaTopology::destinations(ldap.objects(), selfDn).isEmpty());
    }

    void kccDoesNothingWhenTheSiteHoldsOnlyThisDc()
    {
        LdapServer ldap;
        buildStore(&ldap);
        publishDc(&ldap, QStringLiteral("DC1"), QStringLiteral("dc1.corp.example.com"));
        QVERIFY(ReplicaTopology::intrasiteTopology(ldap.objects(), kNtdsDn).isEmpty());
        QVERIFY(ReplicaTopology::synchronize(&ldap, kNtdsDn).isEmpty());
    }
};

#include "test_replicatopology.moc"
QTEST_GUILESS_MAIN(ReplicaTopologyTest)
