// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QtTest>

#include "LdapServer.h"
#include "PasswordSettings.h"

// Fine-grained password policies are only worth serving if the policy that
// governs an account is the one AD says governs it: the applicable PSO with the
// lowest precedence, over the domain's policy, for that account alone.
class TestPasswordSettings : public QObject
{
    Q_OBJECT

private slots:
    void domainPolicyGovernsWithoutAPolicy();
    void lowestPrecedenceWins();
    void appliesThroughAGroup();
    void fieldsThePolicyOmitsStayAsTheDomainHasThem();
    void lockoutFollowsThePolicy();
};

namespace {

DirectoryObject domainObject()
{
    DirectoryObject domain;
    domain.kind = ObjectKind::Domain;
    domain.id = QStringLiteral("DC=corp,DC=example,DC=com");
    domain.attributes.insert(QStringLiteral("minPwdLength"), QStringLiteral("7"));
    domain.attributes.insert(QStringLiteral("pwdHistoryLength"), QStringLiteral("24"));
    domain.attributes.insert(QStringLiteral("pwdProperties"), QStringLiteral("1"));
    domain.attributes.insert(QStringLiteral("maxPwdAge"), QStringLiteral("-36288000000000"));
    domain.attributes.insert(QStringLiteral("minPwdAge"), QStringLiteral("-864000000000"));
    domain.attributes.insert(QStringLiteral("lockoutThreshold"), QStringLiteral("0"));
    domain.attributes.insert(QStringLiteral("lockoutDuration"), QStringLiteral("-18000000000"));
    domain.attributes.insert(QStringLiteral("lockoutObservationWindow"),
                             QStringLiteral("-18000000000"));
    return domain;
}

DirectoryObject userObject(const QStringList &memberOf = {})
{
    DirectoryObject user;
    user.kind = ObjectKind::User;
    user.id = QStringLiteral("CN=Ada,CN=Users,DC=corp,DC=example,DC=com");
    user.memberOf = memberOf;
    return user;
}

DirectoryObject policyObject(quint32 precedence, const QString &appliesTo)
{
    DirectoryObject policy;
    policy.id = QStringLiteral("CN=Policy%1,CN=Password Settings Container,CN=System,"
                               "DC=corp,DC=example,DC=com").arg(precedence);
    policy.attributes.insert(QStringLiteral("objectClass"),
                             QStringLiteral("top;msDS-PasswordSettings"));
    policy.attributes.insert(QStringLiteral("msDS-PasswordSettingsPrecedence"),
                             QString::number(precedence));
    policy.attributes.insert(QStringLiteral("msDS-PSOAppliesTo"), appliesTo);
    return policy;
}

} // namespace

void TestPasswordSettings::domainPolicyGovernsWithoutAPolicy()
{
    const QList<DirectoryObject> directory{domainObject(), userObject()};
    const LdapServer::PasswordPolicy policy = PasswordSettings::policyFor(userObject(), directory);
    QCOMPARE(policy.minLength, 7);
    QCOMPARE(policy.historyLength, 24);
    QVERIFY(PasswordSettings::resultant(userObject(), directory) == nullptr);
}

void TestPasswordSettings::lowestPrecedenceWins()
{
    DirectoryObject loose = policyObject(20, userObject().id);
    loose.attributes.insert(QStringLiteral("msDS-MinimumPasswordLength"), QStringLiteral("12"));
    DirectoryObject strict = policyObject(5, userObject().id);
    strict.attributes.insert(QStringLiteral("msDS-MinimumPasswordLength"), QStringLiteral("16"));
    const QList<DirectoryObject> directory{domainObject(), userObject(), loose, strict};

    const DirectoryObject *winner = PasswordSettings::resultant(userObject(), directory);
    QVERIFY(winner != nullptr);
    QCOMPARE(winner->id, strict.id);
    QCOMPARE(PasswordSettings::policyFor(userObject(), directory).minLength, 16);
}

void TestPasswordSettings::appliesThroughAGroup()
{
    const QString group = QStringLiteral("CN=Engineering,OU=Groups,DC=corp,DC=example,DC=com");
    DirectoryObject policy = policyObject(1, group);
    policy.attributes.insert(QStringLiteral("msDS-MinimumPasswordLength"), QStringLiteral("14"));
    const DirectoryObject member = userObject({group});
    // The policy names the group, not the account: membership is what carries it.
    QVERIFY(PasswordSettings::resultant(member, {domainObject(), member, policy}) != nullptr);
    QCOMPARE(PasswordSettings::policyFor(member, {domainObject(), member, policy}).minLength, 14);
    // An account outside the group stays on the domain policy.
    const DirectoryObject outsider = userObject();
    QVERIFY(PasswordSettings::resultant(outsider,
                                        {domainObject(), outsider, policy}) == nullptr);
}

void TestPasswordSettings::fieldsThePolicyOmitsStayAsTheDomainHasThem()
{
    DirectoryObject policy = policyObject(1, userObject().id);
    policy.attributes.insert(QStringLiteral("msDS-MinimumPasswordLength"), QStringLiteral("20"));
    policy.attributes.insert(QStringLiteral("msDS-PasswordComplexityEnabled"),
                             QStringLiteral("FALSE"));
    const LdapServer::PasswordPolicy effective =
        PasswordSettings::policyFor(userObject(), {domainObject(), userObject(), policy});
    QCOMPARE(effective.minLength, 20);
    // Complexity is switched off by the policy, and everything it says nothing
    // about — the history and the ages — stays as the domain has it.
    QCOMPARE(effective.properties & LdapServer::kPasswordComplex, 0u);
    QCOMPARE(effective.historyLength, 24);
    QCOMPARE(effective.maxAge, qint64(-36288000000000LL));
}

void TestPasswordSettings::lockoutFollowsThePolicy()
{
    DirectoryObject policy = policyObject(1, userObject().id);
    policy.attributes.insert(QStringLiteral("msDS-LockoutThreshold"), QStringLiteral("5"));
    policy.attributes.insert(QStringLiteral("msDS-LockoutDuration"),
                             QStringLiteral("-9000000000"));
    const QList<DirectoryObject> directory{domainObject(), userObject(), policy};
    const PasswordSettings::Lockout lockout = PasswordSettings::lockoutFor(userObject(), directory);
    QCOMPARE(lockout.threshold, 5u);
    QCOMPARE(lockout.duration, qint64(-9000000000LL));
    // A policy that says nothing about the window leaves the domain's.
    QCOMPARE(lockout.window, qint64(-18000000000LL));
}

QTEST_MAIN(TestPasswordSettings)
#include "test_passwordsettings.moc"
