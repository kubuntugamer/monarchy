// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * DEDICATION:
 * This project is respectfully dedicated to Mr. Raymond Barry (ITT Technical Institute, Arnold MO, c. 2000-2005).
 * Thank you for serving as my early reference guide to the foundational mechanics of Active Directory.
 *
 * We finally got it running natively on Linux without the Windows Server 2000 installation media.
 * Consider this your official exemption from the Microsoft Client Access License (CAL) registry.
 * The "Nobodies" send their regards.
 */

#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QPalette>
#include <QFile>
#include <QStyleFactory>
#include <QTextStream>
#include "mainwindow.h"
#include <QSettings>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    app.setApplicationName("Monarchy");
    app.setApplicationVersion("0.1.0");
    app.setOrganizationName("monarchy");
    app.setOrganizationDomain("monarchy.org");

    // Fusion gives every desktop environment the same base metrics; the MMC
    // stylesheet is applied on top of it.
    QApplication::setStyle(QStyleFactory::create(QStringLiteral("Fusion")));

    QPalette palette;
    palette.setColor(QPalette::WindowText, Qt::black);
    palette.setColor(QPalette::ButtonText, Qt::black);
    palette.setColor(QPalette::Text, Qt::black);
    palette.setColor(QPalette::Base, Qt::white);
    palette.setColor(QPalette::AlternateBase, QColor(0xf5, 0xf4, 0xea));
    palette.setColor(QPalette::Window, QColor(0xec, 0xe9, 0xd8));
    palette.setColor(QPalette::Button, QColor(0xec, 0xe9, 0xd8));
    palette.setColor(QPalette::Highlight, QColor(0x31, 0x6a, 0xc5));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    QApplication::setPalette(palette);

    // Load bundled fonts (Selawik -> DejaVu -> system default). The font files
    // are optional until they are added to the resource bundle.
    if (QFile::exists(QStringLiteral(":/fonts/Selawik-Regular.ttf")))
        QFontDatabase::addApplicationFont(QStringLiteral(":/fonts/Selawik-Regular.ttf"));
    if (QFile::exists(QStringLiteral(":/fonts/Selawik-Bold.ttf")))
        QFontDatabase::addApplicationFont(QStringLiteral(":/fonts/Selawik-Bold.ttf"));

    QFont font;
    if (QFontDatabase::families().contains("Selawik")) {
        font.setFamily("Selawik");
        font.setPointSize(9);
    } else if (QFontDatabase::families().contains("DejaVu Sans")) {
        font.setFamily("DejaVu Sans");
        font.setPointSize(9);
    } else {
        font = QApplication::font();
        font.setPointSize(9);
    }
    QApplication::setFont(font);

    // Load MMC stylesheet
    QFile styleFile(":/styles/mmc.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream stream(&styleFile);
        app.setStyleSheet(stream.readAll());
    }

    MainWindow window;
    window.show();

    return app.exec();
}