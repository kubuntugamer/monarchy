// SPDX-FileCopyrightText: 2026 Monarchy contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "objecticons.h"

#include <QHash>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>

namespace {

const QColor kOutline(0x2b, 0x4a, 0x73);
const QColor kUserFill(0x7d, 0xa9, 0xdc);
const QColor kUserBack(0xba, 0xd2, 0xec);
const QColor kFolderFill(0xf3, 0xcd, 0x72);
const QColor kFolderOutline(0x8a, 0x6d, 0x2b);
const QColor kGlobeFill(0x6f, 0x9f, 0xd8);
const QColor kGlobeLine(0xdc, 0xe9, 0xf8);
const QColor kMonitorFill(0xd6, 0xdd, 0xe8);
const QColor kMonitorScreen(0x3d, 0x6d, 0xa8);

void drawPerson(QPainter &p, qreal s, qreal x, qreal y, const QColor &fill)
{
    QPen pen(kOutline);
    pen.setWidthF(qMax(1.0, s * 0.9));
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(fill);

    // Head.
    p.drawEllipse(QRectF(x + 2.5 * s, y + 0.5 * s, 5.0 * s, 5.0 * s));

    // Shoulders.
    QPainterPath body;
    body.moveTo(x + 0.5 * s, y + 13.8 * s);
    body.cubicTo(x + 0.7 * s, y + 9.4 * s, x + 2.2 * s, y + 6.8 * s, x + 5.0 * s, y + 6.8 * s);
    body.cubicTo(x + 7.8 * s, y + 6.8 * s, x + 9.3 * s, y + 9.4 * s, x + 9.5 * s, y + 13.8 * s);
    body.closeSubpath();
    p.drawPath(body);
}

void drawFolder(QPainter &p, qreal s)
{
    QPen pen(kFolderOutline);
    pen.setWidthF(qMax(1.0, s * 0.9));
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(kFolderFill);

    QPainterPath folder;
    folder.moveTo(1.5 * s, 4.5 * s);
    folder.lineTo(6.0 * s, 4.5 * s);
    folder.lineTo(7.2 * s, 6.0 * s);
    folder.lineTo(14.5 * s, 6.0 * s);
    folder.lineTo(14.5 * s, 13.0 * s);
    folder.lineTo(1.5 * s, 13.0 * s);
    folder.closeSubpath();
    p.drawPath(folder);

    // Folder lip.
    QPen lip(kFolderOutline.lighter(115));
    lip.setWidthF(qMax(0.8, s * 0.7));
    p.setPen(lip);
    p.drawLine(QPointF(2.2 * s, 7.2 * s), QPointF(13.8 * s, 7.2 * s));
}

void drawGlobe(QPainter &p, qreal s)
{
    QPen pen(kOutline);
    pen.setWidthF(qMax(1.0, s * 0.9));
    p.setPen(pen);
    p.setBrush(kGlobeFill);

    const QRectF globe(2.0 * s, 2.0 * s, 12.0 * s, 12.0 * s);
    p.drawEllipse(globe);

    QPainterPath clip;
    clip.addEllipse(globe);
    p.save();
    p.setClipPath(clip);

    QPen line(kGlobeLine);
    line.setWidthF(qMax(0.8, s * 0.7));
    p.setPen(line);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(QRectF(5.6 * s, 2.0 * s, 4.8 * s, 12.0 * s));
    p.drawEllipse(QRectF(2.0 * s, 5.6 * s, 12.0 * s, 4.8 * s));
    p.drawLine(QPointF(2.0 * s, 8.0 * s), QPointF(14.0 * s, 8.0 * s));
    p.drawLine(QPointF(8.0 * s, 2.0 * s), QPointF(8.0 * s, 14.0 * s));

    p.restore();
}

void drawComputer(QPainter &p, qreal s)
{
    QPen pen(kOutline);
    pen.setWidthF(qMax(1.0, s * 0.9));
    p.setPen(pen);

    p.setBrush(kMonitorFill);
    p.drawRoundedRect(QRectF(1.4 * s, 2.4 * s, 13.2 * s, 8.8 * s), 1.0 * s, 1.0 * s);

    p.setBrush(kMonitorScreen);
    p.drawRect(QRectF(2.9 * s, 3.8 * s, 10.2 * s, 5.9 * s));

    p.setBrush(kGlobeLine);
    p.setOpacity(0.55);
    p.drawRect(QRectF(3.4 * s, 4.3 * s, 4.2 * s, 1.4 * s));
    p.setOpacity(1.0);

    p.setBrush(QColor(0x9a, 0xa8, 0xb8));
    p.drawRect(QRectF(6.7 * s, 11.2 * s, 2.6 * s, 1.7 * s));
    p.drawRect(QRectF(4.4 * s, 12.9 * s, 7.2 * s, 1.3 * s));
}

QPixmap renderIcon(ObjectKind kind, int size)
{
    QPixmap pixmap(size, size);
    pixmap.fill(Qt::transparent);

    QPainter p(&pixmap);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::SmoothPixmapTransform, true);

    const qreal s = size / 16.0;

    switch (kind) {
    case ObjectKind::User:
        drawPerson(p, s, 3.3, 0.8, kUserFill);
        break;
    case ObjectKind::Group:
        drawPerson(p, s * 0.78, 0.4, 1.0, kUserBack);
        drawPerson(p, s * 0.86, 5.6, 3.2, kUserFill);
        break;
    case ObjectKind::Computer:
        drawComputer(p, s);
        break;
    case ObjectKind::Ou:
        drawFolder(p, s);
        break;
    case ObjectKind::Domain:
        drawGlobe(p, s);
        break;
    case ObjectKind::Container:
    case ObjectKind::Unknown:
        drawFolder(p, s);
        break;
    }

    p.end();
    return pixmap;
}

} // namespace

QIcon objectIcon(ObjectKind kind)
{
    static QHash<int, QIcon> cache;

    const int key = static_cast<int>(kind);
    const auto cached = cache.constFind(key);
    if (cached != cache.constEnd())
        return cached.value();

    QIcon icon;
    for (int size : {16, 24, 32, 48})
        icon.addPixmap(renderIcon(kind, size));

    cache.insert(key, icon);
    return icon;
}
