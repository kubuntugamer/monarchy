# Monarchy — UI Design: Classic MMC Console on Qt 6

## 1. Goal

Reproduce the **classic Microsoft Management Console (MMC)** look and behaviour on Linux, using **Qt 6 Widgets**,
while remaining **multi-distro / multi-DE friendly**. The result must be indistinguishable from the Windows
console to an AD administrator, but built entirely from independently authored code and artwork.

This console is the **Monarchy Management Console** — the GUI half of the Monarchy project. Its binary is
`monarchy-ui`; `monarchy-provision` creates the domain it administers.

**Reference:** [`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md) §0 (reference, don't ship) and §2 (console
catalogue). Legal basis: [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) §13.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  monarchy-ui — Monarchy Management Console (Qt 6)           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Console frame: menu bar, toolbar, status bar         │  │
│  │  ┌──────────────┬──────────────────────────────────┐  │  │
│  │  │ Console tree │ Results pane (view-dependent)    │  │  │
│  │  │ (QTreeView)  │ (QTableView / QListWidget)       │  │  │
│  │  └──────────────┴──────────────────────────────────┘  │  │
│  │  Snap-in host: QPluginLoader-based snap-in modules    │  │
│  │  .msc parser: console file loader/saver               │  │
│  └───────────────────────────────────────────────────────┘  │
│  ad-snapins: ADUC, ADSS, ADDT, Schema, GPMC, DNS, ...      │
│  ad-icons:   own icon theme (Windows-like shape language)  │
└─────────────────────────────────────────────────────────────┘
         │ (LDAP / DCE-RPC / RPC over TCP)
         ▼
   Monarchy backend (Samba-derived protocol engine)
```

### Key decisions

| Decision | Choice | Rationale |
|---|---|---|
| UI toolkit | **Qt 6 Widgets** | Cross-platform, native look, excellent model/view, QSS styling, mature on Linux. Not QML (desktop app, not touch). |
| Build system | **CMake 3.16+** | Qt Creator 6 native support; standard for Qt 6. |
| C++ standard | **C++17** | Qt 6 baseline; wide compiler support. |
| Style base | **QFusionStyle** | Clean, consistent, cross-DE. Custom QSS on top for the MMC look. |
| Config format | **INI via QSettings** | Portable across distros; no DE-specific assumptions. |
| Config location | **XDG Base Directory** | `~/.config/monarchy/` (or `$XDG_CONFIG_HOME`). |
| Icons | **Bundled + QIcon::fromTheme()** | Bundled MMC-style icons with system-theme fallback. |
| Fonts | **Selawik (OFL) / DejaVu Sans** | Metric-compatible with Segoe UI / Tahoma; see §5. |
| Snap-ins | **QPluginLoader (.so)** | Standard Qt plugin mechanism; each snap-in is a shared library. |
| Console files | **.msc (XML)** | MMC-compatible format; reimplement the parser. |

---

## 3. Classic MMC layout

```
┌─────────────────────────────────────────────────────────────┐
│ File  Action  View  Favorites  Window  Help                  │  Menu bar
├─────────────────────────────────────────────────────────────┤
│ [←][→][↑][📁][➕][🗑][📋][🔍][👁][⟳]                    │  Toolbar (16×16 icons)
├──────────────┬──────────────────────────────────────────────┤
│              │ Name        Type        Description           │
│  Console     │──────────────────────────────────────────────│
│  Root        │ 👤 User1    User        Sales dept            │
│  ├ Users     │ 👥 Group1   Group       ...                   │
│  ├ Groups    │ 💻 PC1      Computer    ...                   │
│  └ Computers │                                              │
│              │                                              │
│              │                                              │
├──────────────┴──────────────────────────────────────────────┤
│ Ready                                                       │  Status bar
└─────────────────────────────────────────────────────────────┘
```

### Menu bar (classic MMC)
- **File:** New, Open, Save, Save As, Options, Exit
- **Action:** New Window, New Taskpad View, Export List, Properties, Delete, Refresh, Help
- **View:** Large Icons, Small Icons, List, Details, Customize, Status Bar, Console Tree, Standard Menus, Advanced Menus
- **Favorites:** Add to Favorites, Organize Favorites
- **Window:** Cascade, Tile Horizontally, Tile Vertically, Arrange Icons
- **Help:** Help Topics, About

### Toolbar (classic MMC, 16×16 icons)
Back, Forward, Up, New Folder/Object, Delete, Properties, View selector, Refresh, Help.

### Results pane views
- Large Icons (32×32)
- Small Icons (16×16)
- List
- Details (columns: Name, Type, Description, plus object-specific columns)

### Property sheet (classic MMC)
Tabbed dialog: **General**, **Member Of**, **Profile**, **Environment**, **Sessions**, **Remote Control**, **Terminal Services Profile**, **COM+**, plus object-specific tabs. Standard buttons: **OK**, **Cancel**, **Apply**, **Help**.

---

## 4. Multi-distro / multi-DE compatibility

### 4.1 What "multi-DE friendly" means here

The app must run identically on GNOME, KDE Plasma, XFCE, Cinnamon, MATE, LXQt, and bare window managers (i3, sway, dwm), under both X11 and Wayland, on any distro.

### 4.2 Rules

1. **No DE-specific APIs.** No GNOME D-Bus interfaces, no KDE KIO, no XFCE settings. Use Qt abstractions only.
2. **No DE-specific config.** Use `QSettings` with INI format in `$XDG_CONFIG_HOME/monarchy/` (default `~/.config/monarchy/`). Never read `~/.kde/`, `~/.config/gtk-3.0/`, etc.
3. **Icons: bundled first, system theme second.** `QIcon::fromTheme()` with a bundled fallback. Never assume a specific icon theme exists.
4. **Fonts: Qt font resolution + bundled fallback.** Use `QFontDatabase` to find the best available system font; fall back to bundled Selawik/DejaVu. Never hardcode a font name that only exists on one distro.
5. **HiDPI:** Qt 6 handles scaling automatically. Set `QT_AUTO_SCREEN_SCALE_FACTOR=1` (default in Qt 6). Use device-independent pixels in QSS.
6. **Wayland/X11:** Qt 6's platform plugins handle this. Don't call X11-specific APIs directly. Use `QGuiApplication::platformName()` only for diagnostics, never for branching logic.
7. **File dialogs:** Use `QFileDialog` (Qt's, not native) for consistency, or native with fallback. Qt's dialog works on all DEs.
8. **Notifications:** Use `QSystemTrayIcon` if needed; don't depend on a specific notification daemon.
9. **Clipboard:** Use `QClipboard` — works on all platforms.
10. **Theming:** Apply the QSS stylesheet programmatically at startup, overriding the system theme for the MMC look. This guarantees the classic look regardless of the DE's theme.

### 4.3 Platform detection (diagnostics only)

```cpp
qDebug() << "Platform:" << QGuiApplication::platformName();  // "xcb" or "wayland"
qDebug() << "Style:" << QApplication::style()->objectName();
```

Never branch on platform. The QSS + QFusionStyle base guarantees consistency.

---

## 5. Font strategy

### Classic MMC fonts
- **Windows 2000/XP/2003:** Tahoma 8pt (UI), MS Sans Serif 8pt (legacy)
- **Windows Vista+:** Segoe UI 9pt

### Linux equivalents

| Windows font | Linux equivalent | License | Notes |
|---|---|---|---|
| Segoe UI | **Selawik** | SIL OFL 1.1 | Microsoft's own metric-compatible replacement. GitHub: microsoft/Selawik |
| Segoe UI | **DejaVu Sans** | Bitstream Vera (free) | Wider glyphs; adjust spacing |
| Tahoma | **Wine Tahoma** | LGPL | Closest metric match; available in wine-fonts |
| Tahoma | **Liberation Sans** | SIL OFL | Metric-compatible with Arial/Tahoma; Red Hat |
| MS Sans Serif | **DejaVu Sans** | — | Closest available |

### Implementation

```cpp
// In main.cpp, before creating MainWindow:
QFontDatabase::addApplicationFont(":/fonts/Selawik-Regular.ttf");
QFontDatabase::addApplicationFont(":/fonts/Selawik-Bold.ttf");

QFont font;
// Try Selawik first (Segoe UI metric match), then DejaVu, then system default
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
```

Bundle Selawik TTFs in `resources/fonts/`. Fall back gracefully if they fail to load.

---

## 6. Icon strategy

### Icon sizes needed
| Context | Size | Usage |
|---|---|---|
| Toolbar | 16×16 | Back, Forward, Up, New, Delete, Properties, View, Refresh, Help |
| Results pane (large icons) | 32×32 | User, Group, Computer, OU, etc. |
| Results pane (small icons) | 16×16 | Same objects, smaller |
| Console tree | 16×16 | Node type icons |
| Property sheet tabs | 16×16 | Tab icons (optional) |
| Status bar | 16×16 | Status indicators |

### Icon sources
1. **Bundled MMC-style icons** (primary): Drawn in the Windows common-controls style — 16×16 and 32×32, 256-color palette, specific to each object type (user, group, computer, OU, domain, site, etc.).
2. **System theme fallback** (`QIcon::fromTheme()`): If a bundled icon is missing, try the system icon theme. Use standard freedesktop icon names: `system-users`, `system-users-symbolic`, `computer`, `folder`, `preferences-system`, etc.
3. **Never extract from Windows DLLs.** Draw your own or use an open icon set (Adwaita, Breeze) as reference for shape language only.

### Icon naming convention
```
resources/icons/16x16/
  user.png, group.png, computer.png, ou.png, domain.png,
  site.png, subnet.png, sitelink.png, gpo.png, dns.png,
  back.png, forward.png, up.png, new.png, delete.png,
  properties.png, view.png, refresh.png, help.png
resources/icons/32x32/
  user.png, group.png, computer.png, ou.png, domain.png, ...
```

---

## 7. QSS stylesheet — the MMC look

The classic MMC look is achieved with a QSS stylesheet applied at startup. Key visual elements:

```css
/* Main window background */
QMainWindow {
    background-color: #ece9d8;  /* classic Windows XP/2003 gray */
}

/* Menu bar */
QMenuBar {
    background-color: #ece9d8;
    border-bottom: 1px solid #aca899;
    font-size: 8pt;
}
QMenuBar::item:selected {
    background-color: #316ac5;
    color: white;
}

/* Toolbar */
QToolBar {
    background-color: #ece9d8;
    border-bottom: 1px solid #aca899;
    spacing: 2px;
    padding: 2px;
}
QToolButton {
    border: 1px solid transparent;
    padding: 2px;
    margin: 1px;
}
QToolButton:hover {
    border: 1px solid #aca899;
    background-color: #f5f4ea;
}
QToolButton:pressed {
    border: 1px solid #aca899;
    background-color: #d6d2c2;
}

/* Console tree (left pane) */
QTreeView {
    background-color: white;
    border: 1px solid #aca899;
    font-size: 8pt;
    show-decoration-selected: 1;
}
QTreeView::item {
    padding: 1px 2px;
    height: 16px;
}
QTreeView::item:selected {
    background-color: #316ac5;
    color: white;
}
QTreeView::item:hover {
    background-color: #e8e8e8;
}

/* Results pane (right pane) — Details view */
QTableView {
    background-color: white;
    border: 1px solid #aca899;
    gridline-color: #d4d0c8;
    font-size: 8pt;
}
QTableView::item {
    padding: 2px 4px;
    height: 16px;
}
QTableView::item:selected {
    background-color: #316ac5;
    color: white;
}
QHeaderView::section {
    background-color: #ece9d8;
    border: 1px solid #aca899;
    border-left: none;
    border-top: none;
    padding: 2px 4px;
    font-size: 8pt;
    font-weight: bold;
}
QHeaderView::section:hover {
    background-color: #f5f4ea;
}

/* Splitter */
QSplitter::handle {
    background-color: #d4d0c8;
    width: 4px;
}

/* Status bar */
QStatusBar {
    background-color: #ece9d8;
    border-top: 1px solid #aca899;
    font-size: 8pt;
    min-height: 18px;
}
QStatusBar::item {
    border: none;
}

/* Tab widget (property sheets) */
QTabWidget::pane {
    border: 1px solid #aca899;
    background-color: #ece9d8;
}
QTabBar::tab {
    background-color: #ece9d8;
    border: 1px solid #aca899;
    border-bottom: none;
    padding: 3px 8px;
    margin-right: 1px;
    font-size: 8pt;
}
QTabBar::tab:selected {
    background-color: white;
    border-bottom: 1px solid white;
}
QTabBar::tab:hover {
    background-color: #f5f4ea;
}

/* Push buttons (property sheet) */
QPushButton {
    background-color: #ece9d8;
    border: 1px solid #aca899;
    padding: 3px 12px;
    font-size: 8pt;
    min-width: 75px;
    min-height: 23px;
}
QPushButton:hover {
    background-color: #f5f4ea;
}
QPushButton:pressed {
    background-color: #d6d2c2;
}
QPushButton:default {
    border: 1px solid #000000;
}

/* Line edits / inputs */
QLineEdit, QComboBox, QSpinBox {
    border: 1px solid #7f9db9;
    padding: 2px 4px;
    font-size: 8pt;
    background-color: white;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #316ac5;
}

/* Group box */
QGroupBox {
    border: 1px solid #aca899;
    margin-top: 8px;
    padding-top: 8px;
    font-size: 8pt;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
}

/* Scroll bars */
QScrollBar:vertical {
    background-color: #ece9d8;
    width: 16px;
    border: 1px solid #aca899;
}
QScrollBar::handle:vertical {
    background-color: #d4d0c8;
    border: 1px solid #aca899;
    min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background-color: #ece9d8;
    border: 1px solid #aca899;
    height: 16px;
    subcontrol-position: bottom;
}
QScrollBar:horizontal {
    background-color: #ece9d8;
    height: 16px;
    border: 1px solid #aca899;
}
QScrollBar::handle:horizontal {
    background-color: #d4d0c8;
    border: 1px solid #aca899;
    min-width: 20px;
}
```

---

## 8. Project structure

```
monarchy-ui/
├── CMakeLists.txt
├── src/
│   ├── main.cpp
│   ├── mainwindow.h / .cpp          # Console host frame
│   ├── consolehost.h / .cpp         # MMC host logic (.msc loader, snap-in registration)
│   ├── consoleview.h / .cpp         # Tree + results pane splitter
│   ├── consoletreemodel.h / .cpp    # QAbstractItemModel for console tree
│   ├── resultsmodel.h / .cpp        # QAbstractTableModel for results pane
│   ├── propertysheet.h / .cpp       # Tabbed property sheet base class
│   ├── snapin.h / .cpp              # Snap-in interface (QPluginLoader)
│   └── snapins/
│       ├── aduc/                    # Active Directory Users and Computers
│       ├── adss/                    # Sites and Services
│       ├── addt/                    # Domains and Trusts
│       ├── schema/                  # Schema snap-in
│       ├── gpmc/                    # Group Policy Management
│       └── dns/                     # DNS Manager
├── resources/
│   ├── resources.qrc
│   ├── icons/16x16/                 # Toolbar + tree icons
│   ├── icons/32x32/                 # Large result icons
│   ├── fonts/                       # Selawik TTFs
│   └── styles/
│       └── mmc.qss                  # The stylesheet above
└── tests/
    └── ...
```

---

## 9. CMakeLists.txt (Qt 6)

```cmake
cmake_minimum_required(VERSION 3.16)
project(monarchy-ui VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Widgets Core Gui)

add_executable(monarchy-ui
    src/main.cpp
    src/mainwindow.cpp
    src/consolehost.cpp
    src/consoleview.cpp
    src/consoletreemodel.cpp
    src/resultsmodel.cpp
    src/propertysheet.cpp
    src/snapin.cpp
    resources/resources.qrc
)

target_link_libraries(monarchy-ui PRIVATE
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
)

install(TARGETS monarchy-ui DESTINATION bin)
```

---

## 10. main.cpp (entry point)

```cpp
#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <QFile>
#include <QTextStream>
#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Monarchy");  // or whatever name is chosen
    app.setApplicationVersion("0.1.0");
    app.setOrganizationName("monarchy");
    app.setOrganizationDomain("monarchy.org");

    // Load bundled fonts (Selawik → DejaVu → system default)
    QFontDatabase::addApplicationFont(":/fonts/Selawik-Regular.ttf");
    QFontDatabase::addApplicationFont(":/fonts/Selawik-Bold.ttf");

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
```

---

## 11. Multi-DE checklist

Before shipping, verify on:
- [ ] GNOME (Wayland + X11)
- [ ] KDE Plasma (Wayland + X11)
- [ ] XFCE
- [ ] Cinnamon
- [ ] MATE
- [ ] LXQt
- [ ] i3 / sway (bare WM)
- [ ] HiDPI display (2× scaling)
- [ ] Dark system theme (QSS overrides it — verify the MMC look is preserved)
- [ ] Light system theme
- [ ] Font with no Selawik/DejaVu installed (system fallback)

---

## 12. What's NOT in scope for the UI layer

- **No web UI.** This is a desktop application. A web-based admin console (like Windows Admin Center) is a separate project.
- **No mobile.** Desktop only.
- **No theming engine.** The MMC look is fixed. Users don't get to pick themes — the classic look *is* the brand.
- **No custom widget framework.** Use Qt's standard widgets with QSS. Don't reinvent QTreeView or QTableView.

---

> **Legal reminder:** The MMC look is reproduced by **independently authoring** the layout, styling, and artwork.
> Do not extract, trace, or redistribute Microsoft's icons, bitmaps, or screenshots.
> See [`AD-LICENSING-PATENT-CITATION-INDEX.md`](AD-LICENSING-PATENT-CITATION-INDEX.md) §13 and
> [`AD-CONSOLE-IMAGE-INDEX.md`](AD-CONSOLE-IMAGE-INDEX.md) §0.