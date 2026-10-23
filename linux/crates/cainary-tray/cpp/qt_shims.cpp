#include "cainary.h"

#include <QClipboard>
#include <QColor>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QLibraryInfo>
#include <QLocale>
#include <QMutex>
#include <QPalette>
#include <QQuickWindow>
#include <QScreen>

#include <cstdio>

namespace cainary {
namespace {

QMutex messages_mutex;
QStringList captured_messages;

void message_handler(QtMsgType type, const QMessageLogContext &, const QString &message)
{
    // Host icon-theme names (e.g. "Cosmic") may not be installed; that is not a UI defect.
    const bool icon_theme_noise = message.startsWith(QLatin1String("Icon theme \""))
        || message == QLatin1String("This plugin does not support raise()"); // offscreen platform
    if (!icon_theme_noise && (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg)) {
        QMutexLocker lock(&messages_mutex);
        captured_messages.append(message);
    }
    std::fprintf(stderr, "%s\n", message.toLocal8Bit().constData());
}

} // namespace

void cainary_install_message_handler()
{
    qInstallMessageHandler(message_handler);
}

void cainary_clear_messages()
{
    QMutexLocker lock(&messages_mutex);
    captured_messages.clear();
}

QString cainary_messages()
{
    QMutexLocker lock(&messages_mutex);
    return captured_messages.join(QLatin1Char('\n'));
}

QString cainary_controls_style()
{
    QStringList imports = {QLibraryInfo::path(QLibraryInfo::QmlImportsPath)};
    for (const char *variable : {"QML2_IMPORT_PATH", "QML_IMPORT_PATH"}) {
        const QString value = qEnvironmentVariable(variable);
        if (!value.isEmpty())
            imports.append(value.split(QDir::listSeparator()));
    }
    for (const QString &path : imports) {
        if (QDir(QDir(path).filePath(QStringLiteral("org/kde/desktop"))).exists())
            return QStringLiteral("org.kde.desktop");
    }
    return QStringLiteral("Fusion");
}

QString cainary_platform_name()
{
    return QGuiApplication::platformName();
}

QString cainary_qt_version()
{
    return QString::fromLatin1(qVersion());
}

QString cainary_format_time(const QString &timestamp)
{
    QDateTime value = QDateTime::fromString(timestamp, Qt::ISODateWithMs);
    if (!value.isValid())
        value = QDateTime::fromString(timestamp, Qt::ISODate);
    if (!value.isValid())
        return {};
    return QLocale().toString(value.time(), QLocale::ShortFormat);
}

QScreen *screen_for_point(int x, int y)
{
    if (x != 0 || y != 0) {
        for (QScreen *screen : QGuiApplication::screens()) {
            if (screen->geometry().contains(QPoint(x, y)))
                return screen;
        }
    }
    return QGuiApplication::primaryScreen();
}

// Qt main thread only; QML cannot read a screen's available area itself.
QRect cainary_available_area(int x, int y)
{
    QScreen *screen = screen_for_point(x, y);
    return screen ? screen->availableGeometry() : QRect();
}

// Qt main thread only.
void cainary_copy_text(const QString &text)
{
    if (QClipboard *clipboard = QGuiApplication::clipboard())
        clipboard->setText(text);
}

// Hides the window `name` after saving it to `path` as PNG; no save (false) if `path` is empty. The self-test relies on the hide to reset between scenarios.
bool cainary_grab_window(const QString &name, const QString &path)
{
    for (QWindow *window : QGuiApplication::allWindows()) {
        if (window->objectName() != name)
            continue;
        bool saved = false;
        auto *quick = qobject_cast<QQuickWindow *>(window);
        if (!path.isEmpty() && quick) {
            QDir().mkpath(QFileInfo(path).absolutePath());
            quick->requestUpdate();
            QCoreApplication::processEvents();
            saved = quick->grabWindow().save(path, "PNG");
        }
        window->hide();
        return saved;
    }
    return false;
}

void cainary_set_dark_palette(bool dark)
{
    static const QPalette original = QGuiApplication::palette();
    QPalette palette = original;
    if (dark) {
        const std::pair<QPalette::ColorRole, const char *> colors[] = {
            {QPalette::Window, "#232629"}, {QPalette::WindowText, "#eff0f1"},
            {QPalette::Base, "#1b1e20"}, {QPalette::AlternateBase, "#292d30"},
            {QPalette::Text, "#eff0f1"}, {QPalette::Button, "#292d30"},
            {QPalette::ButtonText, "#eff0f1"}, {QPalette::Highlight, "#3daee9"},
            {QPalette::HighlightedText, "#eff0f1"}};
        for (const auto &[role, color] : colors)
            palette.setColor(role, QColor(QLatin1String(color)));
    }
    QGuiApplication::setPalette(palette);
}

} // namespace cainary
