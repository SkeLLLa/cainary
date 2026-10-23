#include "cainary.h"

#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHash>
#include <QIcon>
#include <QImage>
#include <QPainter>
#include <QPalette>
#include <QtEndian>
#include <QQmlApplicationEngine>
#include <QQuickImageProvider>
#include <QStandardPaths>

#ifdef CAINARY_HAVE_QTSVG
#include <QSvgRenderer>
#endif

namespace cainary {
namespace {

QString scalable_icon_file(const QString &subdir, const QString &name);

class CainaryIconProvider final : public QQuickImageProvider
{
public:
    CainaryIconProvider()
        : QQuickImageProvider(QQuickImageProvider::Image)
    {
    }

    QImage requestImage(const QString &id, QSize *size, const QSize &requested_size) override
    {
        static const QHash<QString, QStringList> themes = {
            {"app", {"ua.SkeLLLa.cAInary"}},
            {"claude", {"claude", "com.anthropic.claude"}},
            {"openai", {"chatgpt", "codex"}},
            {"cursor", {"cursor"}},
            {"copilot", {"github-copilot", "code"}},
            {"device", {"computer-laptop", "computer"}},
            {"device-management", {"applications-office", "building"}},
            {"network-proxy", {"network-workgroup"}},
            {"shield", {"security-high"}},
        };
        const QStringList candidates = themes.value(id);

        const QSize target = requested_size.isValid() ? requested_size : QSize(64, 64);
        QImage image;
        for (const QString &candidate : candidates) {
            const QIcon icon = QIcon::fromTheme(candidate);
            if (icon.isNull())
                continue;
            image = icon.pixmap(target).toImage();
            if (!image.isNull())
                break;
        }
        if (image.isNull() && id == QLatin1String("app")) { // not in the theme: the bundled SVG
            const QString file = scalable_icon_file(QStringLiteral("apps"), candidates.first());
            if (!file.isEmpty())
                image = QIcon(file).pixmap(target).toImage();
        }
        // Qt's QQuickImage warns for a null image-provider result. A transparent sentinel keeps
        // the request warning-free; the QML component can fall back to its monogram.
        if (image.isNull()) {
            image = QImage(1, 1, QImage::Format_ARGB32_Premultiplied);
            image.fill(Qt::transparent);
        }
        if (size)
            *size = image.size();
        return image;
    }
};

// The scalable icon `name` in `subdir` (apps): $CAINARY_ICON_THEME_PATH first, then the
// data dirs, which include a private prefix's share/ (see env_defaults.rs).
QString scalable_icon_file(const QString &subdir, const QString &name)
{
    const QString relative = QStringLiteral("hicolor/scalable/%1/%2.svg").arg(subdir, name);
    const QString override = qEnvironmentVariable("CAINARY_ICON_THEME_PATH");
    if (!override.isEmpty() && QFileInfo::exists(QDir(override).filePath(relative)))
        return QDir(override).filePath(relative);
    for (const QString &root : QStandardPaths::standardLocations(QStandardPaths::GenericDataLocation)) {
        const QString candidate = QDir(root).filePath(QStringLiteral("icons/") + relative);
        if (QFileInfo::exists(candidate))
            return candidate;
    }
    return {};
}

} // namespace

// Ties every window to the desktop entry the tray icon and notifications already name: the
// Wayland app_id (and X11 WM_CLASS) picks the dock/taskbar entry and its icon. The window icon
// covers a dev run, where no desktop entry is installed. Call before any window exists.
void cainary_set_app_identity()
{
    const QString id = QStringLiteral("ua.SkeLLLa.cAInary");
    QGuiApplication::setDesktopFileName(id);
    QIcon icon = QIcon::fromTheme(id);
    if (icon.isNull()) {
        const QString file = scalable_icon_file(QStringLiteral("apps"), id);
        if (!file.isEmpty())
            icon = QIcon(file);
    }
    if (!icon.isNull())
        QGuiApplication::setWindowIcon(icon);
}

void cainary_install_icon_provider(QQmlApplicationEngine &engine)
{
    engine.addImageProvider(QStringLiteral("cainary-icon"), new CainaryIconProvider());
}

// `svg` drawn as `size`x`size` ARGB32 in network byte order, which is what ksni expects whatever
// the host's endianness. Empty for a non-positive size or an SVG that can't be drawn.
QByteArray cainary_svg_pixmap(const QByteArray &svg, int size)
{
    if (size <= 0)
        return {};
    QImage image(size, size, QImage::Format_ARGB32);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    bool drawn = false;
#ifdef CAINARY_HAVE_QTSVG
    QSvgRenderer renderer(svg);
    drawn = renderer.isValid();
    if (drawn)
        renderer.render(&painter, QRectF(0, 0, size, size));
#endif
    if (!drawn) {
        const QImage loaded = QImage::fromData(svg, "SVG");
        drawn = !loaded.isNull();
        if (drawn)
            painter.drawImage(QRect(0, 0, size, size), loaded);
    }
    painter.end();
    if (!drawn)
        return {};

    // ARGB32 rows are 32-bit aligned, so the pixels are contiguous.
    QByteArray bytes(size * size * 4, Qt::Uninitialized);
    qToBigEndian<quint32>(image.constBits(), size * size, bytes.data());
    return bytes;
}

// The desktop's text color as #rrggbb: the closest guess at the panel's for icons we draw.
QString cainary_text_color()
{
    return QGuiApplication::palette().color(QPalette::WindowText).name();
}

// Windows close to the tray; the app quits from its menu, or from Details when there's no tray.
void cainary_keep_running_without_windows()
{
    QGuiApplication::setQuitOnLastWindowClosed(false);
}

} // namespace cainary
