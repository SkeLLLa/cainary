#include "cainary.h"

#include <QDebug>
#include <QGuiApplication>
#include <QMargins>
#include <QPointer>
#include <QRect>
#include <QScreen>
#include <QWindow>

#include <LayerShellQt/Window>

namespace cainary {
namespace {

QPointer<QWindow> popup;
LayerShellQt::Window *layer_window = nullptr;

} // namespace

// Makes the QML window named "popup" a layer surface. Call once after QML has loaded, before the
// window is first shown.
void cainary_layer_shell_attach()
{
    for (QWindow *window : QGuiApplication::allWindows()) {
        if (window->objectName() != QLatin1String("popup"))
            continue;
        layer_window = LayerShellQt::Window::get(window);
        if (!layer_window) {
            qWarning() << "cainary-tray: LayerShellQt could not take the popup window";
            return;
        }
        popup = window;
        layer_window->setLayer(LayerShellQt::Window::LayerTop);
        layer_window->setKeyboardInteractivity(LayerShellQt::Window::KeyboardInteractivityOnDemand);
        layer_window->setExclusiveZone(0);
#ifdef CAINARY_LSQ_HAS_ACTIVATEONSHOW
        layer_window->setActivateOnShow(true);
#endif
        layer_window->setScope(QStringLiteral("cainary-popup"));
#ifdef CAINARY_LSQ_HAS_DESIREDSIZE
        // The popup is as tall as its content, which a hidden window only lays out once shown:
        // the first show maps at a stale height. A layer surface keeps the size it was given,
        // so follow the window's.
        const auto follow_size = [window] {
            if (layer_window && layer_window->desiredSize() != window->size())
                layer_window->setDesiredSize(window->size());
        };
        QObject::connect(window, &QWindow::widthChanged, window, follow_size);
        QObject::connect(window, &QWindow::heightChanged, window, follow_size);
#endif
        return;
    }
    qWarning() << "cainary-tray: no QML window named popup";
}

// Anchors the popup to the screen corner nearest (x, y) with margins that put it under that
// point; (0, 0) means the top right of the primary screen. Call before showing it.
void cainary_layer_shell_place(int x, int y)
{
    if (!popup || !layer_window || popup->isVisible())
        return;
    QScreen *screen = screen_for_point(x, y);
    if (!screen)
        return;
    popup->setScreen(screen);
#ifdef CAINARY_LSQ_HAS_SETSCREEN
    layer_window->setScreen(screen);
#endif

    const QRect area = screen->availableGeometry();
    const int width = popup->width();
    const int height = popup->height();
    const int min_x = area.left() + 8 + width / 2;
    const int max_x = area.right() - 7 - width / 2;
    const int min_y = area.top() + 8 + height / 2;
    const int max_y = area.bottom() - 7 - height / 2;
    const bool top_right_default = x == 0 && y == 0;
    const int point_x = top_right_default ? area.right() - 8 - width / 2 : qBound(min_x, x, qMax(min_x, max_x));
    const int point_y = top_right_default ? area.top() + 8 + height / 2 : qBound(min_y, y, qMax(min_y, max_y));
    const bool anchor_left = !top_right_default && point_x - area.left() <= area.right() - point_x;
    const bool anchor_top = top_right_default || point_y - area.top() <= area.bottom() - point_y;

    LayerShellQt::Window::Anchors anchors;
    anchors.setFlag(anchor_left ? LayerShellQt::Window::AnchorLeft : LayerShellQt::Window::AnchorRight);
    anchors.setFlag(anchor_top ? LayerShellQt::Window::AnchorTop : LayerShellQt::Window::AnchorBottom);
    layer_window->setAnchors(anchors);
    layer_window->setMargins(QMargins(
        anchor_left ? qMax(8, point_x - area.left() - width / 2) : 0,
        anchor_top ? qMax(8, point_y - area.top() - height / 2) : 0,
        anchor_left ? 0 : qMax(8, area.right() - point_x - width / 2),
        anchor_top ? 0 : qMax(8, area.bottom() - point_y - height / 2)));
#ifdef CAINARY_LSQ_HAS_DESIREDSIZE
    layer_window->setDesiredSize(popup->size());
#endif
}

} // namespace cainary
