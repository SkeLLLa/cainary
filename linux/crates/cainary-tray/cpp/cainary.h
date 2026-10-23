#pragma once

#include <QByteArray>
#include <QRect>
#include <QString>

class QQmlApplicationEngine;
class QScreen;

namespace cainary {

// qt_shims.cpp
void cainary_install_message_handler();
void cainary_clear_messages();
QString cainary_messages();
QString cainary_controls_style();
QString cainary_platform_name();
QString cainary_qt_version();
QString cainary_format_time(const QString &timestamp);
void cainary_copy_text(const QString &text);
bool cainary_grab_window(const QString &name, const QString &path);
void cainary_set_dark_palette(bool dark);
// The screen holding (x, y), else the primary one; (0, 0) means the primary screen.
QScreen *screen_for_point(int x, int y);
QRect cainary_available_area(int x, int y);

// icons.cpp
void cainary_set_app_identity();
void cainary_install_icon_provider(QQmlApplicationEngine &engine);
QByteArray cainary_svg_pixmap(const QByteArray &svg, int size);
QString cainary_text_color();
void cainary_keep_running_without_windows();

// layershell.cpp (feature layer-shell)
void cainary_layer_shell_attach();
void cainary_layer_shell_place(int x, int y);

}
