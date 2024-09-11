#!/usr/bin/env python3

################################___TRAY___:

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, GLib, Gio

import os
from sys import argv
from pathlib import Path
from subprocess import Popen

from sw_data import (
    str_tray_open, str_tray_hide, str_tray_run, str_tray_shortcuts, str_tray_stop, str_tray_shutdown
)

sw_link = Path(argv[0]).absolute().parent
sw_scripts = f"{sw_link}"
sw_path = Path(sw_scripts).parent.parent
sw_fsh = Path(f"{sw_scripts}/sw_function.sh")
sw_run = Path(f"{sw_scripts}/sw_run")
sw_menu = Path(f"{sw_scripts}/sw_menu.py")
sw_shortcuts = Path(f"{sw_path}/Shortcuts")

####___SET_PROGRAM_NAME___:

program_name = GLib.set_prgname('StartWine')

####___REQUIRE_VERSION___:

appind = 1

try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as appindicator
except (Exception,):
    try:
        gi.require_version('AppIndicator3', '0.1')
        from gi.repository import AppIndicator3 as appindicator
    except (Exception,):
        appind = 0

APPINDICATOR_ID = 'StartWine'
DIRPATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

####___TRAY_MENU___:


def tray_main():

    def on_startwine(_):
        """___Show or hide StartWine window___"""

        if _.get_label() == str_tray_open:
            _.set_label(str_tray_hide)
        else:
            _.set_label(str_tray_open)

        try:
            proxy.call_sync(
                    "ShowHide", None, Gio.DBusCallFlags.NO_AUTO_START, 500, None
            )
        except (Exception,):
            Popen(f'{sw_menu}', shell=True)

    def on_shortcuts_fr_item(_):
        """___Show shortcuts list for run app___"""

        fr_label = _.get_label()
        fr_name = _.get_name()

        if fr_label != f'StartWine':
            d_exec = [x.split('=')[1] for x in Path(fr_name).read_text().splitlines() if 'Exec=' in x]
            if len(d_exec) > 0:
                exe = [x for x in d_exec[0].split('"') if '.exe' in x.lower()]
                msi = [x for x in d_exec[0].split('"') if '.msi' in x.lower()]
                bat = [x for x in d_exec[0].split('"') if '.bat' in x.lower()]
                lnk = [x for x in d_exec[0].split('"') if '.lnk' in x.lower()]

                if len(exe) > 0:
                    x_path = exe[0]

                elif len(msi) > 0:
                    x_path = msi[0]

                elif len(bat) > 0:
                    x_path = bat[0]

                elif len(lnk) > 0:
                    x_path = lnk[0]
                else:
                    x_path = None

                if x_path is not None and Path(x_path).exists():
                    text = f'"{x_path}"'
                    message = GLib.Variant("(s)", (text,))
                    try:
                        proxy.call_sync(
                                "Run", message, Gio.DBusCallFlags.NO_AUTO_START, 500, None
                        )
                    except Exception as e:
                        print(e)
                else:
                    try:
                        text = 'lnk_error'
                        message = GLib.Variant("(s)", (text,))
                        proxy.call_sync(
                                "Message", message, Gio.DBusCallFlags.NO_AUTO_START, 500, None
                        )
                    except (Exception,):
                        pass

    def on_shortcuts_sc_item(_):
        """___Show shortcuts list for open app___"""

        sc_label = _.get_label()
        sc_name = _.get_name()
        cmd_startwine.set_label(str_tray_hide)

        if sc_label == f'StartWine':
            try:
                proxy.call_sync(
                        "Show", None, Gio.DBusCallFlags.NO_AUTO_START, 500, None
                )
            except (Exception,):
                pass
        else:
            d_exec = [x.split('=')[1] for x in Path(sc_name).read_text().splitlines() if 'Exec=' in x]
            if len(d_exec) > 0:
                exe = [x for x in d_exec[0].split('"') if '.exe' in x.lower()]
                msi = [x for x in d_exec[0].split('"') if '.msi' in x.lower()]
                bat = [x for x in d_exec[0].split('"') if '.bat' in x.lower()]
                lnk = [x for x in d_exec[0].split('"') if '.lnk' in x.lower()]

                if len(exe) > 0:
                    x_path = exe[0]

                elif len(msi) > 0:
                    x_path = msi[0]

                elif len(bat) > 0:
                    x_path = bat[0]

                elif len(lnk) > 0:
                    x_path = lnk[0]

                else:
                    x_path = None

                if x_path is not None and Path(x_path).exists():
                    text = f'"{x_path}"'
                    message = GLib.Variant("(s)", (text,))
                    try:
                        proxy.call_sync(
                                "Show", message, Gio.DBusCallFlags.NO_AUTO_START, 500, None
                        )
                    except Exception as e:
                        print(e)
                else:
                    try:
                        text = 'lnk_error'
                        message = GLib.Variant("(s)", (text,))
                        proxy.call_sync(
                                "Message", message, Gio.DBusCallFlags.NO_AUTO_START, 500, None
                        )
                    except (Exception,):
                        pass

    def stop(_):
        """___Stop all wine processes___"""

        cmd = f"{sw_scripts}/sw_stop"
        Popen(cmd, shell=True)

    def shutdown(_):
        """___StartWine shutdown___"""

        try:
            proxy.call_sync(
                            "Shutdown", None, Gio.DBusCallFlags.NO_AUTO_START, 500, None
            )
        except (Exception,):
            cmd = f"{sw_scripts}/sw_stop"
            Popen(cmd, shell=True)
            Gtk.main_quit()
        else:
            cmd = f"{sw_scripts}/sw_stop"
            Popen(cmd, shell=True)
            Gtk.main_quit()

    def on_check_sc(_):

        sc_path = [sc for sc in list(Path(sw_shortcuts).iterdir())]
        if len(sc_path) == 0:
            pass

    ############################___MAIN_MENU___:

    def on_menu_restruct(menu_item):

        get_submenu = menu_item.get_submenu()
        menu_item_name = [item.get_name() for item in list(get_submenu.get_children())]
        menu_item_widget = [item for item in list(get_submenu.get_children())]
        sc_path = [sc for sc in sorted(list(Path(sw_shortcuts).iterdir()), key=lambda x: str(x).lower())]

        for widget in list(menu_item_widget):
            if not str(widget.get_name()) in str(sc_path):
                get_submenu.remove(widget)

        count = -1
        for sc in list(sc_path):
            count += 1
            if not str(sc) in str(menu_item_name):
                item_ = Gtk.MenuItem.new_with_label('')
                item_.set_label(str(sc.stem))
                item_.set_name(str(sc))
                if menu_item == sc_menu_item:
                    item_.connect('activate', on_shortcuts_sc_item)
                if menu_item == fr_menu_item:
                    item_.connect('activate', on_shortcuts_fr_item)
                get_submenu.insert(item_, count)
                print(item_.get_name())
        menu_item.show_all()
        return True

    ####___MAIN_MENU___:

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    proxy = Gio.DBusProxy.new_sync(
                                    bus,
                                    Gio.DBusProxyFlags.NONE,
                                    None,
                                    "ru.project.StartWine",
                                    "/ru/project/StartWine",
                                    "ru.project.StartWine",
                                    None,
    )
    indicator = appindicator.Indicator.new(
                            APPINDICATOR_ID, DIRPATH + "/img/gui_icons/sw.svg",
                            appindicator.IndicatorCategory.APPLICATION_STATUS
    )
    indicator.set_status(appindicator.IndicatorStatus.ACTIVE)

    menu = Gtk.Menu()
    indicator.set_menu(menu)

    cmd_startwine = Gtk.MenuItem.new_with_label(str_tray_hide)
    cmd_startwine.connect('activate', on_startwine)
    menu.append(cmd_startwine)

    fr_menu_item = Gtk.MenuItem.new_with_label(str_tray_run)
    fr_menu_item.connect('activate', on_check_sc)
    menu.append(fr_menu_item)

    fr_submenu = Gtk.Menu()
    fr_menu_item.set_submenu(fr_submenu)

    for fr in sorted(list(Path(sw_shortcuts).iterdir()), key=lambda x: str(x).lower()):
        fr_item = Gtk.MenuItem.new_with_label('')
        fr_item.set_label(str(fr.stem))
        fr_item.set_name(str(fr))
        fr_item.connect('activate', on_shortcuts_fr_item)
        fr_submenu.append(fr_item)

    sc_menu_item = Gtk.MenuItem.new_with_label(str_tray_shortcuts)
    sc_menu_item.connect('activate', on_check_sc)
    menu.append(sc_menu_item)

    sc_submenu = Gtk.Menu()
    sc_menu_item.set_submenu(sc_submenu)

    for sc in sorted(list(Path(sw_shortcuts).iterdir()), key=lambda x: str(x).lower()):
        sc_item = Gtk.MenuItem.new_with_label('')
        sc_item.set_label(str(sc.stem))
        sc_item.set_name(str(sc))
        sc_item.connect('activate', on_shortcuts_sc_item)
        sc_submenu.append(sc_item)

    cmd_stop = Gtk.MenuItem.new_with_label(str_tray_stop)
    cmd_stop.connect('activate', stop)
    menu.append(cmd_stop)

    cmd_shutdown = Gtk.MenuItem.new_with_label(str_tray_shutdown + ' StartWine')
    cmd_shutdown.connect('activate', shutdown)
    menu.append(cmd_shutdown)

    GLib.timeout_add(1000, on_menu_restruct, sc_menu_item)
    GLib.timeout_add(1000, on_menu_restruct, fr_menu_item)
    menu.show_all()
    Gtk.main()


if __name__ == "__main__":

    if appind == 1:
        tray_main()
    else:
        print('SW_TRAY: error, appindicator not found')
