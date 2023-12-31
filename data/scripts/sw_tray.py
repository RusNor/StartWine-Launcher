#!/usr/bin/env python3

################################___TRAY___:

import gi
gi.require_version('Gtk', '3.0')
gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, GLib, Gdk

import os
from sys import argv
from pathlib import Path
from subprocess import Popen, PIPE, run

from sw_data import (str_tray_open, str_tray_run,
    str_tray_exit, str_tray_stop, str_tray_shortcuts
    )

sw_link = Path(argv[0]).absolute().parent
sw_scripts = f"{sw_link}"
sw_path = Path(sw_scripts).parent.parent
sw_fsh = Path(f"{sw_scripts}/sw_function.sh")
sw_rsh = Path(f"{sw_scripts}/sw_run.sh")
sw_run = Path(f"{sw_scripts}/sw_run")
sw_menu = Path(f"{sw_scripts}/sw_menu.py")
sw_shortcuts = sw_shortcuts = Path(f"{sw_path}/Shortcuts")

####___SET_PROGRAM_NAME___:

program_name = GLib.set_prgname('StartWine')

####___REQUIRE_VERSION___:

appind = 1

try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as appindicator
except:
    try:
        gi.require_version('AppIndicator3', '0.1')
        from gi.repository import AppIndicator3 as appindicator
    except ImportError as e:
        print(f'{e}')
        appind = 0

APPINDICATOR_ID = 'StartWine'
DIRPATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

####___TRAY_MENU___:

def tray_main():

    ####___STARTWINE_RUN___:

    def on_startwine(_):

        Popen(f'"{sw_menu}"', shell=True)

    ####___SHORTCUTS_RUN___:

    def on_shortcuts_fr_item(_):

        fr_label = _.get_label()
        fr_name = _.get_name()

        if fr_label != f'StartWine':
            read_path = Path(fr_name).read_text().split('\n')[2].split('=')[1].split('"')[3]
            sw_rsh.write_text(f'env "{sw_menu}" "{read_path}"')
            run_cmd = f'env "{sw_run}" "{read_path}"'
            Popen(run_cmd, shell=True)

    ####___SHORTCUTS_OPEN___:

    def on_shortcuts_sc_item(_):

        sc_label = _.get_label()
        sc_name = _.get_name()

        if sc_label == f'StartWine':
            run(str(sw_menu), shell=True)
        else:
            read_path = Path(sc_name).read_text().split('\n')[2].split('=')[1].split('"')[3]
            sw_rsh.write_text(f'env "{sw_menu}" "{read_path}"')
            Popen(str(sw_rsh), shell=True)

    ####___STOP___:

    def kill(_):

        cmd = f"{sw_scripts}/sw_stop"
        Popen(cmd, shell=True)

    ####___EXIT___:

    def quit(_):

        Gtk.main_quit()

    def on_check_sc(_):

        sc_path = [sc for sc in list(Path(sw_shortcuts).iterdir())]
        if sc_path == []:
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

    indicator = appindicator.Indicator.new(
        APPINDICATOR_ID, DIRPATH + "/img/gui_icons/sw.svg",
        appindicator.IndicatorCategory.APPLICATION_STATUS
        )
    indicator.set_status(
        appindicator.IndicatorStatus.ACTIVE
        )

    menu = Gtk.Menu()
    indicator.set_menu(menu)

    cmd_startwine = Gtk.MenuItem.new_with_label(str_tray_open)
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

    cmd_kill = Gtk.MenuItem.new_with_label(str_tray_stop)
    cmd_kill.connect('activate', kill)
    menu.append(cmd_kill)

    cmd_quit = Gtk.MenuItem.new_with_label(str_tray_exit)
    cmd_quit.connect('activate', quit)
    menu.append(cmd_quit)

    GLib.timeout_add(1000, on_menu_restruct, sc_menu_item)
    GLib.timeout_add(1000, on_menu_restruct, fr_menu_item)
    menu.show_all()
    Gtk.main()

if __name__ == "__main__":
    if appind == 1:
        tray_main()
    else:
        print('SW_TRAY: error, appindicator not found')

