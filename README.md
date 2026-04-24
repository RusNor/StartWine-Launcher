![sw_image1](/data/img/gui_icons/default_sample.svg)

## StartWine is a launcher that allows you to quickly and easily launch Windows applications on Linux operating systems

# **StartWine Guide**

**English** - [Русский](/README-RU.md)

## Review
1. [Setup](#setup)
2. [Build](#build)
3. [GUI](#gui)
4. [Creating shortcuts and running games](#creating-shortcuts-and-running-games)
5. [What is used in StartWine?](#what-is-used-in-startwine)
6. [Thank you!](#thank-you)
7. [Useful links](#useful-links)
8. [License](#license)

## Setup
To start using the program, download StartWine itself from the GitHub page in the releases section. Make the file executable, move it to the terminal and press Enter.

GitHub > [Click](https://github.com/RusNor/StartWine-Launcher/releases)

AUR > [Click](https://aur.archlinux.org/packages/startwine)

## Installation with one command:
Copy one of the commands, paste it into the terminal and press Enter.
```
bash -c "$(curl -sL RusNor.github.io)"
```
```
bash -c "$(wget -qO - RusNor.github.io)"
```
The command for Ubuntu if the installation suddenly fails
```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```
```
sudo tee -a /etc/sysctl.d/98-apparmor-unuserns.conf <<<kernel.apparmor_restrict_unprivileged_userns=0
```

## Build

```
## StartWine build dependencies:
     python3 >= 3.13
     cargo >= 1.88
     rustup
     gettext
     cairo
     glib
     gio
     gobject
     gdk-pixbuf
     gdk4
     pango
     graphene
     gsk4
     gtk4
     libraw
```
```
git clone https://github.com/RusNor/StartWine-Launcher.git
cd StartWine-Launcher
./build help
```
```
-----------------------------------------------------
USAGE:
    [./build] [COMMAND] [PATH]
-----------------------------------------------------
DEFAULT PATH: /home/$USER
-----------------------------------------------------
COMMANDS:
    all                   Build all ( release source and runtime ).
    release               Build the release and download the latest runtime.
    naked                 Build the release without runtime. ( not recommended )
    rust                  Build only the rust source.
    python                Build only the python source.
    runtime               Build only the runtime.
    download-base         Download the minimal base runtime.
    download-runtime      Download the latest release runtime.
    clean                 Remove build files.
    clean-download        Remove downloaded files.
    clean-all             Remove all build and downloaded files.
    help                  Print help.
    -----------------------------------------------------
```
## GUI
StartWine Screenshots

![sw_image1](/handbook/en/sw_image1.png)
![sw_image2](/handbook/en/sw_image2.png)
![sw_image3](/handbook/en/sw_image3.png)
![sw_image4](/handbook/en/sw_image4.png)
![sw_image5](/handbook/en/sw_image5.png)
![sw_image6](/handbook/en/sw_image6.png)
![sw_image7](/handbook/en/sw_image7.png)
![sw_image8](/handbook/en/sw_image8.png)
![sw_image9](/handbook/en/sw_image9.png)
![sw_image10](/handbook/en/sw_image10.png)
![sw_image11](/handbook/en/sw_image11.png)
![sw_image12](/handbook/en/sw_image12.png)
![sw_image13](/handbook/en/sw_image13.png)

## Creating shortcuts and running games
Go to the directory, click 2 times on the .exe file and select “Create shortcut”

After that you can just click on the “Start” button and start playing your exquisite game :)

Tip!

* In some cases, it may turn out that the installation is going, but the percentages are not going, and the culprit is in my or maybe you have it [NTFS](https://en.wikipedia.org/wiki/NTFS) the partition of the disk from which you started the installer. The fact is that if you have a so-called [dualbut](https://en.wikipedia.org/wiki/Multi-booting) or multi-boot, call it as you like, then if you have not booted from Windows, then Windows will safely take away your rights to any actions on files.
What should I do in this case?
* Option 1: Just reboot into Windows, you don't have to be logged in, then reboot into your Linux distribution. Or after booting into Windows, disable hibernation mode. How to do this? look on the internet.
* Option 2: In the folder where you have the files with the game installer, copy it and transfer it to the Linux partition, preferably in the /home/$USER/ (where $USER should be your username) section.

## What is used in StartWine?
StartWine was written from scratch, but using already ready-made components without which the program itself did not appear
> List 

* [GTK 4](https://www.gtk.org/)
* [Wine-Staging](https://github.com/Kron4ek/Wine-Builds)
* [Proton GE](https://github.com/GloriousEggroll/proton-ge-custom)
* [Proton EM](https://github.com/Etaash-mathamsetty/Proton)
* [Steam Proton](https://github.com/ValveSoftware/Proton)
* [DXVK](https://github.com/doitsujin/dxvk)
* [VK3D](https://github.com/HansKristian-Work/vkd3d-proton)
* [MangoHud](https://github.com/flightlessmango/MangoHud) (Thanks [VHSgunzo](https://github.com/VHSgunzo) for the patch to work on Nvidia graphics cards!)
* [vkBasalt](https://github.com/DadSchoorse/vkBasalt)
* [Mesa](https://www.mesa3d.org/)
* [Runimage](https://github.com/VHSgunzo/runimage)
* [Runimage nvidia drivers](https://github.com/VHSgunzo/runimage-nvidia-drivers)
* [AMD FSR](https://github.com/GPUOpen-Effects/FidelityFX-FSR2)
* [dgVoodoo2](http://dege.freeweb.hu/dgVoodoo2/dgVoodoo2/)
* [DLSS](https://www.nvidia.com/en-us/geforce/technologies/dlss/)

## Thank you!

> **Developers**

- [Rustam Normatov](https://github.com/RusNor)
- [Nikita Maslov](https://github.com/nix-on-nix)

> **Created and helped write code**

- [Rustam Normatov](https://github.com/RusNor)
- [Nikita Maslov](https://github.com/nix-on-nix)
- [Maxim Tarasov](https://github.com/VHSgunzo)

> **Participants in the project**

- StartWine Community
- Андрей
- 3y6HuK
- Alexandrdrdr
- Huskysoul
- kazbek
- Kot41ru
- Fanchji (Vitaly)
- Survolog
- Lex
- Lintech
- Sheridan
- Wik

> **Project design**

StartWine Design Socialist Party

Thank you to everyone who participated in the testing and development of StartWine, as well as in supporting it with their enthusiasm and great patience. ❤️

## Useful links

The author of the manual > [Lintech](https://www.youtube.com/c/Lintech8)

Website > [Click](https://web.startwine-launcher.ru/)

Telegram > [Click](https://t.me/StartWine)

Discord server > [Discord](https://discord.gg/jjY3auVdfm)

## License

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Copyright (C) Maslov N.G. Normatov R.R.

This file is part of StartWine-Launcher.

StartWine-Launcher is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

StartWine-Launcher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with StartWine-Launcher.  If not, see <http://www.gnu.org/licenses/>.
