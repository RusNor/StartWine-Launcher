![sw_image1](/handbook/sw_logo.svg)

> StartWine is a launcher that allows you to quickly and easily launch Windows applications on Linux operating systems

# **StartWine Guide**
**English** - [Русский](/handbook/README-RU.md)

## Review
1. [Setup](#setup)
2. [GUI](#gui)
3. [Creating shortcuts and running games](#creating-shortcuts-and-running-games)
4. [What is used in StartWine?](#what-is-used-in-startwine)
5. [Thank you!](#thank-you)
6. [Useful links](#useful-links)
7. [License](#license)

## Setup
To start using the program, download StartWine itself from the GitHub page under sw_releases or from the discord server

GitHub > [Click](https://github.com/RusNor/StartWine-Launcher/releases)

AUR > [I use Arch :p](https://aur.archlinux.org/packages/startwine)

RPN-based > [Releases](https://github.com/RusNor/StartWine-Launcher/releases)

Discord > [Click](https://discord.gg/jjY3auVdfm)

Make the file executable and launch it with a double click

## GUI

Video demonstration of StartWine interface

https://github.com/RusNor/StartWine-Launcher/assets/81373196/2aa73e3c-87ed-4e99-a110-5112a7cd128a

If you need quick access to folders or to add your own folder to a bookmark, click on the corresponding icon as shown in the video demonstration.

https://github.com/RusNor/StartWine-Launcher/assets/81373196/d784f430-357c-49f8-bdcc-90fcd5add1c9

StartWine Screenshots (Doubtful, but okeey)

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

## Creating shortcuts and running games
If you click "NO" in the choice to create a prefix for .exe and other windup formats, the default prefix for the shortcut will be used by default.

Otherwise, just hit the start button and the game will launch

https://github.com/RusNor/StartWine-Launcher/assets/81373196/e4424939-dcf0-4e7b-be05-28f22d6e925c

Note that StartWine has a ``StartWine-Run.desktop`` that is used by default in file managers such as [dolphin](https://en.wikipedia.org/wiki/Dolphin_(file_manager)), [Nautilus](https://en.wikipedia.org/wiki/GNOME_Files) etc. to run a .exe file without the StartWine interface in addition to the usual interface shortcut

Tip!

* In some cases, it may turn out that the installation is going, but the percentages are not going, and the culprit is in my or maybe you have it [NTFS](https://en.wikipedia.org/wiki/NTFS) the partition of the disk from which you started the installer. The fact is that if you have a so-called [dualbut](https://en.wikipedia.org/wiki/Multi-booting) or multi-boot, call it as you like, then if you have not booted from Windows, then Windows will safely take away your rights to any actions on files.
What should I do in this case?
* Option 1: Just reboot into Windows, you don't have to be logged in, then reboot into your Linux distribution. Or after booting into Windows, disable hibernation mode. How to do this? look on the internet.
* Option 2: In the folder where you have the files with the game installer, copy it and transfer it to the Linux partition, preferably in the /home/$USER/ (where $USER should be your username) section.

## What is used in StartWine?
StartWine was written from scratch, but using already ready-made components without which the program itself did not appear
> List 

* [GTK 4](https://www.gtk.org/)
* [Wine](https://www.winehq.org/)
* [Wine-Staging](https://github.com/Kron4ek/Wine-Builds)
* [Wine GE](https://github.com/GloriousEggroll/wine-ge-custom)
* [Proton GE](https://github.com/GloriousEggroll/proton-ge-custom)
* [Steam Proton](https://github.com/ValveSoftware/Proton)
* [Lutris](https://github.com/lutris/wine)
* [Lutris GE](https://github.com/GloriousEggroll/proton-ge-custom)
* [DXVK](https://github.com/doitsujin/dxvk)
* [DXVK GE](https://github.com/GloriousEggroll/wine-ge-custom)
* [VK3D](https://github.com/HansKristian-Work/vkd3d-proton)
* [VK3D GE](https://github.com/GloriousEggroll/wine-ge-custom)
* [MangoHud](https://github.com/flightlessmango/MangoHud) (Thanks [VHSgunzo](https://github.com/VHSgunzo) for the patch to work on Nvidia graphics cards!)
* [vkBasalt](https://github.com/DadSchoorse/vkBasalt)
* [gamemode](https://github.com/FeralInteractive/gamemode)
* [Mesa](https://www.mesa3d.org/)
* [Runimage](https://github.com/VHSgunzo/runimage)
* [Runimage nvidia drivers](https://github.com/VHSgunzo/runimage-nvidia-drivers)
* [AMD FSR](https://github.com/GPUOpen-Effects/FidelityFX-FSR2)
* [dgVoodoo2](http://dege.freeweb.hu/dgVoodoo2/dgVoodoo2/)
* [DLSS](https://www.nvidia.com/en-us/geforce/technologies/dlss/)

## Thank you!

> **Developers**

- [Rustan Normatov](https://github.com/RusNor)
- [Nikita Maslov](https://github.com/nix-on-nix)

> **Created and helped write code**

- [Rustan Normatov](https://github.com/RusNor)
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
- LinuxShef
- Sheridan
- Wik

> **Project design**

StartWine Design Socialist Party

Thank you to everyone who participated in the testing and development of StartWine, as well as in supporting it with their enthusiasm and great patience. ❤️

## Useful links

The author of the manual > [Lintech](https://www.youtube.com/c/Lintech8)

Website > [Click](https://startwine-project.ru/)

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
