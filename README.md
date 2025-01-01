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

Discord > [Click](https://discord.gg/jjY3auVdfm)

Make the file executable and launch it with a double click

## Installation with one command:
```bash
bash -c "$(curl -sL RusNor.github.io)"
```
or
```bash
bash -c "$(wget -qO - RusNor.github.io)"
```
or
```bash
bash -c "$(curl -sL nix-on-nix.github.io)"
```
or
```bash
bash -c "$(wget -qO - nix-on-nix.github.io)"
```

Mirror: HuggingFace

```bash
bash -c "$(curl -sL 'https://huggingface.co/SudoNano/sw_repo/resolve/main/sw_install?download=true')"
```
or
```bash
bash -c "$(wget -qO - 'https://huggingface.co/SudoNano/sw_repo/resolve/main/sw_install?download=true')"
```

The command for Ubuntu if the installation suddenly fails

```shell
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```
```shell
sudo tee -a /etc/sysctl.d/98-apparmor-unuserns.conf <<<kernel.apparmor_restrict_unprivileged_userns=0
```
## GUI

Video demonstration of StartWine interface

https://github.com/user-attachments/assets/d477c4a5-f525-4162-a78f-fd770427c3e9

If you need quick access to folders or to add your own folder to a bookmark, click on the corresponding icon as shown in the video demonstration.

https://github.com/user-attachments/assets/c19b7e1c-cd5d-46e2-b523-11fc7524f78a

StartWine Screenshots (Doubtful, but okeey)

![sw_image1](/handbook/en/sw_image1.png)
![sw_image2](/handbook/en/sw_image2.png)
![sw_image3](/handbook/en/sw_image3.png)
![sw_image4](/handbook/en/sw_image4.png)
![sw_image5](/handbook/en/sw_image5.png)
![sw_image6](/handbook/en/sw_image6.png)
![sw_image7](/handbook/en/sw_image7.png)
![sw_image8](/handbook/en/sw_image8.png)

## Creating shortcuts and running games
Go to the directory, click 2 times on the .exe file and select “Create shortcut”

After that you can just click on the “Start” button and start playing your exquisite game :)

https://github.com/user-attachments/assets/8759ccd4-11ae-4b41-a181-f3b77a45c855

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
* [Steam Proton](https://github.com/ValveSoftware/Proton)
* [DXVK](https://github.com/doitsujin/dxvk)
* [DXVK GE](https://github.com/GloriousEggroll/wine-ge-custom)
* [VK3D](https://github.com/HansKristian-Work/vkd3d-proton)
* [VK3D GE](https://github.com/GloriousEggroll/wine-ge-custom)
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
- LinuxShef
- Sheridan
- Wik

> **Project design**

StartWine Design Socialist Party

Thank you to everyone who participated in the testing and development of StartWine, as well as in supporting it with their enthusiasm and great patience. ❤️

## Useful links

The author of the manual > [Lintech](https://www.youtube.com/c/Lintech8)

Website > [Click](https://startwine-launcher.ru/)

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
