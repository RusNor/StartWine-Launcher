![sw_image1](/data/img/gui_icons/default_sample.svg)

## StartWine это программа запуска, которая позволяет быстро и легко запускать приложения Windows в операционных системах Linux

# **Руководство StartWine**

**Русский** - [English](/README.md)

## Навигация
1. [Установка](#установка)
2. [Сборка](#сборка)
3. [Интерфейс](#интерфейс)
4. [Создание ярлыков и запуск игр](#cоздание-ярлыков-и-запуск-игр)
5. [Что используется в StartWine?](#что-используется-в-startwine)
6. [Благодарность!](#благодарность)
7. [Полезные ссылки](#полезные-ссылки)
8. [Лицензия](#лицензия)

## Установка
Чтобы начать пользоваться программой, загрузите сам StartWine со страницы GitHub в разделе releases
Сделайте файл исполняемым перенесите его в терминал и нажмите Enter

GitHub > [Click](https://github.com/RusNor/StartWine-Launcher/releases)

AUR > [Click](https://aur.archlinux.org/packages/startwine)

## Установка одной командой:
Скопируйте одну из команд вставьте в терминал и нажмите Enter
```
bash -c "$(curl -sL RusNor.github.io)"
```
```
bash -c "$(wget -qO - RusNor.github.io)"
```
Команды для Ubuntu если вдруг установка не проходит
```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```
```
sudo tee -a /etc/sysctl.d/98-apparmor-unuserns.conf <<<kernel.apparmor_restrict_unprivileged_userns=0
```

## Сборка
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
## Интерфейс
Скриншоты StartWine

![sw_image1](/handbook/ru/sw_image1.png)
![sw_image2](/handbook/ru/sw_image2.png)
![sw_image3](/handbook/ru/sw_image3.png)
![sw_image4](/handbook/ru/sw_image4.png)
![sw_image5](/handbook/ru/sw_image5.png)
![sw_image6](/handbook/ru/sw_image6.png)
![sw_image7](/handbook/ru/sw_image7.png)
![sw_image8](/handbook/ru/sw_image8.png)
![sw_image9](/handbook/ru/sw_image9.png)
![sw_image10](/handbook/ru/sw_image10.png)
![sw_image11](/handbook/ru/sw_image11.png)
![sw_image12](/handbook/ru/sw_image12.png)
![sw_image13](/handbook/ru/sw_image13.png)

## Cоздание ярлыков и запуск игр
Заходим в каталог, щёлкаем 2 раза на .exe файл и выбираем "Создать ярлык"

После можете просто нажать на кнопку "Пуск" и начать играть в свою изысканную игру :)

Совет!

* В некоторых случаях может оказаться, что установка идет, но проценты не идут, и виновник находится в моем или, может быть, у вас есть [NTFS](https://ru.wikipedia.org/wiki/NTFS) раздел диска, с которого вы запустили программу установки. Дело в том, что если у вас есть так называемый [дуалбут](https://ru.wikipedia.org/wiki/Мультизагрузка) или мультизагрузка, называйте это как хотите, тогда, если вы не загрузились из Windows, то Windows благополучно отберет у вас права на любые действия с файлами.
Что мне следует делать в этом случае?
* Вариант 1: Просто возьмите и перезагрузитесь в Windows, не обязательно входить в учетную запись, затем перезагрузитесь в свой дистрибутив Linux. Или после того как загрузились в Windows отключите режим гибернации. Как это делать? Смотрите в интернете.
* Вариант 2: В папке, где у вас есть файлы с установщиком игры, скопируйте его и перенесите в раздел Linux, предпочтительно в раздел /home/$USER/ (где $USER должно быть вашим именем пользователя).

## Что используется в StartWine?
StartWine был написан с нуля, но с использованием уже готовых компонентов без которых сама программа не появилась
> Список 

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

## Благодарность!

> **Разработчики**

- [Рустам Норматов](https://github.com/RusNor)
- [Никита Маслов](https://github.com/nix-on-nix)

> **Создавали и помогали в написании кода**

- [Рустам Норматов](https://github.com/RusNor)
- [Никита Маслов](https://github.com/nix-on-nix)
- [Максим Тарасов](https://github.com/VHSgunzo)

> **Участники проекта**

- StartWine Community
- Андрей
- 3y6HuK
- Alexandrdrdr
- Huskysoul
- kazbek
- Kot41ru
- Fanchji (Виталий)
- Survolog
- Lex
- Lintech
- Sheridan
- Wik

> **Дизайн проекта**

Дизайнерская социалистическая партия StartWine

Спасибо всем кто принимал участие в тестировании и разработки StartWine, а так же в поддержке своим энтузиазмом и большим терпением ❤️

## Полезные ссылки

Автор руководства > [Lintech](https://www.youtube.com/c/Lintech8)

Веб-сайт > [Клик](https://web.startwine-launcher.ru/)

Телеграм > [Клик](https://t.me/StartWine)

Дискорд сервер > [Discord](https://discord.gg/jjY3auVdfm)

## Лицензия

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Copyright (C) Maslov N.G. Normatov R.R.

Этот файл является частью StartWine-Launcher.

StartWine-Launcher - это свободное программное обеспечение: вы можете распространять его и/или изменять
на условиях Стандартной общественной лицензии GNU, опубликованной
Фондом свободного программного обеспечения, либо версии 3 Лицензии, либо
(по вашему выбору) любой более поздней версии.

StartWine-Launcher распространяется в надежде, что он будет полезен,
но БЕЗ КАКИХ-ЛИБО ГАРАНТИЙ; даже без подразумеваемых гарантий
товарности или пригодности для определенной цели. См.
Стандартную общественную лицензию GNU для получения более подробной информации.

Вы должны были получить копию Стандартной общественной лицензии GNU
вместе с StartWine-Launcher.  Если нет, смотрите <http://www.gnu.org/licenses/>.
