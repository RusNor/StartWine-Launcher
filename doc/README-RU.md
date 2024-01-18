![sw_image1](/doc/image/sw_image1.svg)

> StartWine - это программа запуска, которая позволяет быстро и легко запускать приложения Windows в операционных системах Linux
# **Руководство StartWine**

⚠️ **Данное руководство является устаревшей с выходом StartWine версии 400. Совсем скоро будет полностью новое руководство, это не значит что в руководстве нету ничего полезного. Просто большая часть информации уже устарел!** ⚠️

## Навигация

1. [Подготовка к установке](#подготовка-к-установке)
2. [Установка (новое)](#установка-новое)
3. [Установка (старое)](#установка-старое)
4. [Пользовательский интерфейс](#пользовательский-интерфейс)
5. [Начальная настройка](#начальная-настройка)
6. [Как запускать игры и программы](#как-запускать-игры-и-программы)
7. [О нас](#о-нас)


## Подготовка к установке


Чтобы начать пользоваться программу, загрузите сам SrartWine с сервера discord в разделе sw_releases или со страницы GitHub

Discord: [Click](https://discord.gg/jjY3auVdfm)

GitHub: [Click](https://github.com/RusNor/StartWine-Launcher/releases)

StartWine теперь в [AUR!](https://aur.archlinux.org/packages/startwine)

Если вы загрузили и запустили StartWine с помощью команды wget, вы можете просто пропустить пункт ниже

После того, как вы загрузили файл, прежде всего щелкните правой кнопкой мыши, свойства, права (или любой другой подобный пункт в свойствах), установите флажок "Является исполняемым" или "Разрешить запуск как программа".

![sw_image2](/doc/image/sw_image2.png)

или вы можете ввести команду в терминале:
```bash
chmod +x StartWine_v*
```

## Установка (новое)


начиная с версии [3.6.4](https://github.com/RusNor/StartWine-Launcher/releases/tag/StartWine_v364) графическая часть установки была удалена, поэтому установка немного изменилась

теперь просто перетащите файл из папки (не забудьте сделать файл исполняемым), в которую вы загрузили StartWine, в терминале и нажмите enter

если командой хотите с терминала:
```bash
./StartWine_v37*
```

## Установка (старое)
Запустите файл двумя щелчками мыши и увидите сам установщик. Нажмите на кнопку Установить и дождитесь завершения установки (вы можете приготовить чай ☕).

![sw_image3](/doc/image/sw_image3.png)

Если вы хотите установить другие версии wine вместе со startWine, то в пункте advanced options вы можете выбрать нужный вам вариант (рекомендую установить Wine staging и Proton GE).

![sw_image4](/doc/image/sw_image4.png)

После установки у вас в пуске появится программа StartWine-install-Manager, с её помощью вы можете обновит StartWine либо удалить.

![sw_image5](/doc/image/sw_image5.png)


## Пользовательский интерфейс


Теперь давайте вкратце ознакомимся с меню StartWine

![sw_image6](/doc/image/sw_image6.png)

* **Shortcuts** - Каталог приложений.
* **Create shortcuts** - Создаем ярлык .exe-файл вместе с префиксом и рекомендуемыми библиотеками.
* **Prefix tools** - Управление префиксом, с которого вы начали игру.
* **Wine tools** - Управление и настройки Wine, которое в данный момент используется в префиксе.
* **Download wine** - Здесь вы можете скачать wine-staging, wine-steam-proton, wine-proton-ge, wine-lutris, wine-lutris-ge, wine-custom используется для установки сторонних Wine с различных ресурсов.
* **Settings** - Настройка StartWine.
* **Debug** - Запуск exe-файла с префиксом в режиме отладки.
* **Stop** - Остановка всех процессов Wine.

Если вам не нравится фоновая тема StartWine, вы можете изменить её, нажав на значок, показанный на скриншоте ниже 

![sw_image20](/doc/image/sw-image20.png)


Начиная с версии [3.6.0](https://github.com/RusNor/StartWine-Launcher/releases/tag/StartWine_v360), в StartWine добавили настройки mangohud и vkbasalt  

![sw_image17](/doc/image/sw-image17.png)

![sw_image18](/doc/image/sw-image18.png)

Вы можете просмотреть изменения в настройках mangohud и vkbasalt, нажав на кнопку предварительного
просмотра, чтобы выйти из предварительного просмотра, нажмите клавишу Enter

![sw_image19](/doc/image/sw-image19.png)

## Начальная настройка


Перейдите к пункту Download wine и загрузите там следующее (если вы ранее установили wine из списка ниже в установщике, вы можете пропустить этот пункт):
wine-staging,
wine-steam-proton,
wine-proton-ge.

![sw_image7](/doc/image/sw_image7.png)

Больше ничего не остается делать :)


## Как запускать игры и программы


Есть два способа установить игру в StartWine
1. Вы можете установить свои игры с помощью лаунчера в разделе install launchers.

   ![sw_image8](/doc/image/sw_image8.png)

2. Если вы скачали игру из других источников или откуда-то еще, то сначала вам нужно будет установить игру (я покажу вам пример игры [Yuppie Psycho](https://store.steampowered.com/app/597760/Yuppie_Psycho_Executive_Edition)).
Как запустить установщик exe-файла? да, это просто, мы запускаем его в два клика по левой кнопке мыши или просто по правой кнопке мыши

   ![sw_image9](/doc/image/sw_image9.png)

В появившемся окне нажмите на манящую кнопку "START" :) и подождите, пока она не запустится.
Далее выбираем язык, и здесь мы немного остановимся, сначала выбираем место установки, а затем там, где выделенная область находится чуть ниже, убираем все галочки! (Не обращайте внимания, что у меня здесь есть игра [Cuphead](https://store.steampowered.com/app/268910/Cuphead/), это, например)

![sw_image10](/doc/image/sw_image10.png)

Если вы сделали так, как было написано выше, то вы будете хорошим шеф-поваром 👨‍🍳 (последнее - шутка)

Совет!

* В некоторых случаях может оказаться, что установка идет, но проценты не идут, и виновник находится в моем или, может быть, у вас есть [NTFS](https://ru.wikipedia.org/wiki/NTFS ) раздел диска, с которого вы запустили программу установки. Дело в том, что если у вас есть так называемый [дуалбут](https://ru.wikipedia.org/wiki/Мультизагрузка ) или мультизагрузка, называйте это как хотите, тогда, если вы не загрузились из Windows, то Windows благополучно отберет у вас права на любые действия с файлами.
Что мне следует делать в этом случае?
* Вариант 1: Просто возьмите и перезагрузитесь в Windows, не обязательно входить в учетную запись, затем перезагрузитесь в свой дистрибутив Linux.
* Вариант 2: В папке, где у вас есть файлы с установщиком игры, скопируйте его и перенесите в раздел Linux, предпочтительно в раздел /home/$USER/ (где $USER должно быть вашим именем пользователя).

Теперь вернемся к игре. После установки игры перейдите в папку с игрой и найдите exe-файл для запуска игры.

![sw_image11](/doc/image/sw_image11.png)

Запустите файл, нажмите на кнопку Create shortcut.
Cовету из Wine выбирать Proton-ge

![sw_image12](/doc/image/sw_image12.png)

StartWine спросит вас: вы хотите создать префикс? Здесь я рекомендую нажать кнопку "Да"

![sw_image13](/doc/image/sw_image13.png)

В ходе создания префикса StratWine предложит вам установить рекомендованные либы, простымы языком будет в ваш префикс для игры устанавливать библиотеки directX, visual c++ и т.д. На что мы нажимаем на кнопку "Да", тоже конечно не обязательно но в большинство случаев нужно.

![sw_image14](/doc/image/sw_image14.png)

В результате должна получиться такая картинка.

![sw_image15](/doc/image/sw_image15.png)

Вот теперь можете запускать игру

![sw_image16](/doc/image/sw_image16.png)

Приятной вам игры :)

## О нас


Автор руководства: [Lintech](https://www.youtube.com/c/Lintech8)

Создатели StartWine: [Normatov R.R.](https://github.com/RusNor) and [Maslov N.G.](https://github.com/nix-on-nix) 

Помощники в создании руководства:
[Normatov R.R.](https://github.com/RusNor) [Maslov N.G.](https://github.com/nix-on-nix) [Norz3n](https://github.com/vellynproduction) Huskysoul#6112

Веб-сайт [Клик](https://startwine-project.ru/)

Если у вас есть какие-либо вопросы, перейдите на сервер: [Discord](https://discord.gg/jjY3auVdfm)

Телеграм-канал: [StartWine](https://t.me/StartWine)


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
____
