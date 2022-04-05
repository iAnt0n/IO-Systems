# Лабораторная работа 1

**Название:** "Разработка драйверов блочных устройств"

**Цель работы:** получить знания и навыки разработки драйверов блочных устройств для операционной системы Linux.

## Описание функциональности драйвера

Драйвер должен создавать виртуальный жесткий диск в
оперативной памяти с размером 50 Мбайт.
Два первичных и один расширенный разделы с размерами
10Мбайт, 20Мбайт и 20Мбайт соответственно. Расширенный
раздел должен быть разделен на два логических с размерами
по 10Мбайт каждый.

## Инструкция по сборке

```
    $ make
```

## Инструкция пользователя

### Загрузка модуля
1. Собрать модуль
2. Загрузить модуль с помощью
   ```
    # insmod lab2.ko
   ```

### Использование
1. Просмотр информации о диске
    ```
    # fdisk -l /dev/lab2
    ```
2. Форматирование нужных разделов
    ```
    # mkfs.vfat /dev/lab2p1
    # mkfs.vfat /dev/lab2p2
    # mkfs.vfat /dev/lab2p5
    # mkfs.vfat /dev/lab2p6
    ```
3. Монтирование нужных разделов
    ```
    # mkdir -p /mnt/lab2p1
    # mount /dev/lab2p1 /mnt/lab2p1
    # mkdir -p /mnt/lab2p5
    # mount /dev/lab2p5 /mnt/lab2p5
    ```


### Выгрузка модуля
1. Размонтировать примонтированные ранее разделы

2. ```
    # rmmod lab2
   ```

## Примеры использования
```
anton@anton-VirtualBox:/mnt/lab2p1$ sudo fdisk -l /dev/lab2
Disk /dev/lab2: 50 MiB, 52428800 bytes, 102400 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x36e5756d

Device      Boot  Start    End Sectors Size Id Type
/dev/lab2p1           1  20480   20480  10M 83 Linux
/dev/lab2p2       20481  61440   40960  20M 83 Linux
/dev/lab2p3       61441 102402   40962  20M  5 Extended
/dev/lab2p5       61442  81921   20480  10M 83 Linux
/dev/lab2p6      102403 122882   20480  10M 83 Linux
```

```
anton@anton-VirtualBox:~/io/lab2$ time sudo cp /mnt/lab2p1/file /mnt/lab2p5

real    0m0,053s
user    0m0,001s
sys     0m0,045s
```

```
anton@anton-VirtualBox:~/io/lab2$ time sudo cp /mnt/lab2p5/file ~

real    0m0,044s
user    0m0,011s
sys     0m0,024s
```