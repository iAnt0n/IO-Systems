# Лабораторная работа 2

**Название:** "Разработка драйверов сетевых устройств"

**Цель работы:** получить знания и навыки разработки драйверов сетевых интерфейсов для операционной системы Linux.

## Описание функциональности драйвера

Драйвер должен создавать виртуальный сетевой интерфейс в ОС
Linux. Созданный сетевой интерфейс должен перехватывать пакеты
родительского интерфейса (eth0 или другого - указывается параметром модуля `parent_if_name`).
Сетевой интерфейс должен перехватывать пакеты протокола IPv4, адресуемые конкретному IP (параметр `dest_ip`) и выводить IP адреса отправителя и получателя.

## Инструкция по сборке

```
    $ make
```

## Инструкция пользователя

### Загрузка модуля
1. Собрать модуль
2. Загрузить модуль с помощью
   ```
    # insmod lab3.ko
   ```

### Использование
1. Просмотр информации о диске
    ```
    # ifconfig virt
    ```
2. Просмотр перехваченных пакетов
    ```
    # cat /proc/lab3
    ```

### Выгрузка модуля
1. ```
    # rmmod lab3
   ```
