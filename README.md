# Решение

JIT-компилятор языка HQ+.

Требования:

* Linux
* Компилятор C++, поддерживающий стандарт C++17
* Утилита `make`

Сборка:

    make

Запуск:

    # интерактивный шелл
    ./hij

    # справка, спецификация языка
    ./hij -h

    # запуск программы из файла
    ./hij -r file.hq

    # компиляция программы
    ./hij -c file.hq file.bin

    # запуск «скомпилированной» программы
    ./hij -e file.bin

# Задание

## Кусочек JIT компилятора

Цель - получить знакомство с системными вызывами, используемыми для получения/освобождения
памяти от ядра. Получить представление о том, как может работать JIT компилятор.

## Программа должна
 * Выделить память с помощью mmap(2).
 * Записать в выделенную память машинный код, соответсвующий какой-либо функции.
 * Изменить права на выделенную память - чтение и исполнение. See: mprotect(2).
 * Вызвать функцию по указателю на выделенную память.
 * Освободить выделенную память.

## Что может помочь?
 * man objdump
 * help disassemble в gdb

## Extra points
Сильные духом призываются к возможности модификации кода выполняемой функции
в runtime. Например, вы можете получить аргументом вызова вашей программы
какое-то число и пропатчить машинный код этим числом. Эта часть задания будет
оцениваться в дополнительные баллы.
