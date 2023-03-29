# **Move to crackme**

## Description

This challenge need you familiar with Move lanuage and  linux binary crackme. For solve this challenge you need Linux x86-64 system.

## How to get the flag

1.first download (https://github.com/move-language/move) and compile the Move lanuage

2.build this move package:

```
move build
```

3.publish the package:

```
move sandbox publish  -v
```

4.you should complete the `PoC.move` ,if the input is right, will debug print a vector stream (named `out_elf`) (in `./source/MoveToCrackme.move ` at function `core1`) ,which is a  crackme stream.  you should write the stream to a file and crack this crackme  on linux system and then get the flag

```
move sandbox run ./sources/PoC.move --signers 0xf
```

