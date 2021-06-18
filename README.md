## Introduction

Imagine that you have a memory dump and you ready to run Volatility but - for whatever reason - the profile has an invalid or corrupted System.map file!
There have been few attempts in the past to automatically extract this information from a memory dump [1][2], but they have strong assumptions on where the kernel is loaded and so they fail when KASLR is enabled. Moreover they are able to extract only the ksymtab, which contains only a subset of kernel symbols (the symbols exported with EXPORT_SYMBOL).
This tool implements an automated way to extract the kernel kallsyms (System.map) - which are stored in kernel memory in a compressed form - that relies only on information contained in the memory dump.

## Approach

In a nutshell, this tool extracts the kernel function `kallsyms_on_each_symbol` from a memory dump and executes it in [Unicorn Engine](https://github.com/unicorn-engine/unicorn). This function takes care of uncompressing the kallsyms and accepts a function pointer as parameter - which gets called every time a kallsym is uncompressed.

More specifically, our approach can be divided in the following steps:
1) We find the physical location of the string "kallsyms_on_each_symbols\x00" in the memory dump.
2) We search for a candidate ksymtab - a table that contains several `struct kernel_symbol` (defined [here](https://elixir.bootlin.com/linux/v5.0/source/include/linux/export.h#L71)).
Each `kernel_symbol` contains the virtual address of the symbol (`value` field) and a pointer to a string representing the name of the symbol (`name`).
So, to find a candidate symtab the tool scans the memory dump for a sequence (longer than a configurable threshold) of pairs of kernel addresses.
3) At this point, we use the following insight: KASLR randomize the virtual and physical space at a page granularity. This means that the correct ksymtab should contain at least one `kernel_symbol` where the page offset of the name field matches the page offset of the physical location of the string (found at step 1)).
4) When we find such a `kernel_symbol`, since the kernel is mapped contiguously, to find the physical address of the value field we can do: name physical address + (value virtual address - name virtual address)
5) At this point we know the virtual and the physical address of the `kallsyms_on_each_function`: we are ready to extract the surrounding of this address, load the code in Unicorn and execute the function!

I tried this tool against several versions of the kernel and it worked flawlessly even on the memory dumps of The Art Of Memory Forensics (~8 years old) :)

### Usage

The only dependency of this tool is Unicorn. To install it you can `pip3 install unicorn` or see [here](https://www.unicorn-engine.org/docs/) for detailed instructions. To run the tool:
```
    python3 ksymextractor/kallsyms.py path/to/dump.raw
```

At the moment only raw memory dumps are supported. If you have any other type of dump you can convert it to raw format using volatility's [imagecopy](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference#imagecopy).

### Limitations and Future Work:

First of all, this works only if the kernel was compiled with CONFIG_MODULES - otherwise the kallsyms are never created in the first place.

Moreover, the latest versions of the kernel introduced CONFIG_HAVE_ARCH_PREL32_RELOCATIONS. This makes everything more tricky because the fields of `struct kernel_symbol` are not virtual addresses anymore but only offsets. Therefore, while we can still find the physical address of the function in the dump but we don't know its virtual address. I have the strong feeling that by analyzing the code of the function we can still find the correct virtual address (maybe with some small bruteforcing involved?). Ping me if you are interested in working on this!

Finally, `kallsyms_on_each_symbols` also lists the symbols exported from kernel modules (it calls `module_kallsyms_on_each_symbol`). The problem here is that the memory containing this information must be correctly loaded in the emulator (the modules area is not contiguous to the kernel code, so extracting more memory from the dump is not enough). But from the ksymtab we know where `init_level4_pgt` or `init_top_pgt` are - so we could walk the page tables and set everything up correctly in the Unicorn emulator!

### References

[1] https://github.com/emdel/ksfinder

[2] https://github.com/psviderski/volatility-android/blob/master/volatility/plugins/linux/auto_ksymbol.py