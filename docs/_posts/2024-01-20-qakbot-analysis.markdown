---
layout: post
title:  "Qakbot Analysis"
description: A quick analysis of the Qakbot Malware Family
date:   2024-01-20 21:45:00 +0000
categories: Zero2Auto Reversing Malware
---

## The Qakbot Malware Family
[QBot](https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot) is a modular information stealer also known as Oakboat, Pinkslipbot, Qbot or Quakbot. It has been active for years since 2007. It has historically been known as a banking Trojan, meaning that it steals financial data from infected systems, and a loader using C2 servers for payload targeting and download. 

## Loader
When I got this sample, the first thing that caught my eye was the lack of strings and the number of sections with their names, which is not something normal in a binary.

![DiE Sections](/assets/images/zero2auto/2024-01-20/die-sections.png)

My starting point in these cases is to set some breakpoints in known APIs such as ```VirtualAlloc```, ```VirtualProtect```, ```WriteProcessMemory```, ```CreateProcessInternalW``` and others that can be used in the same context, either to self injection or remote injection. I could execute the binary and validate if it has some injection or anything related to that. However, let's start putting BP on the common APIs used for any injection.

In that case, as I set a BP on VirtualProtect, it stopped on the API, and I arrived at the right point after putting the PE section onto the dump.

![x64dbg Dump](/assets/images/zero2auto/2024-01-20/x64dbg-dump.png)

We have the second stage file at the base address ```0x2550000```. To dump it, follow these steps: **Right Click on ```0x4D``` on dump -> Follow in Memory Map -> Right-click on the base address -> Dump Memory to File**.

![PE-bear Imports](/assets/images/zero2auto/2024-01-20/pe-bear-imports.png)

We can see on [PE-bear](https://github.com/hasherezade/pe-bear) that all the imports are good, so we don't need anything to fix it! :)

## First Stage

In this stage, what caught my attention was the entropy to the ```.rdata``` section and ```.rsrc```, and the lack of useful strings.

![DiE Entropy](/assets/images/zero2auto/2024-01-20/die-entropy.png)

Using BinaryNinja to take a look in that stage, I was able to see a interesting function with lots of calls and the result of these function be a value that would be used in a ```GetModuleHandleA```. Hmm, it raised some flag to me.

![BinaryNinja Decrypt Func](/assets/images/zero2auto/2024-01-20/bn-strings-decrypt-func.png)

Looking at this function in the **x64dbg**, things become easier to understand. I could see that after passing this function, it returns a string decrypted. Within this function, we can see the decrypt pattern, as shown below.

![x64dbg Decrypt Routine](/assets/images/zero2auto/2024-01-20/x64dbg-decrypt-strings-routine.png)

To add a layer of simplicity to my **binja** analysis, I just created a simple (and maybe not so good) script to decrypt all these strings and add them as a comment. I've tried to create the script as close as possible to what's in the assembly code.

Here are the **binja [scripts](https://github.com/moval0x1/Zero2Auto/tree/main/qakbot)** used to decrypt strings, APIs, and anything needed for this analysis. After that, you'll find something like that.

![Binary Ninja Plugin](/assets/images/zero2auto/2024-01-20/bn-plugin-decrypt-strings.png)

With strings, it is much better to dive into the malware. Unfortunately, some APIs are resolved in runtime, and even with the names, I cannot see where it would be called. Based on that, I went to the debugger, and with a hand from my friend [**Leandro**](https://leandrofroes.github.io/) - he showed me about this anti-analysis process that I've passed and didn't catch the idea of - I could understand that the ``CreateProcess`` was started as an anti-analysis step. Ask for help is an excellent way to learn; I learned a new trick with his help; thanks, man.

Let me try to summarize things here.

1. When the binary is executed, it tries to create a new process using the param **/C**.
2. This parameter starts a series of **anti-analysis** tricks and leads us down the wrong path.
3. Forcing the result **false** after the ```CreateProcess```.

![CreateProcessW](/assets/images/zero2auto/2024-01-20/x64dbg-create-process-w.png)

With the flow passing by the anti-analysis part, we will not find anything interesting. I've changed the ```EAX``` from ```1``` to ```0```. As mentioned at the beginning of this first stage, we have a high entropy in the ```.rsrc``` part; based on that, I've added a breakpoint on the ```LoadResource``` API. However, this API is only noticed after decrypting the API names, as shown in the image below.

![CommentsAndSymbols](/assets/images/zero2auto/2024-01-20/bn-comments-and-symbols.png)

Now, let us analyze the actual flow!

### The Resource

To start talk about the resource, wee need to understand what happen here. We can put it in parts such as:

1. Load the resource.
2. Decrypt it using RC4.
3. Get the SHA1 sum.
3. Inject it into memory.

All the things that we've seen here are indicators that this **resource** is something *malicious*, and for sure, at any time, resource APIs would be called. As expected, the resource named ```307``` is decrypted and allocated. We can follow it in two ways, the easier way to get this is:

> Follow it in memory map > dump > open in a hex editor and remove the ``SHA1 SUM`` before the ``MZ`` and overlay, and that's it.

It is easy, but it is much better to have a script to help us find it in the resource section, decrypt it, and save on disk a clear file. Think about it: I've created a [**script**](https://github.com/moval0x1/Zero2Auto/tree/main/qakbot) and added it to GitHub for those who want to use it.


### Scripts

To understand what the scripts do, let me briefly explain here. We have here a normal ``RC4`` routine followed by a ``SHA1 SUM`` validation. Although we can see the program here - at least a part of it - **This Program cannot...**. It doesn't look like the complete straightforward program; after the ``SHA1`` validation, a weird value was found that is used out of this call in a comparison: ``0x616CD31A``. Searching for it, I only found it in a blog of a friend of mine [**dark0pcodes**](https://darkopcodes.wordpress.com/2020/06/07/malware-analysis-qakbot-part-2/). Based on what he says, it is a modified version of the [**BriefLZ**](https://github.com/jibsen/brieflz) compression algorithm, which makes much more sense now.

![Decrypt Resource Routine](/assets/images/zero2auto/2024-01-20/x64dbg-decrypt-resource-routine.png)

In order to decompress this file correctly after decrypting, we need to replace the modified bytes with the correct bytes, as added in the script found on GitHub.

```Python
replaced_data = binascii.hexlify(decrypted_resource).decode().replace("616cd31a", "626C7A1A")
```

## C2 in the Second Stage

In this subsequent phase, the approach mirrors that of the initial stage, involving encrypted resources utilizing the **``RC4``** encryption algorithm. These resources, identified by the names ``308`` and ``311``, persist in their encrypted state. Employing an identical script for extraction, we uncover pertinent data pertaining to the campaign, along with details about the utilized IPs.

For easy reference, the extracted configurations can be located [here](https://github.com/moval0x1/Zero2Auto/tree/main/qakbot).

## IoCs
- Loader: ```b92c0aafb4e9b0fc2b023dbb14d7e848249f29e02b0e4cd8624ce27e55c9ac4c```
- First Stage: ```b3e4ad642e5e68944be3aabdfc77c6818e75778f8764448bdc80762fef2dad5b```
- Second Stage: ```a9669005062b3c89146731a1fdd155f3902be2cfbb92a76b0173b61a35dd6516```

## Concluding Thoughts

While there are numerous other aspects to explore in this second stage of Qakbot, I'll conclude this sample discussion here. An opportunity exists for those interested in delving deeper to uncover the encrypted communication methods employed within this sample. Perhaps in a future version, I will undertake this exploration. Thus far, my encounter with Qakbot has been a valuable learning experience, guiding me to develop two plugins for **Binja** [BinjaExportTox64dbg](https://github.com/moval0x1/BinjaExportTox64dbg) and [CommentsAndSymbols](https://github.com/moval0x1/CommentsAndSymbols).

Thank you for taking the time to read this! Should you have any questions or suggestions, please don't hesitate to reach out. Feel free to contact me at your convenience! :)