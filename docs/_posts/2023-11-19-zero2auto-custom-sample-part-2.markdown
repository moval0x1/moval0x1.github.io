---
layout: post
title:  "Zero2Auto Custom Sample - Part 2"
description: Zero2Auto Custom Sample - Part 2
date:   2023-11-19 23:05:00 +0000
categories: Zero2Auto Reversing Malware
---
## Binary Ninja Plugin
To start this second part of the custom sample analysis, I would like to add the script created using [Binary Ninja](https://binary.ninja/). You can find the doc [here](https://docs.binary.ninja/).

The script is not complex - if you have any suggestions to improve this, please share them with me :) - and it is probably not the fanciest code you have been seeing, but it is something that works, lol.

```
"""
    Name        : Zero2Auto_decode_str
    Author      : Charles Lomboni
    Description : Binary Ninja plugin to decode strings from zero2auto custom sample
"""

def get_ref_from_func():
    ref_lst = []
    fn_name = TextLineField("What is the func name? ")
    get_form_input(["Get Function Name", None, fn_name], "Decode Zero2Auto main_bin strings")
    
    fn_addr = bv.get_functions_by_name(fn_name.result)[0].start
    
    for x in bv.get_callers(fn_addr):
        ref_lst.append(x)
    
    return ref_lst

def get_encoded_strs(refs):
    encoded_strs = []
    for x in refs:
        encoded_strs.append(str(x.hlil).replace(')','').replace('"','').split('(')[1])
    
    return encoded_strs


def decode_str(encoded_str):
    base_str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890./="
    new_char = 0
    decoded_str = []

    for x in encoded_str:
        str_diff = (base_str.index(x) + 0xD)
        if str_diff < 66:
            decoded_str.append(base_str[str_diff])
        else:
            new_char = (base_str.index(x) - 66) + 0xD
            decoded_str.append(base_str[new_char])
        
    return ''.join(decoded_str)

refs = get_ref_from_func()
enc_strs = get_encoded_strs(refs)

# mw_resolve_api
for x in enc_strs:
    print(f"[+] {x} => {decode_str(x)}")

```

Here you can see how it works on [Binary Ninja](https://binary.ninja/).

![Decode strings Binja Plugin](/assets/images/zero2auto/2023-11-19/BinaryNinja-Zero2Auto-Plugin.gif)

## Further Stages
Looking at the strings, I found something that caught my eye; there was a **```cruloader```** and it looked weird; maybe the name of this second part? Perhaps it's a joke? Who knows? I'm assuming it is a part of the malware and not a joke.

![Cruloader](/assets/images/zero2auto/2023-11-19/bn-cruloader.png)

DiE tells us that we are dealing with a **```C/C++```** program.

![DiE](/assets/images/zero2auto/2023-11-19/DiE-cruloader.png)

Usually, when I have to deal with it, my first step is to go to the **```main```** function that usually for **```C/C++```** program can be found by three pushes before a call, something like that.

```
push something
push something
push something
call somethingElse
```

I found the **```main```** function, it had an interesting part, and I can tell you why. After the **```GetModuleFileNameA```** which is responsible for: **retrieve the fully qualified path for the file that contains the specified module.** and the **```_strtok```** that is a kind of **split** function - until now, nothing new, right? - there is a function that compares with a hex value.

![Begin of main](/assets/images/zero2auto/2023-11-19/bn-begin-main.png)

Just after going inside this function, we have some values that we can use to search in Google - always a good idea to use Google to bring some insights to us. There are many occurences of the hex value **```0xedb88320```** with a [XOR](https://www.geeksforgeeks.org/bitwise-operators-in-c-cpp/) operation.

![CRC32 function](/assets/images/zero2auto/2023-11-19/bn-crc32.png)

One of the first results brings us the information that this is a [CRC32](https://lxp32.github.io/docs/a-simple-example-crc32-calculation/) implementation. To validate it, I will use the HashDB plugin from OALabs implemented on [Binary Ninja](https://binary.ninja/) by [Cindy Xiao](https://github.com/cxiao/hashdb_bn), luckily it worked very well! <3. I just renamed this function to **```mw_crc32```**. Because it is easier read names than random numbers.

![HashDB](/assets/images/zero2auto/2023-11-19/bn-hashdb-svchost.png)

> **Just a comment here!**
>
> The challenge could be easily resolved using [x64dbg](https://github.com/x64dbg/x64dbg); the goal here is to use [Binary Ninja](https://binary.ninja/) to study the tool and also practice some static analysis to collect information as much as possible without debugging it.

This part is so cool when we understand what is going on here. Look, this function resolves most of the content in run time, but it does not mean that we cannot understand the result without debugging it; basically, the malware gets this hex value and performs a loop, as shown on the left side. We can summarize it as:

1) Get the char[i].
2) Rotate Left char[i] with 4.
3) XOR char[i] with 0xC5.

![Get Pastebin URL](/assets/images/zero2auto/2023-11-19/bn-get-pastebin-url.png)

If we perform the same sequence mentioned previously, the magic happens and we get the Pastebin **```https[:]//pastebin[.]com/raw/mLem9DGk```**. I just used [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Rotate_left(4,false)XOR(%7B'option':'Hex','string':'c5'%7D,'Standard',false)&input=ZGExYjFiNWI2YmZmYWVhZTViNGE2YjFiMGE3YWNhYmFiZTZhYWE4YWFlN2I0YTJiYWU4YTk4MGE4YWNmMTgyOGVh) to help me with that.

![CyberChef Pastebin URL](/assets/images/zero2auto/2023-11-19/cyberchef-pastebin-url.png)

The content of Pastebin will be allocated - according to the APIs called after that. Taking a look at Pastebin, it only has another URL which points to this PNG file **```https[:]//i[.]ibb[.]co/KsfqHym/PNG-02-Copy[.]png```**. Nice, no? Unfortunately, no :/ Not everything is a flower in this awesome world of malware analysis. The image is corrupted, and it might be fixed before the "execution?". It is my hypothesis.

![Corrupted IMG](/assets/images/zero2auto/2023-11-19/img-corrupted.png)

Following taking notes by static analysis, I found good things, and I kind of stayed stuck at some points, but let's keep moving until I got completely stuck. As mentioned before, sometimes I have renamed functions based on voices in my head, lol. To be honest, it is not this but essentially based on what I can understand by the function that I'm analyzing. So, after a deep analysis, one of the functions needed to have its name changed. Mainly because I understood that it also decodes the corrupted file, and I will show you that.

The function named as **```mw_create_writeFile_temp```** now is called by **```mw_decode_create_writeFile_temp```**. Let's dig into it. I can explain almost the whole function without putting the binary on a debugger, but unfortunately, my static analysis skill is not as sharp as I intend to have it in the future - a short future, I hope. It starts by getting the content from Pastebin, performing one more time the **```rol 4 > xor 0x1f```** sequence to decode the string **```.tuptuo\```**. This string looks reversed. Am I sure about that? No, yet, but if we reverse, it becomes **```/output.```**. After that, it performs another decode sequence - but this time, I cannot understand what the string means. I will see it and the other parts on the debugger; I'm just pointing here what I've found in the static analysis part.

At the end of performing some operations in a loop, after that, another loop with the **IMG** content **```XOR 0x61```**. When it finishes, the malware resolves some injection APIs, such as:

- CreateProcessA
- WriteProcessMemory
- ResumeThread
- VirtualAllocEx
- VirtualAlloc
- CreateRemoteThread

It looks like the malware will inject one more time content, keeping the analysis; the following function uses the same **```rol > xor```** sequence to decode the full path of [svchost](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')Rotate_left(4,false)XOR(%7B'option':'Hex','string':'a2'%7D,'Standard',false)&input=MWU4OWVmNWZiY2NjNmNkYzVkMWRlZjFmYmQxZDZkN2NmYzE5MDllZjFkNGQxY2FjZGMxZDZkYzg3Y2FkN2M) **```C:\Windows\System32\svchost.exe```** and, at the end of this function, the last function is in charge of a Process Hollowing. How do I know that without debugging? Based on the APIs called, google is always my good friend, and it helped me find, for instance, this [github](https://github.com/m0n0ph1/Process-Hollowing) with a very close code as I found in the last function.

So far, so good. Now, let me validate all my hypotheses.

## The winner debugger

As I started debugging, I just figured out that I forgot to see and renamed some functions, such as the first **```IsDebuggerPresent```** and the most important one, that is the **```CreateToolhelp32Snapshot```**. According to MSDN, this API **takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.**

```
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
```
It will take a "photo" of the process list and loop through it searching for something, in our case, something hashed by CRC32. I could easily bypass this function result by changing the Zero Flag or the Jump below the comparison, but I'm here to learn more and dig deep into the challenge. Let's debug it! :)

I found that when it compares **```EAX```** with **```0x7C6FFE70```** it returns the wrong result, so let me identify what this value is - I know that it uses a CRC32 implementation, and I will use it to my advantage.

As it spends some time in the loop, I will use a [Conditional BreakPoint](https://help.x64dbg.com/en/latest/introduction/ConditionalBreakpoint.html) to only break when it is **```explorer.exe```** because malware authors, usually use this function to validate the processes running to close an analysis application or close the process itself if find any weird stuff, I will start there, I would not spend too much time on this loop, to be honest.

I just added this beautiful line **```strstr(utf16(ESI), "explorer.exe")```** on this line and executed my program. Easy no?

![Conditional BreakPoint](/assets/images/zero2auto/2023-11-19/x64dbg-conditional-bp.png)

And it worked!

![BreakPoint on explorer.exe](/assets/images/zero2auto/2023-11-19/x64dbg-bp-explorer-exe.png)

I got two programs that I opened to analyze the binary, and both of them were searched by the malware; one of them was **```ProceessHacker.exe```** with the hash **```0x7C6FFE70```**.

![ProcessHacker x64dbg](/assets/images/zero2auto/2023-11-19/x64dbg-processHacker.png)

After closes them I got **```x32dbg.exe```** with the hash **```0xD2F05B7D```**.

![x32dbg process](/assets/images/zero2auto/2023-11-19/x64dbg-x32dbg-process.png)

As I changed the name of my debugger to **```moval0x1.exe```** I was able to continue without further problems. I have to admit that some tasks are easier with debugger than just open in a disassembly and try to understand without dynamicaly run.

The malware download the **```.PNG```** file, get the size using **```HttpQueryInfoA```** with **```dwInfoLevel```** being passed 5, which means **```HTTP_QUERY_CONTENT_LENGTH```**. 

> Retrieves the size of the resource, in bytes.

![output.jpg](/assets/images/zero2auto/2023-11-19/x64dbg-output-jpg.png)

I saw the **cruloader** string, but I didn't catch the idea behind it debugging. I got that it concat with the temp folder to save the output; it also uses [stackstring](https://isc.sans.edu/diary/Stackstrings+type+2/26192/) to disrupt our analysis.

![Create file](/assets/images/zero2auto/2023-11-19/x64dbg-cruloader-temp-folder.png)

The magic of learning and reading about APIs, after the folder has been created, we have a **```WriteFile```** telling us everything we need to know.

```
BOOL WriteFile(
  [in]                HANDLE       hFile,
  [in]                LPCVOID      lpBuffer,
  [in]                DWORD        nNumberOfBytesToWrite,
  [out, optional]     LPDWORD      lpNumberOfBytesWritten,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```
Based on that, we can see that the handle is **```0x470```**, the content to be written is at the address **```0x03740000```**, and the length is **```0x435B8```**. It means that the entire file will be written on disk.

![WriteFile API](/assets/images/zero2auto/2023-11-19/x64dbg-writefile.png)

And one more time it gets a reverse string, **```redaolurc```** that is the same **```cruloader```** and it is find inside the **```.PNG```** as we can see below.

![wxHexEditor](/assets/images/zero2auto/2023-11-19/wxHex-PNG.png)

Ok, but, why this information is useful? That's a good question! The answer is some lines below. The malware reads the content of the **```.PNG```** search for the reverse **cruloader** string and everything after that should be **```XORed```** with **```0x61```**, the image is a Zero2Auto logo and it was used to deceive the first seen of the file. We can see in the image below that it kind of worked.

![XORed PNG](/assets/images/zero2auto/2023-11-19/fi-xored-png.png)

After that, we know that the Process Hollowing is coming. Probably I missed something because the binary showed me some congratulations strings but didn't run - maybe my "smart" moment in just trying to perform the **```XOR```** was not enough. To finish it, taking a look at the renamed function **```mw_processHollowing```** I just passed all steps as I did previously, and before the malware **```ResumeThread```** I dumped the injected file on **```svchost.txt```** and fixed the imports - by the way, there was an organized mess :D

And finally, there is this beautiful message here!

![Cruloader MessageBox](/assets/images/zero2auto/2023-11-19/cruloader-messagebox.png)

Thank you for reading! It was a really fun challenge.