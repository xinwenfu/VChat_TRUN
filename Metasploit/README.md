# TRUN Metasploit Module
The creation of the Metasploit module follows some of the patterns and ideas discussed in the [Making-Dos-DDoS-Metasploit-Module-Vulnserver](https://github.com/DaintyJet/Making-Dos-DDoS-Metasploit-Module-Vulnserver/tree/main/MetasploitModules) document. We will not be discussing how the metasploit module is made here, and will only cover how to install it on a Kali Linux system and how to use the Metasploit module.

> [!IMPORTANT]
> Offsets may vary. Additionally if you recompile the executables or have ASLR enabled the address of the `jmpesp` target may vary.

### Optional Installation of Metasploit Framework
We are using Kali, installed with Metasploit Framework. So this step is optional. Otherwise, the **first** thing that you need to do is have the [Metasploit Framework](https://github.com/rapid7/metasploit-framework) installed on your system (Generall a Kali VM). You can verify this with the following command:

```sh
$ msfconsole -v
```

> [!NOTE]
> The Metasploit Framework in most cases will be installed by default on a Kali Linux or any other penetration testing platform you have chosen.

### Adding VChat TRUN Attack Module
Here is a video demo.

[![Video demo](https://img.youtube.com/vi/ryo-rPS_dSY/mqdefault.jpg)](https://youtu.be/ryo-rPS_dSY)

Once you have the *Metasploit Framework* you can now **download or write** the Metasploit module. As this is an [Exploit Module](https://docs.metasploit.com/docs/modules.html#exploit-modules-2437) since it includes a *payload* and preform the exploitation of a target system/process we need to place the Ruby program into the `/usr/share/metasploit-framework/modules/exploits/`. 

1. Create */usr/share/metasploit-framework/modules/exploits/windows/vchat* folder.
```sh
sudo mkdir /usr/share/metasploit-framework/modules/exploits/windows/vchat
```

2. Create TRUN.rb
```sh
sudo mousepad /usr/share/metasploit-framework/modules/exploits/windows/vchat/TRUN.rb
```
Copy and paste the content of [TRUN.rb](TRUN.rb) into this file and save.

> [!NOTE]
> You can use a text editor like `mousepad`, `vim`, `emacs`, etc. To make the new file, you can also use `cp` or `mv` to place the file into the correct directory if you have made it elsewhere.
