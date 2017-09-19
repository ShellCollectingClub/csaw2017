We were provided a large img file, along with a website asking for a username and password.

First, the file system had to be mounted. The provided image had 2 partions. The larger of the two was mounted using the commands found [here](https://askubuntu.com/questions/69363/mount-single-partition-from-image-of-entire-disk-device). Seeing as the other part of the challenge was a web page asking for login, I looked for its source, which included login creds. Using those to login gave the flag.

```bash
vagrant@vagrant-ubuntu-vivid-64:/vagrant/CTFs/old/csaw17/old$ fdisk -lu ./best_router.img

Disk ./best_router.img: 14.6 GiB, 15640559616 bytes, 30547968 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x7f39f284

Device             Boot Start      End  Sectors  Size Id Type
./best_router.img1       8192    93813    85622 41.8M  c W95 FAT32 (LBA)
./best_router.img2      94208 30547967 30453760 14.5G 83 Linux

vagrant@vagrant-ubuntu-vivid-64:/vagrant/CTFs/old/csaw17/old$ python -c "print 94208 * 512"
48234496
vagrant@vagrant-ubuntu-vivid-64:/vagrant/CTFs/old/csaw17/old$ sudo losetup -o 48234496 /dev/loop0 ./best_router.img
vagrant@vagrant-ubuntu-vivid-64:/vagrant/CTFs/old/csaw17/old$ sudo mount /dev/loop0 /mnt
vagrant@vagrant-ubuntu-vivid-64:/vagrant/CTFs/old/csaw17/old$ cd /mnt
vagrant@vagrant-ubuntu-vivid-64:/mnt$ ls
bin   dev  home  lost+found  mnt  proc  run   srv  tmp  var
boot  etc  lib   media       opt  root  sbin  sys  usr
vagrant@vagrant-ubuntu-vivid-64:/mnt$ cd var/www/
vagrant@vagrant-ubuntu-vivid-64:/mnt/var/www$ ls
flag.txt  index.pl  login.pl  password.txt  username.txt
vagrant@vagrant-ubuntu-vivid-64:/mnt/var/www$ cat username.txt
admin
vagrant@vagrant-ubuntu-vivid-64:/mnt/var/www$ cat password.txt
iforgotaboutthemathtest
```

Using the above credentials of admin:iforgotaboutthemathtest on the provided website gives us
the flag of "flag{but_I_f0rgot_my_my_math_test_and_pants}"
