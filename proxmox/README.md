```table-of-contents
```
# import OVA

Transfer ova file in `/var/lib/vz/template` folder

Extract:

```bash
root@proxmox:/var/lib/vz/template# tar -xf 'Net1 - UbuntuMail.ova'
root@proxmox:/var/lib/vz/template# ls -l
total 12063936
drwxr-xr-x 2 root root         4096 Nov 20  2024  cache
drwxr-xr-x 2 root root         4096 Jul  4 12:44  iso
-rw-rw---- 1 man  daemon 6176713728 Jun 18  2021 'Net1 - UbuntuMail-disk001.vmdk' <==
-rw-r----- 1 man  daemon        153 Jun 18  2021 'Net1 - UbuntuMail.mf'
-rw-r--r-- 1 root root   6176723456 Jul  4 16:56 'Net1 - UbuntuMail.ova'
-rw-r----- 1 man  daemon       7566 Jun 18  2021 'Net1 - UbuntuMail.ovf'
root@proxmox:/var/lib/vz/template#
```

Convert to qcow2 format

```bash
root@proxmox:/var/lib/vz/template# qemu-img convert -f vmdk -O qcow2 'Net1 - UbuntuMail-disk001.vmdk' net1-ubuntumail_image.qcow2
```

Create a new VM (take note of ID) - in this case, `114`

```bash
root@proxmox:/var/lib/vz/template# qm importdisk 114 /var/lib/vz/template/net1-ubuntumail_image.qcow2 local-lvm
Use of uninitialized value $dev in hash element at /usr/share/perl5/PVE/QemuServer/Drive.pm line 555.
importing disk '/var/lib/vz/template/net1-ubuntumail_image.qcow2' to VM 114 ...
  WARNING: You have not turned on protection against thin pools running out of space.
  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.
  Logical volume "vm-114-disk-1" created.
  WARNING: Sum of all thin volume sizes (1.16 TiB) exceeds the size of thin pool pve/data and the size of whole volume group (<475.94 GiB).
transferred 0.0 B of 20.0 GiB (0.00%)
transferred 204.8 MiB of 20.0 GiB (1.00%)
transferred 411.6 MiB of 20.0 GiB (2.01%)
transferred 616.4 MiB of 20.0 GiB (3.01%)
transferred 821.2 MiB of 20.0 GiB (4.01%)
transferred 1.0 GiB of 20.0 GiB (5.02%)
transferred 1.2 GiB of 20.0 GiB (6.03%)
transferred 1.4 GiB of 20.0 GiB (7.04%)
transferred 1.6 GiB of 20.0 GiB (8.05%)
..
..
transferred 19.9 GiB of 20.0 GiB (99.72%)
transferred 20.0 GiB of 20.0 GiB (100.00%)
transferred 20.0 GiB of 20.0 GiB (100.00%)
unused0: successfully imported disk 'local-lvm:vm-114-disk-1'
root@proxmox:/var/lib/vz/template#
```

The new disk appears *unused*

![](_attachment/Pasted%20image%2020250704172803.png)

Let's attach disk to SCSI controller

```bash
root@proxmox:/var/lib/vz/template# qm set 114 -scsi0 local-lvm:vm-114-disk-1
update VM 114: -scsi0 local-lvm:vm-114-disk-1
```

![](_attachment/Pasted%20image%2020250704174823.png)

After, I removed the "Unused Disk 0"




