
sto usando Gparted

![immagine.png](immagine.png)

`/dev/sda1` è la partizione di boot, riesco a mountarla

![immagine.png](immagine%201.png)

mm, così non riesco a mountare il file system di root…!

![immagine.png](immagine%202.png)

ah, mancava questo comando: `vgchange -ay` 

adesso posso accedere al filesystem!

![immagine.png](immagine%203.png)

la procedura dovrebbe essere:

```bash
mkdir /mnt/root_fs
modprobe dm-crypt
cryptsetup luksOpen /dev/sda5 nomedeldevice (nel mio esempio: crypt1)
(inserire password)
vgchange -ay
mount /dev/mapper/kaligra--vg-root /mnt/root_fs

```

per avere un’overview della situazione: `dmsetup table`

![immagine.png](immagine%204.png)

per chiudere:

```bash

umount /mnt/root_fs
lvchange -a a kaligra-vg (nome del virtual group)
cryptsetup luksClose nomedeldevice

```

# la mia vecchia kali del 2019

![immagine.png](immagine%205.png)

## /boot si mounta regolarmente

![immagine.png](immagine%206.png)

metto volontariamente la password sbagliata

![immagine.png](immagine%207.png)

metto la pass giusta:

![immagine.png](immagine%208.png)

attivo il “vg”

![immagine.png](immagine%209.png)

virtual group:

![immagine.png](immagine%2010.png)

![immagine.png](immagine%2011.png)

che peccato, mi fa mountare il logical volume, ma apparentemente c’è un *mischiume* di /boot , /etc …

![immagine.png](immagine%2012.png)

il contenuto è palesemente sminchiato:

![immagine.png](immagine%2013.png)