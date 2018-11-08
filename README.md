# RummeryKOTH
Rummery participated in a King of the Hill competition a while back. The idea was fairly simple. You uploaded executables to a virtual machine, where
they were run as SYSTEM. Every time your QR code was read from the screen, you get points. If the watchdog on the machine didn't report back for
a while, and if test programs uploaded into the machine didn't run properly,  the machine was reset (so just writing a bootloader wasn't a
particularly sound strategy).


We started out spawning a webpage in internet explorer, and ended with workspace switching, spawning processes on winlogon, drawing directly
on the screen, and trashing the disk with our own bootloader. We ultimately held comfortable second place against David Buchanan's display driver.

## Omissions
Names have been redacted from images, and removed from some files. There's also no binaries, for obvious reasons.

## Caveats
* This is a mess. We kept dead code around, switched things out as we needed them, and we enschewed anything resembling efficiency on the basis
that it offered more CPU time to the enemy.
* This doesn't contain any exploits. Some of the more entertaining features rely entirely on running under SYSTEM. This is probably a good thing.
