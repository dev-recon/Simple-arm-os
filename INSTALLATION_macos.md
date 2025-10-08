# Installation

1. Install Homebrew: ``/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"``
1. Install Arm EABI: ``brew install arm-none-eabi-gcc``
1. Install Qemu: ``brew install qemu``
1. Install mtools ``brew install mtools``
1. Install dos2fs tools ``brew install dosfstools``
1. Install make ``brew install make``

# Run

1. Use the run script to compile kernel, libc, userland programs, create image disk ``disk.img`` and run qemu command for you ``./run.sh``

# Play with it

1. You can adapt or create your own user programs. Just copy/paste a folder program, rename it to the name you wish (max name lenth is 8 - Long name are not yet supported by vfs).
1. Add program name int the ``Makefile`` under ``./userland``. By doing this, the programm will be added to the build chain when you run ``./run.sh``



