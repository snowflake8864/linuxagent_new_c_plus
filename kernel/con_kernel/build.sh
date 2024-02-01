#!/bin/bash
#set -ex

#bash  clean.sh
#make KPATH=/root/code/code/linux/kernel/3.10.0-514.el7.x86_64
#mv osec_base.ko osec_base.ko-3.10.0-514-centos
mkdir output

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.4.0-142-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.4.0-142-ubuntu

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-16-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.18.0-16-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-15-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.18.0-15-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.19.0-6-amd64/build -j8
mv osec_base.ko output/osec_base.ko-4.19.0-6-amd64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-1062.12.1.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-1062.12.1.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-1127.10.1.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-1127.10.1.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-229.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-229.el7.x86_64


bash  clean.sh
make KPATH=/root/code/code/linux/kernel/centos/3.10.0-327.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-327.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-148-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.4.0-148-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_ubuntu/4.4.0-21-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.4.0-21-generic

bash clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-88-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.15.0-88-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/2.6.32-642.el6.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-2.6.32-642.el6.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/2.6.32-696.el6.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-2.6.32-696.el6.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-514.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-514.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-693.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-693.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/0629_centos/3.10.0-862.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-862.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-30deepin-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.15.0-30deepin-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-212-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.15.0-212-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.8.0-36-generic/build -j8 
mv osec_base.ko output/osec_base.ko-4.8.0-36-generic


bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-42-generic/build -j8
mv osec_base.ko output/osec_base.ko-5.4.0-42-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.20/build -j8
mv osec_base.ko output/osec_base.ko-5.4.119-20.0009.20


bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.18.0-348.el8.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-4.18.0-348.el8.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-1160.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-1160.el7.x86_64

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.119-20.0009.20/build -j8
mv osec_base.ko output/osec_base.ko-5.4.119-20.0009.20
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/4.15.0-213-generic/build -j8
mv osec_base.ko output/osec_base.ko-4.15.0-213-generic
bash  clean.sh
make KPATH=/root/code/code/linux/kernel/5.4.0-81-generic/build -j8
mv osec_base.ko output/osec_base.ko-5.4.0-81-generic

bash  clean.sh
make KPATH=/root/code/code/linux/kernel/3.10.0-957.el7.x86_64/build -j8
mv osec_base.ko output/osec_base.ko-3.10.0-957.el7.x86_64

