#!/bin/bash

set -e

## Dependencies
# sudo modprobe kvm
# sudo service virtualbox stop
# sudo service qemu-kvm start
# sudo apt-get install kvm cloud-utils genisoimage

function print_help(){
    echo -e \
"Usage of $0:\n" \
"   $0 [options]\n" \
"Options:\n" \
"   -k | --kmemleak IMAGE - Base cloud image with a kmemleak-enabled kernel to download, ignores ARCHITECTURE and VERSION\n" \
"   -r | --repository REPO - GIT repository of kZorp \n" \
"   -b | --branch BRANCH - branch name of the repository where kZorp is compiled from \n" \
"   -a | --arch ARCHITECTURE - Architecture name of the package to be installed\n" \
"   -v | --version VERSION - Ubuntu version to run the test with\n" \
"   -p | --path PATH - Path of the tests directory\n"
"   -h | --help - Display this information \n"
}

Repository="https://github.com/balabit/kzorp.git"
Branch="master"

Root="/tmp/kzorp_test_run"

TestSeedConf="run_test.conf"

Architecture="amd64"

OSVersion="14.04"

while (( $# )); do
  case $1 in
    "-k" | "--kmemleak") KMemLeakURL="$2"; shift 2;;
    "-r" | "--Repository") Repository="$2"; shift 2;;
    "-b" | "--branch") Branch="$2"; shift 2;;
    "-a" | "--arch") Architecture="$2"; shift 2;;
    "-v" | "--version") OSVersion="$2"; shift 2;;
    "-p" | "--path") Root="$2"; shift 2;;
    "-h" | "--help") print_help; exit 0;;
    *) echo "Invalid option $1" >&2; print_help; exit 1;;
  esac
done

case ${Architecture} in
  "amd64") Qemu="qemu-system-x86_64 --enable-kvm";;
  "i386") Qemu="qemu-system-i386 --enable-kvm";;
  "arm64") Qemu="qemu-system-arm -machine virt";;
  *) echo "Error: ${Architecture} is not a supported architecture. Only amd64, i386 and arm64 are supported."; exit 1;;
esac

TestRoot="${Root}/tests"
OSImageDir="${Root}/disk_images"

if [ -z ${KMemLeakURL} ]; then
  ImageURL="http://cloud-images.ubuntu.com/server/releases/${OSVersion}/release"
  ImageURL="${ImageURL}/ubuntu-${OSVersion}-server-cloudimg-${Architecture}-disk1.img"
else
  ImageURL=${KMemLeakURL}
fi

OSImageName="${ImageURL##*/}"  # The part after the last '/' character (the actual filename)
OSImagePath="${OSImageDir}/${OSImageName}"
OSImagePathSeed="${OSImageDir}/${OSImageName}.seed"

if [ ! -d ${OSImageDir} ]; then
  mkdir -p ${OSImageDir}
fi

## Download the image (only once)
if [ ! -f ${OSImagePath} ]; then
  echo "Image not found under ${OSImagePath}"
  wget $ImageURL -O ${OSImagePath}
fi

## Create the result file so the VM will be able to write it
mkdir -p $TestRoot
touch $TestRoot/result.xml
touch $TestRoot/kmemleak

## Packages to install
Packages="
 - git
 - build-essential
 - autoconf
 - libtool
 - python-prctl
 - python-nose
 - python-netaddr"
if [ -z ${KMemLeakURL} ]; then
  Packages="$Packages
 - linux-headers-generic"
fi

## Create the user-data file for cloud-init
cat > $TestSeedConf <<EOF
#cloud-config
password: zorp
chpasswd: { expire: False }
ssh_pwauth: True
apt_proxy: http://proxy.balabit:3128
packages: $Packages
runcmd:
 - set -x
 - mkdir -p $TestRoot
 - sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare $TestRoot
 - cd
 - git clone $Repository
 - cd kzorp
 - git checkout $Branch
 - autoreconf -i
 - ./configure
 - sudo make install-driver
 - TEST_PYTHONPATH=\$PWD/pylib:\$PWD/driver/tests/base
 - TEST_FILES=\`find driver/tests/ -name KZorpTestCase\*.py -printf "%p "\`
 - echo clear | sudo tee /sys/kernel/debug/kmemleak
 - sudo bash -c "PYTHONPATH=\$PYTHONPATH:\$TEST_PYTHONPATH nosetests --with-xunit \$TEST_FILES"
 - sleep 5
 - echo scan | sudo tee /sys/kernel/debug/kmemleak  # kmemleak is more reliable when scanning twice:
 - echo scan | sudo tee /sys/kernel/debug/kmemleak  # http://stackoverflow.com/questions/12943906/debug-kernel-module-memory-corruption
 - sudo cp /sys/kernel/debug/kmemleak ${TestRoot}/kmemleak
 - cp nosetests.xml ${TestRoot}/result.xml
 - sudo poweroff
EOF

## create the disk with NoCloud data on it.
cloud-localds ${OSImagePathSeed} $TestSeedConf

## Boot a kvm, using the downloaded image as a snapshot and leaving it intact
# In a terminal you can login to the machine through the curses interface
#qemu-system-x86_64 --enable-kvm -curses -net nic -net user -hda ${OSImagePath} -hdb ${OSImagePathSeed} -m 2048 -fsdev local,security_model=passthrough,id=fsdev0,path=$TestRoot -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare -snapshot

# Jenkins runs this without terminal
${Qemu} -nographic -net nic -net user -hda ${OSImagePath} -hdb ${OSImagePathSeed} -m 2048 -fsdev local,security_model=passthrough,id=fsdev0,path=$TestRoot -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=hostshare -snapshot

## Copy the test result to the CWD, so Jenkins can access it
cp ${TestRoot}/result.xml result.xml
if [ ! -z $KMemLeakURL ]; then
  cp ${TestRoot}/kmemleak kmemleak
  ./driver/tests/kmemleak2junit.py
fi
