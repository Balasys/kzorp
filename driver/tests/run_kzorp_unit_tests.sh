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
"   -k | --kmemleak IMAGE - Base cloud image with a kmemleak-enabled kernel, ignores ARCHITECTURE and VERSION\n" \
"   -r | --repository REPO - GIT repository of kZorp \n" \
"   -b | --branch BRANCH - branch name of the repository where kZorp is compiled from \n" \
"   -a | --arch ARCHITECTURE - Architecture name of the package to be installed\n" \
"   -v | --version VERSION - Ubuntu version to run the test with\n" \
"   -p | --path PATH - Path of the tests directory\n" \
"   -m | --manual - Manual testing with running VM.\n" \
"   -h | --help - Display this information \n"
}

function check_architecture_and_software(){
  programs=( curl cloud-localds )
  packages=( curl cloud-image-utils )

  case "${Architecture}" in
    "amd64")
      Qemu="qemu-system-x86_64 --enable-kvm"
      programs+=( qemu-system-x86_64 )
      packages+=( qemu-system-x86 )
      ;;
    "i386")
      Qemu="qemu-system-i386 --enable-kvm"
      programs+=( qemu-system-i386 )
      packages+=( qemu-system-x86 )
      ;;
    "arm64")
      Qemu="qemu-system-arm -machine virt"
      programs+=( qemu-system-arm )
      packages+=( qemu-system-arm )
      ;;
    *) echo "Error: ${Architecture} is not a supported architecture. Only amd64, i386 and arm64 are supported."; exit 1;;
  esac

  length=$(expr "${#programs[@]}" - 1)
  for i in $(seq 0 "$length"); do
    if ! which "${programs[$i]}" >/dev/null; then
      echo "${programs[$i]} not found!"
      echo "Please install it with: sudo apt-get install ${packages[$i]}"
      exit 1
    fi
  done
}

Repository="https://github.com/balasys/kzorp.git"
Branch="master"

KzorpPath="/tmp/kzorp"
Root="/tmp/kzorp_test_run"

TestSeedConf="run_test.conf"

Architecture="amd64"

OSVersion="18.04"

ManualTesting=0

while (( $# )); do
  case $1 in
    "-k" | "--kmemleak") KMemLeakImage="$2"; shift 2;;
    "-r" | "--repository") Repository="$2"; shift 2;;
    "-b" | "--branch") Branch="$2"; shift 2;;
    "-a" | "--arch") Architecture="$2"; shift 2;;
    "-v" | "--version") OSVersion="$2"; shift 2;;
    "-p" | "--path") Root="$2"; shift 2;;
    "-m" | "--manual") ManualTesting=1; shift 1;;
    "-h" | "--help") print_help; exit 0;;
    *) echo "Invalid option $1" >&2; print_help; exit 1;;
  esac
done

check_architecture_and_software

TestRoot="${Root}/tests"
OSImageDir="${Root}/disk_images"

if [ -z "${KMemLeakImage}" ]; then
  BaseURL="http://cloud-images.ubuntu.com/releases/${OSVersion}/release"
  case "${OSVersion}" in
    "18.04") ImageURL="${BaseURL}/ubuntu-${OSVersion}-server-cloudimg-${Architecture}.img";;
    *)       ImageURL="${BaseURL}/ubuntu-${OSVersion}-server-cloudimg-${Architecture}-disk1.img";;
  esac
else
  ImageURL=${KMemLeakImage}
fi

OSImageName="${ImageURL##*/}"  # The part after the last '/' character (the actual filename)
OSImagePath="${OSImageDir}/${OSImageName}"
OSImagePathSeed="${OSImageDir}/${OSImageName}.seed"

if [ ! -d "${OSImageDir}" ]; then
  mkdir -p "${OSImageDir}"
fi

if [ -f "${KMemLeakImage}" ]; then
  echo "Copy kmemleak image file '${KMemLeakImage}'"
  cp -f "${KMemLeakImage}" "${OSImagePath}"
fi

## Download the image (only once)
if [ ! -f "${OSImagePath}" ]; then
  echo "Image not found under ${OSImagePath}"
  curl "${ImageURL}" -L -o "${OSImagePath}" -z "${OSImagePath}"
  qemu-img check "${OSImagePath}"
fi

## Create the result file so the VM will be able to write it
mkdir -p $TestRoot
touch $TestRoot/result.xml
touch $TestRoot/kmemleak
touch $TestRoot/dmesg

## Packages to install
Packages="
 - git
 - build-essential
 - autoconf
 - libtool
 - python-prctl
 - python-nose
 - python-netaddr"
if [ -z ${KMemLeakImage} ]; then
  Packages="$Packages
 - linux-headers-generic"
fi

AfterTesting=" - sudo poweroff"
if [ $ManualTesting -gt 0 ]; then
  AfterTesting=" - chown -R ubuntu $KzorpPath
 - echo -e '>> VM will not power off, manual testing can be started! <<\n \
VM will not power off, manual testing can be started.\n \
1. Login with \"ubuntu/balasys\"\n \
2. Run \"cd $KzorpPath\" and edit kzorp code if needed\n \
3. Execute \"run_kzorp_unit_tests.sh\" command\n \
4. Run \"sudo poweroff\" when done\n'"
fi

## Create the user-data file for cloud-init
cat > $TestSeedConf <<EOF
#cloud-config
# username is ubuntu
password: balasys
chpasswd: { expire: False }
ssh_pwauth: True
packages: $Packages
hostname: kzorp
manage_etc_hosts: localhost
write_files:
  - content: |
      #!/bin/bash
      set -e
      set -x
      cd $KzorpPath
      autoreconf -i
      ./configure
      lsmod | grep kzorp && sudo rmmod kzorp || true # remove previous kzorp, if existed
      sudo make install-driver
      TEST_PYTHONPATH=\$PWD/pylib:\$PWD/driver/tests/base
      TEST_FILES=\$(find driver/tests/ -name KZorpTestCase\*.py -printf "%p ")
      echo clear | sudo tee /sys/kernel/debug/kmemleak || true
      sudo bash -c "PYTHONPATH=\$PYTHONPATH:\$TEST_PYTHONPATH nosetests --with-xunit \$TEST_FILES"
      sleep 5
      echo scan | sudo tee /sys/kernel/debug/kmemleak || true  # kmemleak is more reliable when scanning twice:
      echo scan | sudo tee /sys/kernel/debug/kmemleak || true  # http://stackoverflow.com/questions/12943906/debug-kernel-module-memory-corruption
      sudo cp /sys/kernel/debug/kmemleak ${TestRoot}/kmemleak || true
      dmesg | sudo tee ${TestRoot}/dmesg > /dev/null
      cp nosetests.xml ${TestRoot}/result.xml
    path: /bin/run_kzorp_unit_tests.sh
    permissions: '0755'
runcmd:
 - uname -a
 - lsb_release -a
 - set -x
 - mkdir -p $TestRoot
 - sudo mount -t 9p -o trans=virtio,version=9p2000.L hostshare $TestRoot
 - git clone $Repository $KzorpPath
 - cd $KzorpPath
 - git checkout $Branch
 - run_kzorp_unit_tests.sh
$AfterTesting
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
if [ ! -z "$KMemLeakImage" ]; then
  cp ${TestRoot}/kmemleak kmemleak
  ./driver/tests/kmemleak2junit.py

  cp ${TestRoot}/dmesg dmesg
  ./driver/tests/kasan2junit.py
fi
