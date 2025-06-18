
файл genl_test1.c должен находится в /tools/testing/selftests/net/ для ипользования kselftests
Для компиляции genl_test1.c с использованием библиотеки libnl:
gcc genl_test1.c -o genl_test1 $(pkg-config --cflags libnl-3.0 libnl-genl-3.0) -lnl-3 -lnl-genl-3

Для того, чтобы Netlink сам загружал нужный модуль необходимо
sudo cp $(pwd)/net-pf-16-proto-16-family-PARALLEL_GENL.ko /lib/modules/$(uname -r)/kernel
sudo depmod -a
