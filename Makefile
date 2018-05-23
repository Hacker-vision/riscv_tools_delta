OPT = riscv_tools_delta.tar.gz

build:
	@rm $(OPT)
	@tar -zcvf $(OPT) binutils/ gcc/ src/ newlib/
	@rm -r ../ri5cy_gnu_toolchain/riscv_tools_delta.tar.gz
	@cp riscv_tools_delta.tar.gz ../ri5cy_gnu_toolchain/
#	cd ../ri5cy_gnu_toolchain
	#make MICRORISCY=1
