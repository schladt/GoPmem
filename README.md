# GoPmem
Physical memory acquisition tool written in Go

Go port of https://github.com/google/rekall/blob/master/tools/windows/winpmem/winpmem.py
Rekall's pmem suite of tools found here https://github.com/google/rekall/tree/master/tools/pmem (Copyright 2012 Michael Cohen <scudette@gmail.com>)

'''
Usage of GoPmem.exe:
  -device string
        Name of kernel driver device (default "pmem")
  -filename string
        Name of output file (default "memdump.bin")
  -load
        Load Winpmem driver and exit
  -mode string
        The acquisition mode [ physical | iospace | pte | pte_pci ] (default "physical")
  -unload
        Unload Winpmem driver and exit
'''