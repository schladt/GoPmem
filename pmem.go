// GoPmem
// Mike Schladt - 2018
// Go port of https://github.com/google/rekall/blob/master/tools/windows/winpmem/winpmem.py

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const DISPLAY_NAME = "Physical Memory Acquistion Tool"

// Constructs control codes for winpmem driver
func CTL_CODE(DeviceType, Function, Method, Access uint32) uint32 {
	return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
}

// struct to abstract image
type Image struct {
	BufferSize             uint64
	Fd                     syscall.Handle
	CTRL_IOCTRL            uint32
	INFO_IOCTRL            uint32
	INFO_IOCTRL_DEPRECATED uint32
	Dtb                    uint64
	Kdbg                   uint64
	MemoryParameters       map[string]uint64
	Runs                   [][]uint64
	Mode                   string
}

// Issues control code to driver to retrieve physical memory paratmeters
// updates MemoryParametres, Kdbg, Dtb, Runs
func (image *Image) ParseMemoryRuns() {
	//set fields
	fields := []string{"CR3", "NtBuildNumber", "KernBase", "KDBG", "KPCR00", "KPCR01", "KPCR02", "KPCR03", "KPCR04", "KPCR05", "KPCR06", "KPCR07", "KPCR08", "KPCR09", "KPCR10", "KPCR11", "KPCR12", "KPCR13", "KPCR14", "KPCR15", "KPCR16", "KPCR17", "KPCR18", "KPCR19", "KPCR20", "KPCR21", "KPCR22", "KPCR23", "KPCR24", "KPCR25", "KPCR26", "KPCR27", "KPCR28", "KPCR29", "KPCR30", "KPCR31", "PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead", "Padding0", "Padding1", "Padding2", "Padding3", "Padding4", "Padding5", "Padding6", "Padding7", "Padding8", "Padding9", "Padding10", "Padding11", "Padding12", "Padding13", "Padding14", "Padding15", "Padding16", "Padding17", "Padding18", "Padding19", "Padding20", "Padding21", "Padding22", "Padding23", "Padding24", "Padding25", "Padding26", "Padding27", "Padding28", "Padding29", "Padding30", "Padding31", "Padding32", "Padding33", "Padding34", "Padding35", "Padding36", "Padding37", "Padding38", "Padding39", "Padding40", "Padding41", "Padding42", "Padding43", "Padding44", "Padding45", "Padding46", "Padding47", "Padding48", "Padding49", "Padding50", "Padding51", "Padding52", "Padding53", "Padding54", "Padding55", "Padding56", "Padding57", "Padding58", "Padding59", "Padding60", "Padding61", "Padding62", "Padding63", "Padding64", "Padding65", "Padding66", "Padding67", "Padding68", "Padding69", "Padding70", "Padding71", "Padding72", "Padding73", "Padding74", "Padding75", "Padding76", "Padding77", "Padding78", "Padding79", "Padding80", "Padding81", "Padding82", "Padding83", "Padding84", "Padding85", "Padding86", "Padding87", "Padding88", "Padding89", "Padding90", "Padding91", "Padding92", "Padding93", "Padding94", "Padding95", "Padding96", "Padding97", "Padding98", "Padding99", "Padding100", "Padding101", "Padding102", "Padding103", "Padding104", "Padding105", "Padding106", "Padding107", "Padding108", "Padding109", "Padding110", "Padding111", "Padding112", "Padding113", "Padding114", "Padding115", "Padding116", "Padding117", "Padding118", "Padding119", "Padding120", "Padding121", "Padding122", "Padding123", "Padding124", "Padding125", "Padding126", "Padding127", "Padding128", "Padding129", "Padding130", "Padding131", "Padding132", "Padding133", "Padding134", "Padding135", "Padding136", "Padding137", "Padding138", "Padding139", "Padding140", "Padding141", "Padding142", "Padding143", "Padding144", "Padding145", "Padding146", "Padding147", "Padding148", "Padding149", "Padding150", "Padding151", "Padding152", "Padding153", "Padding154", "Padding155", "Padding156", "Padding157", "Padding158", "Padding159", "Padding160", "Padding161", "Padding162", "Padding163", "Padding164", "Padding165", "Padding166", "Padding167", "Padding168", "Padding169", "Padding170", "Padding171", "Padding172", "Padding173", "Padding174", "Padding175", "Padding176", "Padding177", "Padding178", "Padding179", "Padding180", "Padding181", "Padding182", "Padding183", "Padding184", "Padding185", "Padding186", "Padding187", "Padding188", "Padding189", "Padding190", "Padding191", "Padding192", "Padding193", "Padding194", "Padding195", "Padding196", "Padding197", "Padding198", "Padding199", "Padding200", "Padding201", "Padding202", "Padding203", "Padding204", "Padding205", "Padding206", "Padding207", "Padding208", "Padding209", "Padding210", "Padding211", "Padding212", "Padding213", "Padding214", "Padding215", "Padding216", "Padding217", "Padding218", "Padding219", "Padding220", "Padding221", "Padding222", "Padding223", "Padding224", "Padding225", "Padding226", "Padding227", "Padding228", "Padding229", "Padding230", "Padding231", "Padding232", "Padding233", "Padding234", "Padding235", "Padding236", "Padding237", "Padding238", "Padding239", "Padding240", "Padding241", "Padding242", "Padding243", "Padding244", "Padding245", "Padding246", "Padding247", "Padding248", "Padding249", "Padding250", "Padding251", "Padding252", "Padding253", "Padding254", "NumberOfRuns"}

	//issue driver command
	outBuffer := make([]byte, 102400)
	var bytesReturned uint32
	err := syscall.DeviceIoControl(
		image.Fd,
		image.INFO_IOCTRL,
		nil,
		0,
		&outBuffer[0],
		uint32(len(outBuffer)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		log.Printf("Unable to parse memory runs: %v", err)
	}

	//parse output buffer to field in memory map
	image.MemoryParameters = make(map[string]uint64)
	for i, field := range fields {
		image.MemoryParameters[field] = binary.LittleEndian.Uint64(outBuffer[i*8 : (i+1)*8])
	}

	//house keeping
	image.Dtb = image.MemoryParameters["CR3"]
	image.Kdbg = image.MemoryParameters["KDBG"]

	//get memory runs
	for i := 0; i < int(image.MemoryParameters["NumberOfRuns"]); i++ {
		offset := i*16 + (len(fields) * 8)
		start := binary.LittleEndian.Uint64(outBuffer[offset : offset+8])
		offset = offset + 8
		length := binary.LittleEndian.Uint64(outBuffer[offset : offset+8])
		image.Runs = append(image.Runs, []uint64{start, length})
	}
}

// Prints memory information to console
func (image *Image) GetInfo() {
	fmt.Println("--------------------------------------")
	fmt.Println("Memory Parameters:")
	for key, value := range image.MemoryParameters {
		if strings.HasPrefix(key, "Pad") || value == 0 {
			continue
		}

		fmt.Printf("%s: \t%#08x (%v)\n", key, value, value)

	}

	//print runs
	fmt.Println("--------------------------------------")
	fmt.Println("Memory Ranges:")
	fmt.Println("Start\t\tEnd\t\tLength")
	for _, item := range image.Runs {
		start := item[0]
		length := item[1]
		fmt.Printf("0x%X\t\t0x%X\t\t0x%X\n", start, start+length, length)
	}
	fmt.Println("--------------------------------------")
}

//Sets the acquistion mode via control codes to the driver
func (image *Image) SetMode() {

	mode := make([]byte, 4)
	switch image.Mode {
	case "iospace":
		binary.LittleEndian.PutUint32(mode, 0)
	case "physical":
		binary.LittleEndian.PutUint32(mode, 1)
	case "pte":
		binary.LittleEndian.PutUint32(mode, 2)
	case "pte_pci":
		binary.LittleEndian.PutUint32(mode, 3)
	default:
		log.Panic("Unknown mode: " + image.Mode)
	}

	//issue deviceiocontorl command
	err := syscall.DeviceIoControl(
		image.Fd,
		image.CTRL_IOCTRL,
		&mode[0],
		4,
		nil,
		0,
		nil,
		nil,
	)
	if err != nil {
		log.Printf("Unable to parse set memory acquistion mode: %v", err)
	}

}

// pads output file with null characters
func (image *Image) PadWithNulls(out *os.File, length uint64) {
	for length > 0 {
		// write min between length and buffersize
		var toWrite uint64
		if length > image.BufferSize {
			toWrite = image.BufferSize
		} else {
			toWrite = length
		}

		out.Write(make([]byte, toWrite))
		length = length - toWrite
	}
}

// Read the image and write all the data to a raw file."
func (image *Image) DumpWithRead(outFilename string) error {
	//open new file for writing
	out, err := os.Create(outFilename)
	if err != nil {
		return err
	}
	defer out.Close()

	fmt.Println("--------------------------------------")
	fmt.Println("Dumping Memory:")

	var offset uint64
	for _, item := range image.Runs {
		start := item[0]
		length := item[1]

		// pad with null
		if start > offset {
			fmt.Printf("\nPadding from 0x%X to 0x%X\n", offset, start)
			image.PadWithNulls(out, start-offset)
		}

		offset = start
		end := start + length
		for offset < end {
			var toRead uint32
			if image.BufferSize > end-offset {
				toRead = uint32(end - offset)
			} else {
				toRead = uint32(image.BufferSize)
			}

			//set filepointer to offset
			offsetBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(offsetBytes, offset)
			lowoffset := *(*int32)(unsafe.Pointer(&offsetBytes[0]))
			highoffsetptr := (*int32)(unsafe.Pointer(&offsetBytes[4]))

			_, err := syscall.SetFilePointer(image.Fd, lowoffset, highoffsetptr, 0)
			if err != nil {
				return err
			}

			// read bytes
			buf := make([]byte, toRead)
			if err := syscall.ReadFile(image.Fd, buf, &toRead, nil); err != nil {
				return err
			}

			//write bytes
			out.Write(buf)

			// update offset
			offset = offset + uint64(toRead)

			// print status
			offsetMb := offset / 1024 / 1024
			if offsetMb%50 == 0 {
				fmt.Printf("\n%04dMB\t", offsetMb)
			}

			fmt.Printf(".")
		}
	}
	fmt.Printf("\n")
	fmt.Println("Memory dump written to", outFilename)
	return nil
}

func main() {

	//set up flags
	loadDriverFlag := flag.Bool("load", false, "Load Winpmem driver and exit")
	unloadDriverFlag := flag.Bool("unload", false, "Unload Winpmem driver and exit")
	filenameFlag := flag.String("filename", "memdump.bin", "Name of output file")
	modeFlag := flag.String("mode", "physical", "The acquisition mode [ physical | iospace | pte | pte_pci ]")
	deviceNameFlag := flag.String("device", "pmem", "Name of kernel driver device")
	flag.Parse()

	if *loadDriverFlag == true {
		if err := LoadDriver(*deviceNameFlag); err != nil {
			log.Fatalf("Unable to load winpmem driver: %v", err)
		}
		return
	}

	if *unloadDriverFlag == true {
		if err := UnloadDriver(*deviceNameFlag); err != nil {
			log.Fatalf("Unable to unload winpmem driver: %v", err)
		}
		return
	}

	//acquire image by default
	if err := AcquireImage(*deviceNameFlag, *modeFlag, *filenameFlag); err != nil {
		log.Fatalf("Unable to acquire memory image: %v", err)
	}
}

// Perfoms memory acquistion
func AcquireImage(deviceName, mode, filename string) error {

	// unload drivers to start clean, ignoring errors
	UnloadDriver(deviceName)

	// load drivers
	if err := LoadDriver(deviceName); err != nil {
		return err
	}
	defer UnloadDriver(deviceName)

	// open device
	fd, err := syscall.CreateFile(
		syscall.StringToUTF16Ptr("\\\\.\\"+deviceName),
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Create Image instance
	image := Image{
		BufferSize:             1024 * 1024,
		Fd:                     fd,
		CTRL_IOCTRL:            CTL_CODE(0x22, 0x101, 0, 3),
		INFO_IOCTRL:            CTL_CODE(0x22, 0x103, 0, 3),
		INFO_IOCTRL_DEPRECATED: CTL_CODE(0x22, 0x100, 0, 3),
		Mode: mode,
	}

	image.SetMode()
	image.ParseMemoryRuns()
	image.GetInfo()
	if err := image.DumpWithRead(filename); err != nil {
		log.Fatalf("Unable to acquire image: %v", err)
	}
	return nil
}

// Loads winpmem driver (from embedded resource)
// INPUT: deviceName (string): name of device created
func LoadDriver(deviceName string) error {
	log.Println("Loading Winpmem Driver...")

	// Store driver to tempfile
	var driverName string
	if runtime.GOARCH == "386" {
		driverName = "winpmem_x86.sys"
	} else if runtime.GOARCH == "amd64" {
		driverName = "winpmem_x64.sys"
	} else {
		return errors.New("Architecture not supported: " + runtime.GOARCH)
	}

	//get file content
	content, err := Asset("res/" + driverName)
	if err != nil {
		return err
	}

	//write to file
	driverPath := filepath.Join(os.Getenv("SYSTEMROOT"), "system32", "drivers", driverName)
	if err := ioutil.WriteFile(driverPath, content, 0755); err != nil {
		return err
	}

	log.Println("Driver saved to", driverPath)

	//create service
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(deviceName)
	if err == nil {
		s.Close()
		return errors.New("Serivce already exists.")
	}
	config := mgr.Config{
		ServiceType: windows.SERVICE_KERNEL_DRIVER,
		StartType:   mgr.StartManual,
		Description: DISPLAY_NAME,
	}

	s, err = m.CreateService(deviceName, driverPath, config)
	if err != nil {
		return err
	}
	defer s.Close()

	log.Println("Service created.")

	//start service
	if err := ControlService(deviceName, "start"); err != nil {
		return err
	}

	return nil
}

//Unload driver
func UnloadDriver(deviceName string) error {
	log.Println("Unloading Winpmem Driver...")

	// Store driver to tempfile
	var driverName string
	if runtime.GOARCH == "386" {
		driverName = "winpmem_x86.sys"
	} else if runtime.GOARCH == "amd64" {
		driverName = "winpmem_x64.sys"
	} else {
		return errors.New("Architecture not supported: " + runtime.GOARCH)
	}

	driverPath := filepath.Join(os.Getenv("SYSTEMROOT"), "system32", "drivers", driverName)

	//stop service
	if err := ControlService(deviceName, "stop"); err != nil {
		log.Printf("Unable to stop service: %v", err)
	}

	//remove service
	if err := ControlService(deviceName, "delete"); err != nil {
		log.Printf("Unable to delete service: %v", err)
	}

	//Delete driver file
	if err := os.Remove(driverPath); err != nil {
		log.Printf("Unable to remove driver file %v : %v", driverPath, err)
	} else {
		log.Printf("Drive file removed from: %v", driverPath)
	}

	return nil
}

//performs actions on
//INPUT: serviceName (string) - name of service to control
//INPUTL action (string) - choose from start, stop, delete
func ControlService(serviceName, action string) error {
	//open manager
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	//open service
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	//stop service
	if action == "stop" {
		status, err := s.Control(svc.Stop)
		if err != nil {
			return err
		}
		timeout := time.Now().Add(10 * time.Second)
		for status.State != svc.Stopped {
			if timeout.Before(time.Now()) {
				return errors.New("Timed out waiting for service to stop")
			}
			time.Sleep(300 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				return err
			}
		}
		log.Println("Service stopped.")
	}
	if action == "delete" {
		if err := s.Delete(); err != nil {
			log.Printf("Unable to delete service: %v", err)

		} else {
			log.Println("Service deleted.")
		}
	}
	if action == "start" {
		if err := s.Start(); err != nil {
			return err
		}
		log.Println("Service started")
	}

	return nil
}
