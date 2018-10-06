package main

import (
	"fmt"
	"log"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/nanitefactory/gominhook"
	"github.com/nanitefactory/winmb"
	"github.com/zetamatta/go-outputdebug"
)

// ----------------------------------------------------------------------------

/*
#include <string.h>
#include <Windows.h>

// Due to lack of my knowledge in reversing I literally have no idea what the return type of these functions would be though.
// Arguments could be guessed; 64-bit integers because they always pass in R8, RDX, RCX in order.

typedef DWORD64 (*ProtoOnDisplayUpdate)(DWORD64, DWORD64, DWORD64);
DWORD64 OnDisplayUpdate(DWORD64, DWORD64, DWORD64);

typedef DWORD64 (*ProtoOnNumberUpdate)(DWORD64, DWORD64, DWORD64);
DWORD64 OnNumberUpdate(DWORD64, DWORD64, DWORD64);

*/
import "C"

var isInMiddleOfOnDisplayUpdate bool

var fpDisplayUpdate C.ProtoOnDisplayUpdate
var fpNumberUpdate C.ProtoOnNumberUpdate

//export OnDisplayUpdate
func OnDisplayUpdate(arg1, arg2, arg3 uintptr) (ret uintptr) {
	isInMiddleOfOnDisplayUpdate = true
	ret, _, _ = syscall.Syscall6(uintptr(unsafe.Pointer(fpDisplayUpdate)), 3, arg1, arg2, arg3, 0, 0, 0)
	return
}

//export OnNumberUpdate
func OnNumberUpdate(arg1, arg2, arg3 uintptr) (ret uintptr) {
	// See if it's hooked well. // arg3 points to the stack where our string is stored.
	outputdebug.String("OnNumberUpdate(): " + fmt.Sprintf("Arguments passed: 0x%X 0x%X 0x%X", arg1, arg2, arg3))

	// If this OnNumberUpdate() is not called from OnDisplayUpdate(), don't do nothing and fallthrough.
	if !isInMiddleOfOnDisplayUpdate {
		ret, _, _ = syscall.Syscall6(uintptr(unsafe.Pointer(fpNumberUpdate)), 3, arg1, arg2, arg3, 0, 0, 0)
		return
	}
	isInMiddleOfOnDisplayUpdate = false

	// Convert our UTF16 string (WSTR) to which our arg3 points to a plain Go string.
	strArg3 := lpwstrToString((C.LPCWSTR)(unsafe.Pointer(arg3)))
	outputdebug.String("original text: " + strArg3)

	// Make some changes to this copied string.
	strArg3 = strings.Replace(strArg3, "0", "空", -1)
	strArg3 = strings.Replace(strArg3, "1", "一", -1)
	strArg3 = strings.Replace(strArg3, "2", "二", -1)
	strArg3 = strings.Replace(strArg3, "3", "三", -1)
	strArg3 = strings.Replace(strArg3, "4", "四", -1)
	strArg3 = strings.Replace(strArg3, "5", "五", -1)
	strArg3 = strings.Replace(strArg3, "6", "六", -1)
	strArg3 = strings.Replace(strArg3, "7", "七", -1)
	strArg3 = strings.Replace(strArg3, "8", "八", -1)
	strArg3 = strings.Replace(strArg3, "9", "九", -1)
	// strArg3 = "야옹, 멍멍, 귀여워! <" + strArg3 + "> by 코코넛 xD 냠냠"
	outputdebug.String("modified text: " + strArg3)

	// Get another copy of that modified string with a ptr to it.
	newArg3 := syscall.StringToUTF16Ptr(strArg3)
	sizeNewArg3 := len(syscall.StringToUTF16(strArg3)) * 2 // size as byte array
	outputdebug.String("arg3: " + fmt.Sprintf("0x%X -> 0x%X -> 0x%X", arg3, strArg3, newArg3))

	// ----------------------------------------------------------------------------
	// Copy this new string to where arg3 points to.

	// Going to read & write memory with kernel32 API.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")

	hProcess, _, _ := syscall.Syscall(
		kernel32.NewProc("GetCurrentProcess").Addr(),
		0, 0, 0, 0,
	)

	var oldProtect C.DWORD
	ret, _, err := syscall.Syscall6(
		kernel32.NewProc("VirtualProtectEx").Addr(),
		5, hProcess, arg3, uintptr(sizeNewArg3), C.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)), 0,
	)
	outputdebug.String(fmt.Sprint(ret, err)) // ret: return code. err: return detail.

	ret, _, err = syscall.Syscall6(
		kernel32.NewProc("WriteProcessMemory").Addr(),
		4, hProcess, arg3, uintptr(unsafe.Pointer(newArg3)), uintptr(sizeNewArg3), 0, 0,
	)
	outputdebug.String(fmt.Sprint(ret, err)) // ret: return code. err: return detail.
	// ----------------------------------------------------------------------------

	// Call the original function.
	ret, _, _ = syscall.Syscall6(uintptr(unsafe.Pointer(fpNumberUpdate)), 3, arg1, arg2, arg3, 0, 0, 0)
	return
}

func lpwstrToString(cwstr C.LPCWSTR) string {
	const maxRunes = 1<<30 - 1
	ptr := unsafe.Pointer(cwstr)
	sz := C.wcslen((*C.wchar_t)(ptr))
	wstr := (*[maxRunes]uint16)(ptr)[:sz:sz]
	return string(utf16.Decode(wstr))
}

// ----------------------------------------------------------------------------

// GetProcessModuleHandle returns the base address of .exe module.
//export GetProcessModuleHandle
func GetProcessModuleHandle() (hModule uintptr) {
	hModule, _, _ = syscall.Syscall( // (HANDLE)GetModuleHandle(NULL);
		syscall.NewLazyDLL("kernel32.dll").NewProc("GetModuleHandleW").Addr(),
		1, 0, 0, 0,
	)
	outputdebug.String(fmt.Sprintf("GetProcessModuleHandle(): 0x%X", hModule))
	return
}

// GetHookPoint in our process.
//export GetHookPoint
func GetHookPoint(offset uintptr) (hookPoint uintptr) {
	base := GetProcessModuleHandle()
	hookPoint = base + offset
	outputdebug.String(fmt.Sprintf("GetHookPoint(): 0x%X = 0x%X + 0x%X", hookPoint, base, offset))
	return
}

// OnProcessAttach is an async callback (hook).
//export OnProcessAttach
func OnProcessAttach(
	hinstDLL unsafe.Pointer, // handle to DLL module
	fdwReason uint32, // reason for calling function
	lpReserved unsafe.Pointer, // reserved
) {
	// Initialize minhook
	err := gominhook.Initialize()
	if err != nil {
		outputdebug.String(err.Error())
		log.Fatalln(err)
	}

	// Clean-up minhook
	defer func() {
		// Unhook
		err := gominhook.DisableHook(gominhook.AllHooks)
		if err != nil {
			outputdebug.String(err.Error())
			log.Println(err)
		}
		// Uninitialize
		err = gominhook.Uninitialize()
		if err != nil {
			outputdebug.String(err.Error())
			log.Println(err)
		}
	}()

	// ----------------------------------------------------------------------------

	// Create a hook for OnDisplayUpdate(). // Calculator.exe+2BBC8 - 48 89 5C 24 08        - mov [rsp+08],rbx
	err = gominhook.CreateHook(GetHookPoint(0x2BBC8), uintptr(C.OnDisplayUpdate), uintptr(unsafe.Pointer(&fpDisplayUpdate)))
	if err != nil {
		outputdebug.String(err.Error())
		log.Fatalln(err)
	}

	// Create a hook for OnNumberUpdate(). // Calculator.exe+2BC94 - 48 89 5C 24 08        - mov [rsp+08],rbx
	err = gominhook.CreateHook(GetHookPoint(0x2BC94), uintptr(C.OnNumberUpdate), uintptr(unsafe.Pointer(&fpNumberUpdate)))
	if err != nil {
		outputdebug.String(err.Error())
		log.Fatalln(err)
	}

	// Enable the hook.
	err = gominhook.EnableHook(gominhook.AllHooks)
	if err != nil {
		outputdebug.String(err.Error())
		log.Fatalln(err)
	}

	// ----------------------------------------------------------------------------

	// Block this routine.
	ch := make(chan int)
	<-ch
	outputdebug.String("OnProcessAttach(): Exit")
}

// ----------------------------------------------------------------------------

//export MessageBoxTest
func MessageBoxTest() {
	winmb.MessageBoxPlain("export Test", "export Test")
}

//export Test
func Test() {
}

const title = "TITLE"

var version = "undefined"

func main() {
	// nothing really. xD
}
