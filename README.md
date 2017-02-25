# maclook4ref
Quickly find references to the specified Immediate number, or find the function call of specifies offset, and generate C++ functions call backtrace, The disassembly framework used is [Capstone](http://www.capstone-engine.org/)

[![Contact](https://img.shields.io/badge/contact-@cocoahuke-fbb52b.svg?style=flat)](https://twitter.com/cocoahuke) [![build](https://travis-ci.org/cocoahuke/maclook4ref.svg?branch=master)](https://travis-ci.org/cocoahuke/maclook4ref) [![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/cocoahuke/maclook4ref/blob/master/LICENSE) [![paypal](https://img.shields.io/badge/Donate-PayPal-039ce0.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=EQDXSYW8Z23UY)

This tool does not support iOS, its used to analyze kext of Macos

When you statically analyze a kernel extension of a Mac to look for vulnerabilities, you may want to find out where this might exploitable C++ function call come from.
It may come from a call from a function call from a very complicated `external Method`, if it does, then you may get a way to influence or control something about that function.

C ++ function calls essentially are jump to a function address that get from vtable with an offset. The address of vtable is fixed relative to the program code, the fixed address will be saved in memory of allocation of the instance, get the vtable address from the instance, and then add an offset to the vtable to get the function address, finally use the instruction jump to there.

The principle of this tool is very simple, scan the entire `__text` section of binary to match specified offset, get the location and print it together with the respective C ++ functions, so can be clear at a glance.

Let's see demo

## Usage
```
Usage: maclook4ref <target Mac kext path> <hexadecimal offset of seek> [-p <index>] [-s] [-l]
	-p try to generate functions call backtrace
	-s print vtable offsets and results, its slow
	-l list all vtable offsets, its slow
  ```
## Tool demo

### Lists the vtable offsets for all functions
```
maclook4ref "IOThunderboltFamily" - -l
```
```
...
2642 [0x360]IOThunderboltTransmitCommand::_RESERVEDIOThunderboltTransmitCommand31
2643 [0x960]IOThunderboltFamilyUserClient::checkArguments
2644 [0xbd0]IOThunderboltSwitchType1::resetMessagedArray
2645 [?]IOThunderboltConfigWriteQuadletCommand::withController
2646 [0x158]IOThunderboltDispatchContext::getUInt64Parameter
2647 [0xd20]IOThunderboltSwitch::wakeLocalPorts
...
```
*`[?]` mean didn't found, The reason usually is the class isn't defined in this binary*

`checkArguments` is used to parse the user state parameter, which is mean that place where the call to this function, can be affected from the userland

###Then looking for references to `0x960` immediate numbers

```
maclook4ref "IOThunderboltFamily" 0x960
```
```
0.in IOThunderboltFamilyUserClient::plugEvent
0x455B:	xor		r9d, r9d
0x455E:	mov		rdi, r12
0x4561:	mov		rsi, rbx
0x4564:	call		qword ptr [rax + 0x960]
0x456A:	mov		r14d, eax
0x456D:	test		r14d, r14d


1.in IOThunderboltFamilyUserClient::configWriteAction
0x48F2:	xor		ecx, ecx
0x48F4:	xor		r8d, r8d
0x48F7:	xor		r9d, r9d
0x48FA:	call		qword ptr [rax + 0x960]
0x4900:	mov		r13d, eax
0x4903:	test		r13d, r13d


2.in IOThunderboltFamilyUserClient::xDomainRequestAction
0x4AFE:	xor		r9d, r9d
0x4B01:	mov		rdi, r12
0x4B04:	mov		rsi, rbx
0x4B07:	call		qword ptr [rax + 0x960]
0x4B0D:	test		eax, eax
0x4B0F:	je		0x4b28
...
```

<p align="center">
<img src="IMG1.png" height="360" />
</p>

With the Instruction address you can quickly jump there in IDA, and start analysis

###Or you want to search for backtracking, list all possible places where function call from
###Example: Lists all possible calls to `configWriteAction`

```
maclook4ref "IOThunderboltFamily" 0x960 -p 1
```
```
|- [0x988]IOThunderboltFamilyUserClient::configWrite(0x48bd)
|- - [0x850]IOThunderboltFamilyUserClient::externalMethod(0x3fe2)
|- - [0x970]IOThunderboltSwitch::createResources (0x16c8a)
|- - [0x978]IOThunderboltSwitchType2::destroyResources (0x50fa9)
|- - [0x978]IOThunderboltSwitchType1::destroyResources (0x58178)
|- [0x978]IOThunderboltSwitch::destroyResources (0x17126)
|- - [0x860]IOThunderboltController::incrementScanCount (0x2909)
|- - [0x868]IOThunderboltController::decrementScanCount (0x2a45)
```

<p align="center">
<img src="IMG2.png" height="360" />
</p>

Correct backtrace in example are: `configWriteAction`<- `configWrite` <- `externalMethod`

The horizontal line on the left indicates the depth, I set the depth limit to 2. The right side is the instruction address
Data will lose meaning if depth over than 2, it's may fall into a loop. So the most credible data is the first line, better belong to the same class

This tool may help you save some time, hope it will help some  
Thank you for read

# **Compile and install** to /usr/local/bin/

```bash
git clone https://github.com/cocoahuke/maclook4ref.git \
&& cd maclook4ref && make && make install
```
