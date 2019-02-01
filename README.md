# Ridgway

A quick tool for hiding a new process running shellcode.

Not sure it adds much value compared to just migrating into an existing process, was more of an exercise for learning C++ and playing with the Windows APIs.

## What's it do?

It will create an instance of the given process and set that process' parent to that of the ID passed in, helping hide the process.

It will then inject some shellcode (hard coded so change before compiling) into that process, using a few different methods.

## Usage

`Ridgway.exe <process path> <parentProcessId> [injectMethod]`

**injectMethod** is an optional parameter of one of the follwing:

* `1`: uses `CreateRemoteThread` (default)
* `2`: WIP

### Example

`Ridgway.exe C:\Windows\syswow64\notepad.exe 1337`

## Cobalt Strike

There's an aggressor script **artifact.cna** which can be loaded into Cobalt Strike so that the generated Windows Executables use this executable.
Note you need to keep the default shellcode of 'A's, and may need to change the path to the **encoded_payload.sh** script in the artifact.cna.

## Name

For those interested it's named after Stan Ridgway, who sang [this belter](https://www.youtube.com/watch?v=VgRXdozljRs), as that's exactly what we're trying to do here.

## TODO

* [ ] Check 32/64 processes
* [ ] Support compiling to 32 bit?
* [ ] Do proper process hollowing
* [ ] Check 32/64 bit payloads for CS
* [ ] Tidy up aggressor script & don't rely on msfvenom.