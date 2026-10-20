@echo off
rem Builds build\pulse_mcp_native\PulseMCP.exe (needs VS Build Tools with MSVC, and Node).
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (echo Visual Studio Build Tools with MSVC not found. & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "OUT=%~dp0..\..\build\pulse_mcp_native"
cmake -S "%~dp0." -B "%OUT%" -G Ninja -DCMAKE_BUILD_TYPE=Release || exit /b 1
cmake --build "%OUT%" || exit /b 1
"%OUT%\PulseMCP.exe" --self-test
