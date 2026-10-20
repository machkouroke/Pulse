# PulseMCP (native)

MCP server (stdio) that reads Windows diagnostics with **PulseService's own collectors**, compiled in. No Pulse install, service or pipe needed.

```
Claude ──stdio──► PulseMCP.exe ──► Windows (Event Log, PDH, SetupAPI, SMBIOS…)
                  └ service/pulse_service/src collectors + Pulse's event explanations
```

## Tools

| Tool | What |
|------|------|
| `timeline_search` | Event Log search (time, severity, provider, Event ID, keyword, channels) with Pulse's title/summary/recommendation; crashes and wakes explained. `group: true` counts per provider + Event ID |
| `timeline_event` | One record with raw XML (EventData) |
| `read_evtx` | Exported `.evtx` file |
| `system_health` | CPU, memory, GPUs, disks (SMART/NVMe), volumes, network, top processes, hardware info |
| `process_list` / `process_details` | Task Manager–style processes; command-line secrets redacted |
| `inventory` | services, drivers, software, usb, pci, displays, audio, bluetooth, printers, battery, motherboard, bios, cpu, memory_modules, storage, network_adapters |
| `status` | Readable channels, elevation, network ETW state |

## Build

Needs VS 2022 Build Tools (MSVC, Windows SDK, CMake, Ninja) and Node (generates JSON serializers from `pulse_wire.hpp` at build time). `build.cmd` finds Visual Studio itself, builds Release and runs the self-test:

```bash
apps\pulse_mcp_native\build.cmd
claude mcp add --scope user pulse-mcp -- "<repo>/build/pulse_mcp_native/PulseMCP.exe"
```

## Rights

Runs as the user who starts the MCP client (Pulse's own service runs as LocalService). As a standard user everything works except:

- **Security log**: access denied. *Event Log Readers* (S-1-5-32-573) grants it.
- **Per-app network**: Kernel-Network ETW is denied (`win32=5`); the TCPIP fallback session runs but attributes no bytes to processes. Needs admin, or possibly *Performance Log Users* (S-1-5-32-559).

Add groups from an elevated PowerShell (`Add-LocalGroupMember -SID S-1-5-32-573 -Member "$env:USERDOMAIN\$env:USERNAME"`), then sign out and back in. `status` reports what is actually readable (`channels`, `per_app_network`).

Uses its own ETW session (`PulseMcpNet`): the collector stops any session with its name before starting, so sharing PulseService's `PulseHealthNet` would cut Pulse's network tracing.
