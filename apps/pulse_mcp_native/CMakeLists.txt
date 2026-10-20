cmake_minimum_required(VERSION 3.25)
project(PulseMCP VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(PULSE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(SVC "${PULSE_ROOT}/service/pulse_service/src")
set(WIRE "${PULSE_ROOT}/shared/pulse_protocol/cpp")

# JSON serializers generated from the wire structs (stays in sync with upstream).
find_program(NODE_EXE node REQUIRED)
set(WIRE_JSON "${CMAKE_CURRENT_BINARY_DIR}/generated/wire_json.hpp")
add_custom_command(
  OUTPUT "${WIRE_JSON}"
  COMMAND "${NODE_EXE}" "${CMAKE_CURRENT_SOURCE_DIR}/gen_wire_json.mjs"
          "${WIRE}/pulse_wire.hpp" "${WIRE_JSON}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/gen_wire_json.mjs" "${WIRE}/pulse_wire.hpp"
)

# PulseService's collection code, without the service, pipe or config.
add_executable(PulseMCP
  main.cpp
  "${WIRE_JSON}"
  "${WIRE}/pulse_wire.cpp"
  "${SVC}/collectors/event_log_collector.cpp"
  "${SVC}/collectors/event_log_channels.cpp"
  "${SVC}/collectors/evtx_file_reader.cpp"
  "${SVC}/collectors/health_metrics_collector.cpp"
  "${SVC}/collectors/hardware_sensors_collector.cpp"
  "${SVC}/collectors/disk_health.cpp"
  "${SVC}/collectors/network_etw_engine.cpp"
  "${SVC}/collectors/gpu_adapter_info.cpp"
  "${SVC}/collectors/gpu_engine_load.cpp"
  "${SVC}/collectors/system_overview_info.cpp"
  "${SVC}/collectors/process_metrics.cpp"
  "${SVC}/ipc/event_mapper.cpp"
  "${SVC}/intelligence/event_intelligence.cpp"
  "${SVC}/intelligence/crash_explainer.cpp"
  "${SVC}/intelligence/wake_explainer.cpp"
  "${SVC}/intelligence/bugcheck_catalog.cpp"
  "${SVC}/inventory/inventory_engine.cpp"
  "${SVC}/inventory/services_collector.cpp"
  "${SVC}/inventory/drivers_collector.cpp"
  "${SVC}/inventory/software_collector.cpp"
  "${SVC}/inventory/usb_collector.cpp"
  "${SVC}/inventory/pci_collector.cpp"
  "${SVC}/inventory/displays_collector.cpp"
  "${SVC}/inventory/audio_collector.cpp"
  "${SVC}/inventory/bluetooth_collector.cpp"
  "${SVC}/inventory/printers_collector.cpp"
  "${SVC}/inventory/battery_collector.cpp"
  "${SVC}/inventory/setupapi_device_enumerator.cpp"
  "${SVC}/inventory/smbios_table.cpp"
  "${SVC}/inventory/motherboard_collector.cpp"
  "${SVC}/inventory/bios_collector.cpp"
  "${SVC}/inventory/memory_modules_collector.cpp"
  "${SVC}/inventory/cpu_collector.cpp"
  "${SVC}/inventory/storage_collector.cpp"
  "${SVC}/inventory/network_adapters_collector.cpp"
  "${SVC}/windows/wevt_helpers.cpp"
  "${SVC}/logging/logger.cpp"
  "${SVC}/util/windows_edition.cpp"
)

target_include_directories(PulseMCP PRIVATE
  "${SVC}"
  "${WIRE}"
  "${PULSE_ROOT}/shared/pulse_common/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
  "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

# Own ETW session name: PulseService stops any session named like its own.
target_compile_definitions(PulseMCP PRIVATE PULSE_ETW_SESSION_NAME=PulseMcpNet)

target_link_libraries(PulseMCP PRIVATE
  advapi32 shell32 ole32 wevtapi pdh iphlpapi dxgi d3d12 gdi32 psapi version
  wlanapi setupapi cfgmgr32 winspool bcrypt
)
