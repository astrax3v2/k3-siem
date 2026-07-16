cmake_minimum_required(VERSION 3.16)
project(k3-agent-cpp CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)

set(SOURCES
  src/main.cpp
  src/config.cpp
  src/siem_client.cpp
)

if(WIN32)
  list(APPEND SOURCES src/collectors/windows.cpp)
elseif(APPLE)
  list(APPEND SOURCES src/collectors/macos.cpp)
else()
  list(APPEND SOURCES src/collectors/linux.cpp)
endif()

add_executable(k3-agent ${SOURCES})
target_include_directories(k3-agent PRIVATE src vendor)
target_link_libraries(k3-agent PRIVATE CURL::libcurl)

if(WIN32)
  # Event Log (wevtapi), registry enumeration (advapi32), Windows Update Agent COM (wuapi via
  # #import, no extra lib needed beyond ole32/oleaut32 for the COM plumbing it generates).
  target_link_libraries(k3-agent PRIVATE wevtapi advapi32 ole32 oleaut32 ws2_32)
elseif(NOT APPLE)
  find_library(SYSTEMD_LIB systemd)
  if(SYSTEMD_LIB)
    target_compile_definitions(k3-agent PRIVATE K3_HAVE_LIBSYSTEMD=1)
    target_link_libraries(k3-agent PRIVATE ${SYSTEMD_LIB})
  endif()
  target_link_libraries(k3-agent PRIVATE pthread)
endif()

install(TARGETS k3-agent RUNTIME DESTINATION bin)
