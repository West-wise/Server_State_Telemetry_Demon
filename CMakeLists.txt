cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 및 버전 설정
project(SSTD VERSION 1.0.0 LANGUAGES CXX)

# C++17 표준 사용 설정
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 컴파일러별 경고 옵션 설정
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -Os)
endif()

# 아키텍쳐별 libsodium 라이브러리 설정
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(SODIUM_LIB_PATH ${CMAKE_SOURCE_DIR}/lib/libsodium/aarch64/lib/libsodium.a)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(SODIUM_LIB_PATH ${CMAKE_SOURCE_DIR}/lib/libsodium/x86_64/lib/libsodium.a)
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "libsodium path: ${SODIUM_LIB_PATH}")

# 포함 디렉토리 설정
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib
    ${CMAKE_SOURCE_DIR}/lib/libsodium/include
    ${CMAKE_SOURCE_DIR}/lib/spdlog/include
)


# 소스 파일 설정
set(SOURCES
    main.cpp
    src/TcpServer.cpp
    src/qrcodegen.cpp
    src/SystemReader.cpp
    src/PacketUtil.cpp
    src/NoiseSession.cpp
    src/Config.cpp
    src/utility.cpp
)

# 실행 파일 생성
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_options(${PROJECT_NAME} PRIVATE
    -Wl,--gc-sections
    -s
)
set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)

# 라이브러리 링크(스레드, libsodium)
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    Threads::Threads
    ${SODIUM_LIB_PATH}
)
