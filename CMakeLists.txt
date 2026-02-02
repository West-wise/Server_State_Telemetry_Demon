cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 및 버전 설정
project(SST_Demon VERSION 1.0.0 LANGUAGES CXX)

# C++17 표준 사용 설정
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 컴파일러별 경고 옵션 설정
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -O2)
endif()

# 포함 디렉토리 설정
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib
)


# 소스 파일 설정
set(SOURCES
    main.cpp
    src/TcpServer.cpp
    src/SystemReader.cpp
    src/PacketUtil.cpp
    lib/sha256.cpp
)

# 실행 파일 생성
add_executable(${PROJECT_NAME} ${SOURCES})

# 스레드 라이브러리 링크
find_package(Threads REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)