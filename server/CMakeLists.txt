# server/CMakeLists.txt

# If you don't already have this at a higher level, make sure Qt SQL is found
# (safe to call again; CMake will de-duplicate)
find_package(Qt6 REQUIRED COMPONENTS Core Network Sql)

set(SERVER_SRC
    main.cpp
    Server.cpp
    Server.h
    ${CMAKE_SOURCE_DIR}/server/SessionDBManager.cpp   # <- add this
    resources.qrc   # Qt resources (embedded PowerShell scripts)
)

add_executable(AnimoServer ${SERVER_SRC})

target_include_directories(AnimoServer PRIVATE
    ${CMAKE_SOURCE_DIR}/shared
)

target_link_libraries(AnimoServer
    Qt6::Core
    Qt6::Network
    Qt6::Sql
    animo_shared
)

# NOTE:
# If you later add SessionDBManager.cpp to the animo_shared library,
# remove it from SERVER_SRC to avoid duplicate symbols.
