# shared/CMakeLists.txt

file(GLOB SHARED_SOURCES
    *.cpp
    *.h
)

# Find OpenSSL for CryptoHelper (AES-256-GCM encryption)
find_package(OpenSSL REQUIRED)

# Create the library with the same name used everywhere
add_library(animo_shared STATIC
    ${SHARED_SOURCES}
)

# Link against Qt6 components needed by shared code
target_link_libraries(animo_shared
    PUBLIC Qt6::Core Qt6::Widgets Qt6::Sql Qt6::Network
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
)

# Make headers available to client and server
target_include_directories(animo_shared
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)
