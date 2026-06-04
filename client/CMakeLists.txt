# client/CMakeLists.txt

file(GLOB CLIENT_SOURCES
    *.cpp
    *.h
    *.ui
    network/*cpp
    network/*.h
)

add_executable(AnimoClient
    ${CLIENT_SOURCES}
)

target_link_libraries(AnimoClient
    PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Sql
        Qt6::WebEngineWidgets
        animo_shared   # <-- fixed name
)

target_include_directories(AnimoClient
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/shared
        ${CMAKE_CURRENT_SOURCE_DIR}/network
)

# Resources to embed (use RELATIVE paths!)
set(CLIENT_RSRC
    icons/appicon.png
    icons/azure_cloud.svg
    icons/users.png
    icons/groups.png
    icons/roles.png
    icons/context.png
    icons/shareicons/clip.png
    icons/shareicons/folder.png
    icons/shareicons/image.png
    icons/shareicons/pdf.png
    icons/shareicons/txt.png
    icons/shareicons/zip.png
)

# Qt 6: attach resources to the executable target
qt_add_resources(AnimoClient client_rcc
    PREFIX "/"
    FILES ${CLIENT_RSRC}
)
