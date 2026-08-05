add_subdirectory(core)
add_subdirectory(cli)

if(CABRAL_BUILD_GUI)
    add_subdirectory(gui)
endif()
