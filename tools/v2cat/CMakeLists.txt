set(SOURCES main.cpp
            enrolment.cpp
            ctl.cpp
            helpers.cpp)

add_executable(v2cat ${SOURCES})

include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git
                         GIT_TAG 6ea2dec)
FetchContent_MakeAvailable(cpr)

target_link_libraries(v2cat PUBLIC Boost::system Boost::program_options Vanetza::asn1 Vanetza::security Vanetza::vanetza cpr::cpr)
set_target_properties(v2cat PROPERTIES INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS v2cat EXPORT ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
