cmake_minimum_required(VERSION 3.6)
project(ice LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(ENABLE_BOOST ON)

#固定句式
# 获取第三方目录下的所有子项目
set(3RD_LIBS "") #设置全局变量
set(3RD_INC_DIRS "") #设置全局变量
file(GLOB 3RD_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/3rd/*")
foreach(3RD_DIR IN LISTS 3RD_DIRS)
    get_filename_component(3RD_NAME ${3RD_DIR} NAME)
    add_subdirectory(${3RD_DIR})
endforeach()

if(ENABLE_BOOST)

find_package(Boost 1.74.0 REQUIRED COMPONENTS filesystem system)
if(Boost_FOUND)
    set(CMAKE_CXX_STANDARD 17) # boost 1.74.0 
    set(3RD_INC_DIRS  ${3RD_LIBS} ${Boost_INCLUDE_DIRS}) 
    set(3RD_LIBS ${3RD_LIBS} ${Boost_LIBRARIES})
else()
    message(STATUS  "NOT FOUND BOOST!")
endif()
endif()






file(GLOB SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
set(MAIN_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/inc)


#生成可执行文件
add_library(${CMAKE_PROJECT_NAME} ${SRC} )
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${MAIN_INC_DIR}
    ${3RD_INC_DIRS}
)
target_link_libraries(${CMAKE_PROJECT_NAME}  ${IMGUI_BACKEND_DEPENDS_LIBS} ${3RD_LIBS})

set (TEST_INC_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/test/  )
file(GLOB TEST_SRC ${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp)
foreach(TEST IN LISTS TEST_SRC)
    get_filename_component(TEST_NAME ${TEST} NAME_WE)
    add_executable(${TEST_NAME}  ${TEST} )
    target_include_directories(${TEST_NAME} PRIVATE  ${TEST_INC_DIRS} ${MAIN_INC_DIR} ${3RD_INC_DIRS})
    target_link_libraries(${TEST_NAME}  ${CMAKE_PROJECT_NAME}  ${IMGUI_BACKEND_DEPENDS_LIBS} ${3RD_LIBS})
endforeach()