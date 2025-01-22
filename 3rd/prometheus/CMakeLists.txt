project(prometheus)
cmake_minimum_required(VERSION 3.22)
add_library(${PROJECT_NAME}
  src/check_names.cc
  src/counter.cc
  src/detail/builder.cc
  src/detail/ckms_quantiles.cc
  src/detail/time_window_quantiles.cc
  src/detail/utils.cc
  src/family.cc
  src/gauge.cc
  src/histogram.cc
  src/registry.cc
  src/serializer.cc
  src/summary.cc
  src/text_serializer.cc
)
if(HAVE_CXX_LIBATOMIC)
  # the exported library config must use libatomic unconditionally
  # (the HAVE_CXX_LIBATOMIC variable should not leak into the target config)
  target_link_libraries(${PROJECT_NAME} PUBLIC atomic)
endif()
set(INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/inc")

target_include_directories(${PROJECT_NAME} PUBLIC ${INC_DIR})
set_target_properties(${PROJECT_NAME}
  PROPERTIES
    OUTPUT_NAME ${PROJECT_NAME}
    DEFINE_SYMBOL PROMETHEUS_CPP_CORE_EXPORTS
    # VERSION "${PROJECT_VERSION}"
    # SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
)
#固定句式
#全局变量传递库名给主项目(其他三方库同样使用)
set(3RD_LIBS ${3RD_LIBS}  ${PROJECT_NAME} PARENT_SCOPE)
set(3RD_INC_DIRS ${3RD_INC_DIRS}  ${INC_DIR} PARENT_SCOPE)

