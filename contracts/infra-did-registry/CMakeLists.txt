add_contract(infra-did-registry infra-did-registry
        ${CMAKE_CURRENT_SOURCE_DIR}/src/infra-did-registry.cpp
)

target_include_directories(infra-did-registry
   PUBLIC
   ${CMAKE_CURRENT_SOURCE_DIR}/include
   ${CMAKE_CURRENT_SOURCE_DIR}/../include)

set_target_properties(infra-did-registry
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/ricardian/infra-did-registry.contracts.md.in ${CMAKE_CURRENT_BINARY_DIR}/ricardian/infra-did-registry.contracts.md @ONLY )

target_compile_options( infra-did-registry PUBLIC -R${CMAKE_CURRENT_SOURCE_DIR}/ricardian -R${CMAKE_CURRENT_BINARY_DIR}/ricardian )
