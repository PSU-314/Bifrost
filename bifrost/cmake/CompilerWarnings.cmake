# Shared compiler warning flags for Bifrost targets.
# Provides set_project_warnings(<target>), applied to every library,
# executable, and test target so the whole codebase is held to the same
# strictness (conversions, shadowing, format-string, and cast warnings).

function(set_project_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wformat=2
        -Wundef
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Woverloaded-virtual
    )
endfunction()
