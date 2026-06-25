option(ENABLE_SANITIZERS "Enable ASAN and UBSAN for debugging" OFF)

function(set_security_flags target)
    get_target_property(_type ${target} TYPE)

    # -fPIC for libraries, -fPIE for executables.
    if(_type STREQUAL "EXECUTABLE")
        set(_pie_flag -fPIE)
    else()
        set(_pie_flag -fPIC)
    endif()

    target_compile_options(${target} PRIVATE
        ${_pie_flag}
        -fstack-protector-strong
        # -D_FORTIFY_SOURCE=3 requires glibc >= 2.35 and optimisation enabled;
        # use =2 as the portable baseline. _FORTIFY_SOURCE has no effect without
        # at least -O1, so guard it to non-Debug configurations only.
        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>
        -D_GLIBCXX_ASSERTIONS
        # -fstack-clash-protection: GCC and Clang >= 11 on Linux/x86; not
        # supported on Apple Clang before Xcode 15 or on ARM macOS.
        $<$<AND:$<NOT:$<PLATFORM_ID:Darwin>>,$<OR:$<CXX_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:Clang>>>:-fstack-clash-protection>
    )

    # Linker hardening: apply only to executables.
    # -Wl,-z,* are GNU ld / lld-on-Linux flags; they are unknown to Apple ld64.
    if(_type STREQUAL "EXECUTABLE")
        if(APPLE)
            target_link_options(${target} PRIVATE
                # BIND_NOW equivalent on Mach-O: resolve all symbols at load.
                -Wl,-bind_at_load
                # PIE: required for ASLR participation on macOS.
                -Wl,-pie
            )
        else()
            # Linux/GNU: full RELRO + BIND_NOW + NX stack + PIE.
            target_link_options(${target} PRIVATE
                -pie
                -Wl,-z,relro
                -Wl,-z,now
                -Wl,-z,noexecstack
            )
        endif()
    endif()

    # Sanitizers: debug builds only. Guard with a real CMake boolean, not a
    # generator expression inside if() (which always evaluates truthy as a
    # non-empty string).
    if(ENABLE_SANITIZERS)
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>
            $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
        )
        target_link_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        )
    endif()
endfunction()
