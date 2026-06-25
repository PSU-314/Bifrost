option(ENABLE_SANITIZERS "Enable ASAN and UBSAN for debugging" OFF)

function(set_security_flags target)
    # Compile-time Hardening
    target_compile_options(${target} PRIVATE
        -fPIE
        -fstack-protector-strong
        -fstack-clash-protection
        $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>
        -D_GLIBCXX_ASSERTIONS
    )

    # Link-time Hardening (RELRO, NOW, NoExecStack)
    target_link_options(${target} PRIVATE
        -pie
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
    )

    # Sanitizers (For Debugging/CI only, never in Release)
    if(ENABLE_SANITIZERS AND $<CONFIG:Debug>)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()
