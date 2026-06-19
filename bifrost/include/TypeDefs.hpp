#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>
namespace fs = std::filesystem;

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

#define DEFAULT_KEYFILE "totp-secrets.keys"

class Paths {
    private:
        static std::string _keyfile;

    public:
        static void init() {
            auto cnfgdir = configDir();
            if (!fs::exists(cnfgdir))
                fs::create_directories(cnfgdir);
            _keyfile = DEFAULT_KEYFILE;
        }

        static fs::path homeDir() { return fs::path(std::getenv("HOME")); }
        static fs::path configDir() { return homeDir() / ".config/bifrost"; }

        static void setKeyfile(const std::string &file) { _keyfile = file; }
        static fs::path keyfile() { return configDir() / _keyfile; }
};
