#include <DiffieHellman.hpp>
#include <Random.hpp>
#include <TypeDefs.hpp>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <sstream>
#include <utility.hpp>

using json = nlohmann::json;

num_t generatePrivateSecret() {
    return Random::generatePrimeNum(PRIVATE_SECRET_LENGTH);
}

num_t generateSharedSecret(const std::string &serverRegCode) {
    num_t privateKey = generatePrivateSecret();
    num_t pubKey = powMod(DH_GEN, privateKey, DH_PRIME);

    num_t serverPublicKey = getServerPublicKey(pubKey, serverRegCode);

    return powMod(serverPublicKey, privateKey, DH_PRIME);
}

num_t getServerPublicKey(const num_t &pubKey,
                         const std::string &serverRegCode) {
    std::string pubKeyStr = BytesToHex(numToBytes(pubKey));
    json payload = {{"bifrost-public-key", pubKeyStr}};

    cpr::Response r = cpr::Post(
        cpr::Url{SERVER_URL + serverRegCode}, cpr::Body{payload.dump()},
        cpr::Header{{"Content-Type", "application/json"}});

    num_t serverkey;
    if (r.status_code == 200 || r.status_code == 201) {
        try {
            json response_data = json::parse(r.text);

            if (response_data.contains("server-public-key")) {
                serverkey = num_t(
                    "0x" + std::string(response_data["server-public-key"]));
                std::cout << "Successfully extracted server public key: "
                          << serverkey << std::endl;
            } else {
                std::cerr
                    << "Required fields not found in response. Raw response:\n"
                    << response_data.dump(4) << std::endl;
                return -1;
            }

        } catch (const json::parse_error &e) {
            std::cerr << "Failed to parse API response as JSON: " << e.what()
                      << std::endl;
            return -1;
        }
    } else {
        std::cerr << "HTTP Error occurred!" << std::endl;
        std::cerr << "Status Code: " << r.status_code << std::endl;
        std::cerr << "Error Message: " << r.error.message << std::endl;
        return -1;
    }
    return serverkey;
}
