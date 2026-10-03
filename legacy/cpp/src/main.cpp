#include "rnetch/rnetch.h"
#include "tinyxml2.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h> // For MultiByteToWideChar

// Helper function to convert UTF-8 string to wstring, as required by the driver
std::wstring to_wstring(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

struct AppConfig {
    std::string socks5_host;
    std::string socks5_port;
    std::string socks5_user;
    std::string socks5_pass;
    std::vector<rnetch::Rule> rules;
};

std::string trim_copy(const std::string& input) {
    auto begin = std::find_if_not(input.begin(), input.end(), [](unsigned char ch) { return std::isspace(ch); });
    auto end = std::find_if_not(input.rbegin(), input.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
    if (begin >= end) {
        return {};
    }
    return std::string(begin, end);
}

void add_process_names(const std::string& names, std::vector<std::wstring>& target) {
    std::stringstream ss(names);
    std::string name;
    while (std::getline(ss, name, ',')) {
        auto trimmed = trim_copy(name);
        if (!trimmed.empty()) {
            target.push_back(to_wstring(trimmed));
        }
    }
}

bool load_config_from_xml(const std::string& path, AppConfig& config) {
    tinyxml2::XMLDocument doc;
    const auto load_result = doc.LoadFile(path.c_str());
    if (load_result != tinyxml2::XML_SUCCESS) {
        std::cerr << "Failed to load config file " << path << ": " << doc.ErrorStr() << std::endl;
        return false;
    }

    auto* root = doc.FirstChildElement("config");
    if (!root) {
        std::cerr << "Missing <config> root element in " << path << std::endl;
        return false;
    }

    auto* socks5_elem = root->FirstChildElement("socks5");
    if (!socks5_elem) {
        std::cerr << "Missing <socks5> element in " << path << std::endl;
        return false;
    }

    const char* host = socks5_elem->Attribute("host");
    const char* port = socks5_elem->Attribute("port");
    const char* user = socks5_elem->Attribute("user");
    const char* pass = socks5_elem->Attribute("pass");

    if (!host || !port) {
        std::cerr << "Attributes 'host' and 'port' are required on <socks5>." << std::endl;
        return false;
    }

    config.socks5_host = host;
    config.socks5_port = port;
    config.socks5_user = user ? user : "";
    config.socks5_pass = pass ? pass : "";

    auto* rules_elem = root->FirstChildElement("rules");
    if (!rules_elem) {
        std::cerr << "Missing <rules> element in " << path << std::endl;
        return false;
    }

    for (auto* rule_elem = rules_elem->FirstChildElement("rule"); rule_elem; rule_elem = rule_elem->NextSiblingElement("rule")) {
        rnetch::Rule rule{};
        const char* names_attr = rule_elem->Attribute("names");
        const char* name_attr = rule_elem->Attribute("name");

        std::string names_value;
        if (names_attr && *names_attr) {
            names_value = names_attr;
        } else if (name_attr && *name_attr) {
            names_value = name_attr;
        }

        add_process_names(names_value, rule.process_names);
        if (rule.process_names.empty()) {
            std::cerr << "Skipping <rule> with no process name." << std::endl;
            continue;
        }

        rule.accelerate_tcp = rule_elem->BoolAttribute("tcp", false);
        rule.accelerate_udp = rule_elem->BoolAttribute("udp", false);
        config.rules.push_back(std::move(rule));
    }

    if (config.rules.empty()) {
        std::cerr << "No valid <rule> entries found in " << path << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    AppConfig config;
    std::string config_path = "config.xml";

    // Allow overriding config path via first argument
    if (argc > 1 && argv[1]) {
        config_path = argv[1];
    }

    if (!load_config_from_xml(config_path, config)) {
        return 1;
    }

    if (!rnetch::start(config.socks5_host, config.socks5_port, config.socks5_user, config.socks5_pass, config.rules)) {
        return 1;
    }

    // Keep the application running
    std::cout << "Rnetch started with " << config.rules.size() << " rules (loaded from " << config_path << ")." << std::endl;
    std::cout << "Press Enter to stop rnetch..." << std::endl;
    rnetch::wait_for_stop();

    // Stop rnetch
    rnetch::stop();

    return 0;
}
