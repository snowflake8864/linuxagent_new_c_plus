#include "ini_parser.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include "singleton.hpp"
#include "utils/string_utils.hpp"

using namespace std;

//remove before and after blank space
string& INIParser::TrimString(string &str) {
    return string_utils::Trim(str, " \r");
}

//read in INI file and parse it
int INIParser::ReadINI(const std::string& path) {
    Singleton<CINIProcessLock>::Instance().Init(path);
    QH_THREAD::CFileLockAutoLocker _filelocker(&Singleton<CINIProcessLock>::Instance());

    ifstream in_conf_file(path.c_str());
    if (!in_conf_file) return 0;
    string str_line = "";
    string str_root = "";
    vector<ININode> vec_ini;
    while (getline(in_conf_file, str_line)) {
        string::size_type left_pos = 0;
        string::size_type right_pos = 0;
        string::size_type equal_div_pos = 0;
        string str_key = "";
        string str_value = "";
        TrimString(str_line);
        if (str_line.length() == 0)
            continue;
        if (str_line.at(0) == '#' || str_line.at(0) == ';')
            continue;

        if (str_line.at(0) == '[') {
            if ((str_line.npos != (left_pos = str_line.find("[")))
                    && (str_line.npos != (right_pos = str_line.find("]")))
                    && (str_line.npos == str_line.find("=["))) {
                str_root = str_line.substr(left_pos+1, right_pos-1);
            }
        }
        if (str_line.npos != (equal_div_pos = str_line.find("=")) && equal_div_pos != str_line.size()-1) {
           str_key = str_line.substr(0, equal_div_pos);
           str_value = str_line.substr(equal_div_pos+1, str_line.size()-equal_div_pos);
           str_key = TrimString(str_key);
           str_value = TrimString(str_value);
           string_utils::ToUpper(str_key);
        }

        if ((!str_root.empty()) && (!str_key.empty()) && (!str_value.empty())) {
           string_utils::ToUpper(str_root);
           ININode ini_node(str_root, str_key, str_value);
           vec_ini.push_back(ini_node);
           if (std::find(m_rootlist_.begin(), m_rootlist_.end(), str_root) == m_rootlist_.end())
               m_rootlist_.push_back(str_root);
        }
    }
    in_conf_file.close();
    in_conf_file.clear();

    //vector convert to set
    set<string> set_tmp;
    for (vector<ININode>::iterator itr = vec_ini.begin(); itr != vec_ini.end(); ++itr) {
        set_tmp.insert(itr->root);
    }

    for (set<string>::iterator itr = set_tmp.begin(); itr != set_tmp.end(); ++itr) {
       SubNode sn;
       for (vector<ININode>::iterator sub_itr = vec_ini.begin(); sub_itr != vec_ini.end(); ++sub_itr) {
           if (sub_itr->root == (*itr))
               sn.InsertElement(sub_itr->key, sub_itr->value);
       }
       m_map_ini_.insert(make_pair((*itr), sn));
    }
    return 1;
}

//get value by root and key
string INIParser::GetValue(const string& root, const string& key) {
    std::string dstkey = key;
    std::string dstroot = root;
    string_utils::ToUpper(dstkey);
    string_utils::ToUpper(dstroot);
    QH_THREAD::CFileLockAutoLocker _filelocker(&Singleton<CINIProcessLock>::Instance());

    map<string, SubNode>::iterator itr = m_map_ini_.find(dstroot);
    if (itr == m_map_ini_.end())
        return "";
    map<string, string>::iterator sub_itr = itr->second.sub_node.find(dstkey);
    if (sub_itr == itr->second.sub_node.end())
        return "";
    if (!(sub_itr->second).empty())
        return sub_itr->second;
    return "";
}

void INIParser::GetKeyValue(const std::string& root, std::map<std::string, std::string>& kv_map) {
    std::string dstroot = root;
    string_utils::ToUpper(dstroot);
    map<string, SubNode>::iterator itr = m_map_ini_.find(dstroot);
    if (itr != m_map_ini_.end()) itr->second.CopyElement(kv_map);
}

//write ini file
int INIParser::WriteINI(const std::string& path) {
    QH_THREAD::CFileLockAutoLocker _filelocker(&Singleton<CINIProcessLock>::Instance());

    ofstream out_conf_file;
    std::string path_bak = path + "_bak";

    out_conf_file.open(path_bak.c_str(), ios::out | ios::binary | ios::trunc);

    if (!out_conf_file)
        return -1;

    for (list<string>::iterator it = m_rootlist_.begin(); it != m_rootlist_.end(); it++) {
        SubNode & sub = m_map_ini_[*it];
        out_conf_file << "[" << it->c_str() << "]" << "\n";
        for(map<string, string>::iterator sub_itr = sub.sub_node.begin(); sub_itr != sub.sub_node.end(); ++sub_itr) {
            out_conf_file << sub_itr->first << "=" << sub_itr->second << "\n";
        }
    }

    out_conf_file.close();
    out_conf_file.clear();
    if (0 != ::rename(path_bak.c_str(), path.c_str())) {
        return -1;
    }
    return 1;
}

//set value
vector<INIParser::ININode>::size_type INIParser::SetValue(const string& root, const string& key, const string& value) {
    std::string dstroot = root;
    std::string dstkey = key;
    string_utils::ToUpper(dstroot);
    string_utils::ToUpper(dstkey);
    QH_THREAD::CFileLockAutoLocker _sem(&Singleton<CINIProcessLock>::Instance());

    map<string, SubNode>::iterator itr = m_map_ini_.find(dstroot);
    if (m_map_ini_.end() != itr) {
        itr->second.sub_node[dstkey] = value;
    } else {
        SubNode sn;
        sn.InsertElement(dstkey, value);
        m_map_ini_.insert(make_pair(dstroot, sn));
        m_rootlist_.push_back(dstroot);
    }
    return m_map_ini_.size();
}
