#ifndef INI_PARSER_H_
#define INI_PARSER_H_

#include <stdio.h>
#include <list>
#include <map>
#include <string>
#include <vector>
#include "qh_thread/locker.hpp"
#include "utils/file_utils.h"

class INIParser {
   public:
    // inner class ININode
    class ININode {
       public:
        ININode(const std::string& r, const std::string& k,
                const std::string& v)
            : root(r), key(k), value(v) {}
        std::string root;
        std::string key;
        std::string value;
    };
    // inner class SubNode
    class SubNode {
       public:
        void InsertElement(const std::string& key, const std::string& value) {
            sub_node.insert(make_pair(key, value));
        }
        void CopyElement(std::map<std::string, std::string>& kv_map) {
            std::map<std::string, std::string> kv_copy(sub_node);
            kv_copy.swap(kv_map);
        }
        std::map<std::string, std::string> sub_node;
    };
    // inner class iniprocesslock
    class CINIProcessLock : public QH_THREAD::CFileLock {
      public:
        CINIProcessLock()
            : m_inited_(false) {
        }
        bool Init(const std::string& path) {
            if (m_inited_ == true) {
                return true;
            }
            m_inited_ = true;
            std::string str_base_name = file_utils::GetBaseName(path);
            str_base_name = "." + str_base_name + "_lock";
            std::string str_parent_dir = file_utils::GetParentDir(path);
            std::string str_lock_file_path = str_parent_dir + "/" + str_base_name;
            if (!create(str_lock_file_path.c_str())) {
                printf("create config process lock error.\n");
            }
            return true;
        }
      private:
        volatile bool m_inited_;
    };
    /** member of class INIParser */
   private:
    std::string& TrimString(std::string& str);

   public:
    int ReadINI(const std::string& path);
    std::string GetValue(const std::string& root, const std::string& key);
    void GetKeyValue(const std::string& root,
                     std::map<std::string, std::string>& kv_map);
    std::list<std::string> GetRootList() { return m_rootlist_; }
    std::vector<ININode>::size_type GetSize() { return m_map_ini_.size(); }
    std::vector<ININode>::size_type SetValue(const std::string& root,
                                             const std::string& key,
                                             const std::string& value);
    int WriteINI(const std::string& path);
    void Clear() {
        m_map_ini_.clear();
        m_rootlist_.clear();
    }

   private:
    std::map<std::string, SubNode> m_map_ini_;
    std::list<std::string> m_rootlist_;
};

#endif  /* INI_PARSER_H_ */
