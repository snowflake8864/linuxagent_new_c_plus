
#ifndef PID_FILE_H_
#define PID_FILE_H_

#include <string>

namespace pid_file {

bool write_pid_file(const char* file_name);
bool delete_pid_file(const char* file_name);
bool read_pid_file(const char* file_name, std::string& pid);

} // namespace

#endif /* PID_FILE_H_ */
