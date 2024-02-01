
#ifndef ENTCLIENT_ENTCLIENT_PIDFILE_H
#define ENTCLIENT_ENTCLIENT_PIDFILE_H

class CPidFile
{
public:
	CPidFile(){}
	~CPidFile(){}

	static int write_pid_file(const char* file_name);
	static bool delete_pid_file(const char* file_name);
};

#endif /* ENTCLIENT_ENTCLIENT_PIDFILE_H */
