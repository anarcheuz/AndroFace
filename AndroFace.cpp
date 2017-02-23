/*
	Author: @anarcheuz
	script to find kernel attack surface on Android, superSU must be present on device !
*/

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <iostream>
#include <map>
#include <tuple>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>
#include <iomanip>

#include <memory>


#define XATTR_NAME_SELINUX "security.selinux"

typedef char * security_context_t;

static const char *su_path = "/su/bin/su";
static const char *su_switch = "-c";

using namespace std;

static vector<string> visitedDirectory;

// [TYPE] 1700: shell (ENFORCING) [mlstrustedsubject newAttr6 newAttr4]
static vector<tuple<int, string, string, string>> types;
// [AV] 1266: ALLOW felica_app-->fimg2d_video_device (chr_file) [write ioctl read open]
static vector<tuple<int, string, string, string, string, string>> av;

#define MAX_FILES (2 << 15)

struct File {
	char path[256];
	uid_t owner;
	gid_t group;
	char perms[10];
	char real_perms[4];
	char tag[32];
	char secontext[128];
};

File *files;

void exec(const char *cmd, char **argv, string &output) {
	int status, len, pipefd[2];
	pid_t child;
	char buffer[4096];

	pipe(pipefd);

	if((child = fork()) == 0) {
		close(pipefd[0]); //close reading end in child
		
		dup2(pipefd[1], 1); // stdout
		dup2(pipefd[1], 2); // stderr

		close(pipefd[1]); // no longer needed

		execvp(cmd, argv);
		exit(2);
	} 

	else if(child == -1) {
		perror("fork");
		exit(1);
	} 

	else {
		close(pipefd[1]); // close writing end in parent

		while((len = read(pipefd[0], buffer, sizeof(buffer)-1)) > 0) {
			buffer[len] = '\0';
			output += buffer;
		}

		waitpid(child, &status, __WALL);
		close(pipefd[0]);
	}
}

int isLink(struct stat &sb){
	return S_ISLNK(sb.st_mode);
}

int isDir(struct stat &sb){
	return S_ISDIR(sb.st_mode);
}


int getfilecon(const char *path, security_context_t *context) {
	ssize_t size, ret;
	char *buf;

	size = getxattr(path, XATTR_NAME_SELINUX, NULL, 0);
	if(size < 0) {
		perror("getxattr");
		exit(1);
	}

	buf = static_cast<char*>(malloc(++size));
	if(!buf) {
		perror("malloc");
		exit(1);
	}

	ret = getxattr(path, XATTR_NAME_SELINUX, buf, size - 1);
	if(ret < 0) {
		perror("getxattr2");
		free(buf);
		exit(1);
	}

	*context = buf;
	return size;
}

void get_perms(struct stat &sb, File *curFile) {
	string perms;

	perms += (sb.st_mode & S_IRUSR) ? "r" : "-";
	perms += (sb.st_mode & S_IWUSR) ? "w" : "-";
	perms += (sb.st_mode & S_IXUSR) ? "x" : "-";
	perms += (sb.st_mode & S_IRGRP) ? "r" : "-";
	perms += (sb.st_mode & S_IWGRP) ? "w" : "-";
	perms += (sb.st_mode & S_IXGRP) ? "x" : "-";
	perms += (sb.st_mode & S_IROTH) ? "r" : "-";
	perms += (sb.st_mode & S_IWOTH) ? "w" : "-";
	perms += (sb.st_mode & S_IXOTH) ? "x" : "-";

	memcpy(curFile->perms, perms.c_str(), perms.size());
}

void dump_av() {
	string output;
	const char *args[] = {su_path, su_switch, "supolicy --dumpav", nullptr};

	exec(su_path, (char **)args, output);

	istringstream f(output);
    string line;  
    regex typ_r{"\\[TYPE\\]\\s(\\d+):\\s(.*)\\s\\((.*)\\)\\s\\[(.*)\\].*"};
    regex av_r{"\\[AV\\]\\s(\\d+):\\s([A-Z]+)\\s(.*)-->(.*)\\s\\((.*)\\)\\s\\[(.*)\\].*"};

    while (getline(f, line)) {
    	smatch match;
    	try {
    		if(regex_search(line, match, typ_r) && match.size() > 1)
    			types.push_back({stoi(match.str(1)), match.str(2), match.str(3), match.str(4)});
    		else if(regex_search(line, match, av_r) && match.size() > 1)
    			av.push_back({stoi(match.str(1)), match.str(2), match.str(3), match.str(4), match.str(5), match.str(6)});
    	} catch(regex_error &e) {
    		cerr << "Regex exception: " << e.what() << endl;
    	}   
    }
}

// some useless folder, can speed up lookup process
bool is_dir_allowed(const string path) {
	vector<string> blacklist{"/proc/irq/", "/proc/sys/", "/proc/device-tree/", "/sys/fs/selinux/", "/sys/devices/", "/sys/bus/", "/sys/class/", "/sys/kernel/"};
	regex procID_r{"^(/proc/\\d)(.*)"};

	for(auto &v : blacklist)
		if(path.find(v) != string::npos || regex_match(path, procID_r))
			return false;
	return true;
}

void check_acl(const string &path, string &acl) {
	acl += access(path.c_str(), F_OK | R_OK) == 0 ? "r" : "-";
	acl += access(path.c_str(), F_OK | W_OK) == 0 ? "w" : "-";
	acl += access(path.c_str(), F_OK | X_OK) == 0 ? "x" : "-";
}

vector<string> split(const string &source, char sep) {
	vector<string> res;
	istringstream f(source);
	string item;

	while(getline(f, item, sep))
		res.push_back(item);

	return res;
}

void get_subtags(vector<string> &subtags) {
	if(subtags.size() <= 0)
		return;

	for(auto &type: types) {
		if(get<1>(type).compare(subtags[0]) == 0 && get<2>(type).compare("ENFORCING") == 0) {
			stringstream ss{get<3>(type)};
			string item;

			while(getline(ss, item, ' ')) {
				if(find(subtags.begin(), subtags.end(), item) == subtags.end()) {
					subtags.insert(subtags.begin(), item);
					get_subtags(subtags);
				}
			}
		}
	}
}

void get_av(vector<string> &subtags, map<string, string> &permissions) {
	for(auto &vect: av) {	
		if(get<1>(vect).compare("ALLOW") == 0 && find(subtags.begin(), subtags.end(), get<2>(vect)) != subtags.end()) {
			permissions[get<3>(vect)] = get<4>(vect) + " [" + get<5>(vect) + "]";
		}
	}
}

void lookup_directory(const string &dir_path, int depth, map<string, string> permissions) {
	DIR *dirp;
	struct dirent *entry;  
	string file_path;

	// don't lookup too much in subdirectories, less probable to have device driver there ..
	if(++depth > 64) 
		return;

	visitedDirectory.push_back(dir_path);

	if ((dirp = opendir(dir_path.c_str())) != NULL)
	{
		while(entry = readdir(dirp)) {
			if(strncmp(entry->d_name, ".", 2) == 0)
				continue;
			else if(strncmp(entry->d_name, "..", 3) == 0)
				continue;
			
			file_path = dir_path + "/" + entry->d_name;
			struct stat sb;
	
			if(lstat(file_path.c_str(), &sb) == -1) {
				perror("lstat");
				exit(1);
			}

			// don't follow symbolic links
			if(isLink(sb))
				continue;

			if(isDir(sb)) { 
				if(is_dir_allowed(file_path) && find(visitedDirectory.begin(), visitedDirectory.end(), file_path) == visitedDirectory.end())
					lookup_directory(file_path, depth, permissions);
				continue;
			}

			int *pos = (int *)files;
			File *curFile = &files[*pos];

			// First get selinux context and if not in reachable, we skip
			security_context_t context;
			int size = getfilecon(file_path.c_str(), &context);
			string context_ = context;
			free(context);

			vector<string> context_vec = split(context_, ':');

			bool accessible = false;
			for(auto &perm: permissions) {
				if(perm.first.compare(context_vec[2]) == 0) {
					memcpy(curFile->secontext, perm.second.c_str(), perm.second.size());
					accessible = true;
					break;
				}
			}

			if(!accessible)
				continue;

			memcpy(curFile->tag, context_vec[2].c_str(), context_vec[2].size());

			// get normal info and perms

			memcpy(curFile->path, file_path.c_str(), file_path.size());
			curFile->owner = sb.st_uid;
			curFile->group = sb.st_gid;

			get_perms(sb, curFile);

			// inc offset
			++(*pos);
			if(*pos > MAX_FILES) {
				cerr << "mmap overflow: " << *pos << " > " << MAX_FILES / sizeof(struct File) << endl;
				exit(-1);
			}

		}

		closedir(dirp);
	}
	else {
		perror("opendir");
		exit(-1);
	}
}

void get_attack_surface(vector<string> subtags) {
	vector<string> folders{"/dev", "/proc", "/sys"};
	map<string, string> permissions;

	cout << "[..] Processing access vectors" << endl;

	dump_av();
	get_subtags(subtags);
	get_av(subtags, permissions);

	for(auto &folder: folders) {
		int depth{0};

		cout << "[..] Fetching from: " << folder << endl;

		lookup_directory(folder, depth, permissions);
	}
}

void show_attack_surface() {
	int pos = *(int *)files;

	cout << "[+] Results: " << endl << endl;
	
	for(int i = 1; i < pos; ++i) {
		string acl;
		File *curFile = &files[i];

		check_acl(curFile->path, acl);

		if(acl == "---") // no read access means not reachable
			continue;

		memcpy(curFile->real_perms, acl.c_str(), acl.size());

		cout << curFile->path << endl;
		cout << "\t" << curFile->owner << "\t" << curFile->group << "\t" << curFile->perms << "\t" << curFile->real_perms;
		cout << "\t" << curFile->tag << "\t" << curFile->secontext << endl;
	}
}

void get_reachable_from(const string &path) {
	dump_av();

	security_context_t context;
	int size = getfilecon(path.c_str(), &context);
	string context_ = context;
	free(context);

	vector<string> context_vec = split(context_, ':');
	string tag = context_vec[2];

	cout << "Reachable from these contexts: " << endl << endl;
	for(auto &vect: av) {
		if(get<3>(vect).compare(tag) == 0) {
			string from = get<2>(vect);
			string ops = get<5>(vect);
			vector<string> subtags{from};

			get_subtags(subtags);
			for(auto &sub: subtags) {
				cout << sub << " ";
			}
			cout << "\t[" << ops << "]" << endl;
		}
	}
}


void help(char *argv[]) {
	cout << "Usage: " << argv[0] << " <find|rfind> <tag|path>" << endl << endl;
	cout << "find\t" << "find all accessible device driver from tag" << endl;
	cout << "rfind\t" << "find all context tag who can access the device driver at path" << endl;
}

/*
	if device is not root, try to acquire root and fork a new instance
	that can use dumpav
*/
int main(int argc, char *argv[]) {
	string acl, output;
	const char *args[] = {"/system/bin/id", nullptr};

	files = (struct File *) mmap(nullptr, sizeof(struct File) * MAX_FILES, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(files == (struct File *)-1) {
		perror("mmap");
		return -1;
	}
	*(int *)files = 1;

	int fd = open("/data/local/tmp/AndroFace_tmp", O_CREAT | O_RDWR, 0666);
	if(fd == -1) {
		perror("open");
		return -1;
	}

	exec("/system/bin/id", (char **)args, output);
	
	if(output.find("uid=0(root)") == string::npos) {
		cout << "[.] Try to get root privilege.." << endl;

		check_acl(su_path, acl);

		if(acl.find("r") == string::npos && acl.find("x") == string::npos) {
			cout << "[-] Need superSU to work !" << endl;
			return -1;
		}

		pid_t child;
		if((child = fork()) == -1) {
			perror("fork");
			return -1;
		} else if(child == 0) {
			char **args2 = (char **) malloc(sizeof(char *) *(argc + 3));
			
			args2[0] = (char *)su_path;
			args2[1] = (char *)su_switch;
			for(auto i = 2; i < argc + 2; ++i)
				args2[i] = argv[i-2];

			args2[argc + 2] = nullptr;

			execvp("/su/bin/su", args2);
			perror("execv");
			return -1;
		} else {
			waitpid(child, nullptr, __WALL);

			read(fd, files, sizeof(struct File) * MAX_FILES);
			close(fd);
			remove("/data/local/tmp/AndroFace_tmp");

			cout << "[.] data loaded" << endl;

			// parent will get real acl now since it has local user privilege
			if(*(int *)files > 1) // if pos is still 1 == no element has been found or we called get_reachable_from
				show_attack_surface();
			return 0;
		}
	}

	cout << "[+] root privilege acquired" << endl;

	if(argc > 2 && strcmp(argv[1], "find") == 0) {
		vector<string> subtags{argv[2]};
		get_attack_surface(subtags);
	}
	else if(argc > 2 && strcmp(argv[1], "rfind") == 0)
		get_reachable_from(argv[2]);
	else
		help(argv);

	write(fd, files, sizeof(struct File) * MAX_FILES);
	close(fd);
	cout << "[.] Child task over" << endl;

	return 0;
}

