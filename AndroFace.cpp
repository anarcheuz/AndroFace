#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>

#include <iostream>
#include <map>
#include <tuple>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>

#include <memory>

using namespace std;

// <file, <selinux context id, selinux permissions, ACL>>
static map<string, tuple<string, string, string>> validFiles;
static vector<string> visitedDirectory;

// [TYPE] 1700: shell (ENFORCING) [mlstrustedsubject newAttr6 newAttr4]
static vector<tuple<int, string, string, string>> types;
// [AV] 1266: ALLOW felica_app-->fimg2d_video_device (chr_file) [write ioctl read open]
static vector<tuple<int, string, string, string, string, string>> av;

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

void dump_av() {
	string output;
	const char *args[] = {"/su/bin/su", "-c", "supolicy --dumpav", nullptr};

	exec("/su/bin/su", (char **)args, output);

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
	regex procID_r{"^/proc/\\d+.*"};

	for(auto &v : blacklist)
		if(path.find(v) != string::npos || regex_match(path, procID_r))
			return false;
	return true;
}

void check_acl(const string &path, string &acl) {
	if(access(path.c_str(), F_OK | R_OK) == 0)
		acl += "r:";
	if(access(path.c_str(), F_OK | W_OK) == 0)
		acl += "w:";
	if(access(path.c_str(), F_OK | X_OK) == 0)
		acl += "x:";

	acl = acl.substr(0, acl.size()-1);
}

vector<string> split(const string &source, char sep) {
	vector<string> res;
	istringstream f(source);
	string item;

	while(getline(f, item, sep))
		res.push_back(item);

	return res;
}

vector<string> check_file_properties(const string &path) {
	vector<string> res;
	string acl{""};
	string output;
	const char *args[] = {"/system/bin/ls", "-lZa", path.c_str(), nullptr};

	check_acl(path, acl);
	res.push_back(acl);

	exec("/system/bin/ls", (char **)args, output);

	regex pattern_r{"([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)"};
	smatch match;

	try {
		if(regex_search(output, match, pattern_r) && match.size() == 6) {
			res.push_back(match.str(1)); // imprecise ACL
			res.push_back(match.str(2)); // owner
			res.push_back(match.str(3)); // group
			string tag = split(match.str(4), ':')[2];
			res.push_back(tag); // selinux context
			res.push_back(match.str(5)); // filename
		}
	} catch(regex_error &e) {
    	cerr << "Regex exception: " << e.what() << endl;
    }  

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

void get_av(vector<string> &subtags, map<string, vector<string>> &permissions) {
	for(auto &vect: av) {	
		if(get<1>(vect).compare("ALLOW") == 0 && find(subtags.begin(), subtags.end(), get<2>(vect)) != subtags.end()) {
			vector<string> perm{get<4>(vect), get<5>(vect)};
			permissions[get<3>(vect)] = perm;
		}
	}
}

void lookup_directory(const string &dir_path, vector<vector<string>> &result, int depth) {
	struct dirent *dir = nullptr;
	shared_ptr<DIR> d{opendir(dir_path.c_str()), closedir};

	// don't lookup too much in subdirectories, less probable to have device driver there ..
	if(++depth > 64) 
		return;

	if(d) {
		visitedDirectory.push_back(dir_path);

		while((dir = readdir(d.get())) != nullptr) {
			string filename = string{dir->d_name};
			string full_path;
			char *tmp = nullptr;

			if(filename.compare(".") == 0 || filename.compare("..") == 0)
				continue;

			full_path = dir_path + "/" + filename;

			// if is a symbolic link, resolve it, always work on absolute path
			if(dir->d_type == DT_LNK) {
				tmp = realpath(full_path.c_str(), nullptr);
				full_path = tmp;
				free(tmp);
			}


			// if is a directory
			if(dir->d_type == DT_DIR) {
				if(is_dir_allowed(full_path) 
					&& find(visitedDirectory.begin(), visitedDirectory.end(), full_path) == visitedDirectory.end()) 
					lookup_directory(full_path.c_str(), result, depth);
				continue;
			}

			vector<string> properties = check_file_properties(full_path);
			properties.insert(properties.begin(), full_path);
			result.push_back(properties);
		}
	} 
	else
		perror(dir_path.c_str());
}

void get_attack_surface(vector<string> subtags) {
	vector<string> folders{"/dev", "/proc", "/sys"};
	map<string, vector<string>> permissions;

	cout << "[..] Processing access vectors" << endl;

	dump_av();
	get_subtags(subtags);
	get_av(subtags, permissions);

	for(auto &folder: folders) {
		vector<vector<string>> files;
		int depth{0};

		cout << "[..] Fetching from: " << folder << endl << endl;
		
		lookup_directory(folder, files, depth);

		for(auto &file: files) {
			if(file[1].size() < 1) // we have no access on file...
				continue;
			for(auto &perm: permissions) {
				if(perm.first.compare(file.at(file.size()-2)) == 0) { // print selinux permissions on file and access rights
					cout << file[0] << "\t\t";
					cout << "current access rights: " << file[1] << "\t\t";
					cout << "general access rights: " << file[2] << "\t\t";
					cout << perm.second.at(0) << " [" << perm.second.at(1) << "]";
					cout << endl;
				}
			}
		}

		cout << endl << endl;
	}
}

void get_reachable_from(const string &path) {
	string tag;
	vector<string> tmp;
	dump_av();

	tmp = check_file_properties(path);
	tag = tmp.at(tmp.size()-2);

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

int main(int argc, char *argv[]) {

	if(argc > 2 && strcmp(argv[1], "find") == 0) {
		vector<string> subtags{argv[2]};
		get_attack_surface(subtags);
	}
	else if(argc > 2 && strcmp(argv[1], "rfind") == 0)
		get_reachable_from(argv[2]);
	else
		help(argv);

	return 0;
}