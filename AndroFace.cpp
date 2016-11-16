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

#include <iostream>
#include <map>
#include <tuple>
#include <vector>
#include <algorithm>
#include <sstream>
#include <regex>
#include <iomanip>

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
	regex procID_r{"^(/proc/\\d)(.*)"};

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
	const char *args[] = {"/su/bin/su", "-c", "/system/bin/ls", "-lZa", path.c_str(), nullptr};

	check_acl(path, acl);
	res.push_back(acl);

	exec("/su/bin/su", (char **)args, output);

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

void lookup_directory(const string &dir_path, vector<map<string, string>> &result, int depth) {
	const char *args[] = {"/su/bin/su", "-c", "/system/bin/ls", "-lZa", dir_path.c_str(), nullptr};
	string output, line;
	regex pattern_r{"([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+).*"};
	smatch match;

	// don't lookup too much in subdirectories, less probable to have device driver there ..
	if(++depth > 64) 
		return;

	visitedDirectory.push_back(dir_path);
	exec("/su/bin/su", (char **)args, output);

	stringstream ss{output};

	while(getline(ss, line, '\n')) {
		try {
			if(regex_search(line, match, pattern_r) && match.size() == 6) {
				string acl = match.str(1), acl2;

				map<string, string> file;
				file["acl"] = acl;
				file["owner"] = match.str(2);
				file["group"] = match.str(3);
				file["context"] = split(match.str(4), ':')[2];
				file["name"] = match.str(5);
				file["path"] = dir_path + "/" + file["name"];

				// if is a symbolic link, we dont process it (suppose will appear later on /dev, /sys or /proc)
				// normally accessible drivers should be in these locations
				if(acl.size()>0 && acl[0] == 'l') {
					// cout << "[-] Ignored symlink: " << file["path"] << endl;
					continue;
				}

				if(acl.size()>0 && acl[0] == 'd') {
					if(is_dir_allowed(file["path"]) && find(visitedDirectory.begin(), visitedDirectory.end(), file["path"]) == visitedDirectory.end())
						lookup_directory(file["path"], result, depth);
					continue;
				}

				check_acl(file["path"], acl2);
				file["access"] = acl2;
				result.push_back(file);
			}
		} catch(regex_error &e) {
	    	cerr << "Regex exception: " << e.what() << endl;
	    } 
	}
}

void get_attack_surface(vector<string> subtags) {
	vector<string> folders{"/dev", "/proc", "/sys"};
	map<string, vector<string>> permissions;

	cout << "[..] Processing access vectors" << endl;

	dump_av();
	get_subtags(subtags);
	get_av(subtags, permissions);

	for(auto &folder: folders) {
		vector<map<string, string>> files;
		int depth{0};

		cout << "[..] Fetching from: " << folder << endl << endl;
		
		lookup_directory(folder, files, depth);


		for(auto &file: files) {
			if(file["access"].size() == 0) // we have no access on file...
				continue;
			for(auto &perm: permissions) {
				if(perm.first.compare(file["context"]) == 0) { // print selinux permissions on file and access rights
					cout << file["path"] << endl;
					printf("\towner: %-15s", file["owner"].c_str());
					printf("current user acl: %-10s", file["access"].c_str());
					printf("general acl: %-15s", file["acl"].c_str());
					printf("selinux context: %s [%s]\n", perm.second[0].c_str(), perm.second[1].c_str());
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
	string acl;

	check_acl("/su/bin/su", acl);

	if(acl.find("r") == string::npos && acl.find("x") == string::npos) {
		cout << "[-] Need superSU to work !" << endl;
		exit(0);
	}

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