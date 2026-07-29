#pragma once
<<<<<<< HEAD
#include <string>
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class Rollback {
public:
    bool detectRegression();
    bool revertLastCommit();
<<<<<<< HEAD
=======
    // open GitHub issue
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    bool openIssue(const std::string& title, const std::string& body);
};

