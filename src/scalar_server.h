#ifndef SCALAR_SERVER_H
#define SCALAR_SERVER_H

class ScalarServer {

public:
    explicit ScalarServer(void* parent = nullptr);
    void start();
    void stop();

private:
    void* m_parent;
};

#endif
