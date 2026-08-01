#ifndef MODEL_ROUTER_WIDGET_H
#define MODEL_ROUTER_WIDGET_H

class ModelRouterWidget {

public:
    explicit ModelRouterWidget(void* parent = nullptr);
    void initialize();

private:
    void* m_parent;
};

#endif
