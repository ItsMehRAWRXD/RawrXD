#include "model_router_widget.h"
#include <iostream>

ModelRouterWidget::ModelRouterWidget(void* parent)
    : m_parent(parent)
{
}

void ModelRouterWidget::initialize() {
    std::cout << "ModelRouterWidget initialized" << std::endl;
}
