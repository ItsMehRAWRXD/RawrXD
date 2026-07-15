module hello::hello {
    public entry fun hello() {
        std::debug::print(&b"Hello from Move");
    }
}
