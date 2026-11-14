class AlphaWidget {
public:
  void tick() {}
};
int alpha_helper() { return 42; } // TODO: wire
void use_alpha() { AlphaWidget w; w.tick(); }
