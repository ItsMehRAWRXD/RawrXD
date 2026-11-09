# Additional linkage risks

Confirmed risk:

- Two same-named `RawrXD::Backend::OllamaClient` implementation pairs exist with different headers and data structures. Adding both implementation files to one target could create duplicate definitions or an incompatible ABI/data contract.

No additional missing IDE implementation unit was promoted to a repair candidate from this audit. The only concrete unresolved-symbol evidence is the seven methods from the ChatWindow object. Other omissions would require a new linker diagnostic or a separately authorized symbol-completeness analysis.
