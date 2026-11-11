// Standalone isolation check of the H2 host-authoritative counting logic.
// Reproduces exactly what cmdAsk now does with receipts.
#include <string>
#include <vector>
#include <cstdio>
enum class ActionStatus { Proposed, Authorized, Executed, Failed };
struct Receipt { std::string toolName; ActionStatus status; bool ok; };
static int countExecuted(const std::vector<Receipt>& r){
    int executedCount = 0;
    for (const auto& t : r) if (t.status == ActionStatus::Executed) ++executedCount;
    return executedCount;
}
int main(){
    std::vector<Receipt> r;
    r.push_back({"search_text", ActionStatus::Executed, true});   // the one real run
    for (int i=0;i<13;i++) r.push_back({"search_text", ActionStatus::Proposed, false}); // looped proposals
    int executedCount = countExecuted(r);
    int suppressed = (int)r.size() - executedCount;
    printf("tools_executed=%d suppressed_proposals=%d total_receipts=%zu\n",
           executedCount, suppressed, r.size());
    // H2 PASS iff tools_executed equals the number of Executed (not all) receipts.
    return (executedCount == 1 && suppressed == 13) ? 0 : 1;
}
