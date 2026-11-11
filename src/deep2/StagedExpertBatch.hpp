#pragma once
// Staged expert batch transaction: no residency changes before caller confirms IO.
// This is metadata only; the loader remains sole owner of physical buffers.
#include "ExpertBatchPlanner.hpp"
#include <utility>
namespace rawrxd::deep2 {
class StagedExpertBatch {
 ExpertResidencyPlanner candidate_;
 BatchPlan plan_;
 bool prepared_ = false;
public:
 StagedExpertBatch(const ExpertResidencyPlanner& live, std::vector<ExpertRequest> requests)
     : candidate_(live) {
  plan_ = planExpertBatch(candidate_, std::move(requests));
  prepared_ = plan_.accepted;
 }
 bool ready() const noexcept { return prepared_; }
 const BatchPlan& plan() const noexcept { return plan_; }
 // Call only after all required reads/transfers have completed successfully
 // and after physical eviction has been safely coordinated by the loader.
 bool commit(ExpertResidencyPlanner& live) {
  if (!prepared_) return false;
  live = std::move(candidate_);
  prepared_ = false;
  return true;
 }
 void abort() noexcept { prepared_ = false; }
};
}
