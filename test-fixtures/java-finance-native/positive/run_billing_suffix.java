@RestController class RecurringBillingController {
  BillingRun billingRun;
  @PostMapping Object runBilling(@RequestBody BillingCommand command) {
    return billingRun.runBilling(command.getBatchId());
  }
}
