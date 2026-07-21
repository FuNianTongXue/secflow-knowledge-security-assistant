@RestController class FundsTransferController {
  TransactionService transactionService;
  @PostMapping Object transfer(@RequestBody TransferRequest request) {
    return transactionService.transferFunds(request);
  }
}
