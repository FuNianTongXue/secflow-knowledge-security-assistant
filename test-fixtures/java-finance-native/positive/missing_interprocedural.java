@RestController class TransferController {
  TransferService service;
  @PostMapping Object transfer(@RequestBody TransferRequest request) {
    return service.transfer(request.getOrderNo(), request.getAmount());
  }
}
class TransferService {
  LedgerRepository repository;
  @Transactional Object transfer(String orderNo, BigDecimal amount) {
    return repository.debit(orderNo, amount);
  }
}
