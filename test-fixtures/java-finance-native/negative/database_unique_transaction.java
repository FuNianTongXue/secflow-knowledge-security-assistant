@RestController class SafeDatabaseController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping Object pay(@RequestBody PaymentRequest request) {
    return execute(request.getRequestNo(), request.getAmount());
  }
  @Transactional Object execute(String requestNo, BigDecimal amount) {
    idempotencyRepository.insertUnique(requestNo);
    return paymentRepository.debit(requestNo, amount);
  }
}
