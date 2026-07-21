@RestController class MissingTransactionController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping Object pay(@RequestBody PaymentRequest request) {
    idempotencyRepository.insertUnique(request.getRequestNo());
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
