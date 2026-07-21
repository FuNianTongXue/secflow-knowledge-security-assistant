@RestController class NonUniqueRecordController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    idempotencyRepository.save(new IdempotencyRecord(request.getRequestNo()));
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
