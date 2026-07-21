class IdempotencyRecord {
  @Column(unique = true) String requestNo;
  IdempotencyRecord(String requestNo) { this.requestNo = requestNo; }
}
@RestController class JpaUniqueController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    idempotencyRepository.save(new IdempotencyRecord(request.getRequestNo()));
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
