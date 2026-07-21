@RestController class ConstantClaimController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    idempotencyRepository.insertUnique("shared-key");
    return paymentRepository.debit(request.getOrderNo(), request.getAmount());
  }
}
