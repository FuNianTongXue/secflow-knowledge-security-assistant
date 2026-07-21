@RestController class LateClaimController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    Object result = paymentRepository.debit(request.getRequestNo(), request.getAmount());
    idempotencyRepository.insertUnique(request.getRequestNo());
    return result;
  }
}
