@RestController class ConditionalClaimController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request, boolean claimEnabled) {
    if (claimEnabled) {
      idempotencyRepository.insertUnique(request.getRequestNo());
    }
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
