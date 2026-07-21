@RestController class RedisCrossStoreController {
  IdempotencyRedis idempotencyRedis;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    if (!idempotencyRedis.setIfAbsent(request.getRequestNo())) {
      return idempotencyRedis.previousResult(request.getRequestNo());
    }
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
