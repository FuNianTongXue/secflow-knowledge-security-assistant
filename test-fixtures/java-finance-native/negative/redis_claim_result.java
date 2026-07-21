@RestController class SafeRedisController {
  IdempotencyRedis idempotencyRedis;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    if (!idempotencyRedis.setIfAbsent(request.getRequestNo())) {
      return idempotencyRedis.previousResult(request.getRequestNo());
    }
    Object result = paymentRepository.debit(request.getRequestNo(), request.getAmount());
    idempotencyRedis.complete(request.getRequestNo(), result);
    return result;
  }
}
