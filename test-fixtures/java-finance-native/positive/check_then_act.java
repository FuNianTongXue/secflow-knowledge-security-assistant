@RestController class CheckThenPayController {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    if (idempotencyRepository.existsByRequestNo(request.getRequestNo())) {
      return idempotencyRepository.findByRequestNo(request.getRequestNo());
    }
    return paymentRepository.debit(request.getRequestNo(), request.getAmount());
  }
}
