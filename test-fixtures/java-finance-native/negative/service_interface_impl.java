@RestController class InterfaceController {
  PaymentService paymentService;
  @PostMapping Object pay(@RequestBody PaymentRequest request) {
    return paymentService.pay(request.getRequestNo(), request.getAmount());
  }
}
class PaymentServiceImpl {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @Transactional Object pay(String requestNo, BigDecimal amount) {
    idempotencyRepository.insertUnique(requestNo);
    return paymentRepository.debit(requestNo, amount);
  }
}
