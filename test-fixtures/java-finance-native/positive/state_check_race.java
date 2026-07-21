@RestController class RefundRaceController {
  RefundService service;
  @PostMapping Object refund(@RequestBody RefundRequest request) {
    return service.refund(request.getRequestNo(), request.getPaymentId());
  }
}
class RefundService {
  IdempotencyRepository idempotencyRepository;
  PaymentRepository paymentRepository;
  @Transactional Object refund(String requestNo, String paymentId) {
    idempotencyRepository.insertUnique(requestNo);
    Payment payment = paymentRepository.findById(paymentId);
    if (!payment.getStatus().equals("PAID")) return payment;
    return paymentRepository.refund(paymentId);
  }
}
