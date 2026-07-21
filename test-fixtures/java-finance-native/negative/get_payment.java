@RestController class PaymentGetController {
  PaymentRepository repository;
  @GetMapping Object getPayment(String paymentId) {
    return repository.findById(paymentId);
  }
}
