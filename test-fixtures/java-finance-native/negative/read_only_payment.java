@RestController class PaymentQueryController {
  PaymentRepository repository;
  @PostMapping Object findPayment(@RequestBody PaymentQuery query) {
    return repository.findById(query.getPaymentId());
  }
}
