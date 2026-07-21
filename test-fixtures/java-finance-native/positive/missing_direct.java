@RestController class DirectPaymentController {
  PaymentRepository repository;
  @PostMapping @Transactional Object pay(@RequestBody PaymentRequest request) {
    return repository.debit(request.getOrderNo(), request.getAmount());
  }
}
