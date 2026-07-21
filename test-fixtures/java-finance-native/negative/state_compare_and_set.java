@RestController class SafeStateController {
  PaymentStateRepository stateRepository;
  StripePaymentClient stripePaymentClient;
  @PostMapping Object capture(@RequestBody CaptureRequest request) {
    stateRepository.compareAndSet(request.getPaymentId(), "AUTHORIZED", "CAPTURING");
    return stripePaymentClient.capture(request.getPaymentId(), request.getAmount());
  }
}
