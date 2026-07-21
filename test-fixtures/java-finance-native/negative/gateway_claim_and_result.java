@RestController class SafeGatewayController {
  IdempotencyRepository idempotencyRepository;
  StripePaymentClient stripePaymentClient;
  @PostMapping Object charge(@RequestBody ChargeRequest request) {
    idempotencyRepository.insertUnique(request.getRequestNo());
    Object result = stripePaymentClient.charge(request.getPaymentId(), request.getAmount());
    idempotencyRepository.saveResult(request.getRequestNo(), result);
    return result;
  }
}
