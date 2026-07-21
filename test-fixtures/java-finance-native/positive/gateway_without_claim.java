@RestController class GatewayChargeController {
  StripePaymentClient stripePaymentClient;
  @PostMapping Object charge(@RequestBody ChargeRequest request) {
    return stripePaymentClient.charge(request.getPaymentId(), request.getAmount());
  }
}
