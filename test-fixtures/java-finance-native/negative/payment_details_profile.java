@RestController class PaymentDetailsController {
  PaymentDetailsRepository paymentDetailsRepository;
  @PostMapping Object updatePaymentDetails(@RequestBody PaymentDetails paymentDetails) {
    return paymentDetailsRepository.save(paymentDetails);
  }
}
