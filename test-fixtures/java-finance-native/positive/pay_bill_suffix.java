@RestController class CardBillPaymentController {
  CardBillService cardBillService;
  @PostMapping Object pay(@RequestBody PayBillRequest request) {
    return cardBillService.payBill(request.getBillId(), request.getAmount());
  }
}
