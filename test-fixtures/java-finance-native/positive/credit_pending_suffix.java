@RestController class CashbackController {
  CashbackService cashbackService;
  @PostMapping Object credit(@RequestBody CashbackRequest request) {
    return cashbackService.creditPending(request.getCardId(), request.getAmount());
  }
}
